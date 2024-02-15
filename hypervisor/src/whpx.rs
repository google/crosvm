// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implementation for WHPX hypervisor aka Windows Hyper-V platform.

use core::ffi::c_void;
use std::arch::x86_64::__cpuid_count;

use base::error;
use base::warn;
use base::Error;
use base::Result;
use once_cell::sync::Lazy;
use thiserror::Error as ThisError;
use winapi::shared::winerror::S_OK;

use crate::CpuId;
use crate::CpuIdEntry;
use crate::Hypervisor;
use crate::HypervisorCap;
use crate::HypervisorX86_64;

#[macro_export]
macro_rules! check_whpx {
    ($x: expr) => {{
        match $x {
            S_OK => Ok(()),
            _ => Err(Error::new($x)),
        }
    }};
}

mod types;
mod vcpu;
pub use vcpu::*;
mod vm;
pub use vm::*;
pub mod whpx_sys;
pub use whpx_sys::*;

// used by both the vm and vcpu
struct SafePartition {
    partition: WHV_PARTITION_HANDLE,
}

// we can send the partition over safely even though it is void*, it can be sent
// in another thread safely.
unsafe impl Send for SafePartition {}
unsafe impl Sync for SafePartition {}

impl SafePartition {
    fn new() -> WhpxResult<SafePartition> {
        let mut partition_handle: WHV_PARTITION_HANDLE = std::ptr::null_mut();
        // safe because we pass in the partition handle for the system to fill in.
        check_whpx!(unsafe { WHvCreatePartition(&mut partition_handle) })
            .map_err(WhpxError::CreatePartitionError)?;

        Ok(SafePartition {
            partition: partition_handle,
        })
    }
}

impl Drop for SafePartition {
    fn drop(&mut self) {
        // safe because we own this partition
        check_whpx!(unsafe { WHvDeletePartition(self.partition) }).unwrap();
    }
}

#[derive(Clone)]
pub struct Whpx {
    // there is no general whpx object, the vm contains the partition.
}

/// Enum of WHPX Features. Similar to WHV_CAPABILITY_FEATURES but allows us to avoid making the
/// whpx_sys crate pub.
#[derive(Debug)]
pub enum WhpxFeature {
    PartialUnmap = 0x0,
    LocalApicEmulation = 0x1,
    Xsave = 0x2,
    DirtyPageTracking = 0x4,
    SpeculationControl = 0x8,
    ApicRemoteRead = 0x10,
    IdleSuspend = 0x20,
}

#[derive(ThisError, Debug, Clone, Copy)]
pub enum WhpxError {
    #[error("failed to create WHPX partition: {0}")]
    CreatePartitionError(base::Error),
    #[error("failed to get WHPX capability {0}: {1}")]
    GetCapability(WHV_CAPABILITY_CODE, base::Error),
    #[error("WHPX local apic emulation is not supported on this host")]
    LocalApicEmulationNotSupported,
    #[error("failed to map guest physical address range: {0}")]
    MapGpaRange(base::Error),
    #[error("failed to set WHPX partition processor count: {0}")]
    SetProcessorCount(base::Error),
    #[error("failed to set WHPX partition cpuid result list: {0}")]
    SetCpuidResultList(base::Error),
    #[error("failed to set WHPX partition cpuid exit list: {0}")]
    SetCpuidExitList(base::Error),
    #[error("failed to set WHPX partition extended vm exits: {0}")]
    SetExtendedVmExits(base::Error),
    #[error("failed to set WHPX partition local apic emulation mode: {0}")]
    SetLocalApicEmulationMode(base::Error),
    #[error("failed to setup WHPX partition: {0}")]
    SetupPartition(base::Error),
}

impl From<WhpxError> for Box<dyn std::error::Error + Send> {
    fn from(e: WhpxError) -> Self {
        Box::new(e)
    }
}

type WhpxResult<T> = std::result::Result<T, WhpxError>;

impl Whpx {
    pub fn new() -> Result<Whpx> {
        Ok(Whpx {})
    }

    pub fn is_enabled() -> bool {
        let res = Whpx::get_capability(WHV_CAPABILITY_CODE_WHvCapabilityCodeHypervisorPresent);
        match res {
            Ok(cap_code) => {
                // safe because we trust the kernel to fill in hypervisor present in the union
                unsafe { cap_code.HypervisorPresent > 0 }
            }
            _ => {
                warn!("error checking if whpx was enabled. Assuming whpx is disabled");
                false
            }
        }
    }

    fn get_capability(cap: WHV_CAPABILITY_CODE) -> WhpxResult<WHV_CAPABILITY> {
        let mut capability: WHV_CAPABILITY = Default::default();
        let mut written_size = 0;
        check_whpx!(unsafe {
            WHvGetCapability(
                cap,
                &mut capability as *mut _ as *mut c_void,
                std::mem::size_of::<WHV_CAPABILITY>() as u32,
                &mut written_size,
            )
        })
        .map_err(|e| WhpxError::GetCapability(cap, e))?;
        Ok(capability)
    }

    pub fn check_whpx_feature(feature: WhpxFeature) -> WhpxResult<bool> {
        // use Lazy to cache the results of the get_capability call
        static FEATURES: Lazy<WhpxResult<WHV_CAPABILITY>> =
            Lazy::new(|| Whpx::get_capability(WHV_CAPABILITY_CODE_WHvCapabilityCodeFeatures));

        Ok((unsafe { (*FEATURES)?.Features.AsUINT64 } & feature as u64) != 0)
    }
}

impl Hypervisor for Whpx {
    /// Makes a shallow clone of this `Hypervisor`.
    fn try_clone(&self) -> Result<Self> {
        Ok(self.clone())
    }

    /// Checks if a particular `HypervisorCap` is available.
    fn check_capability(&self, cap: HypervisorCap) -> bool {
        // whpx supports immediate exit, user memory, and the xcr0 state
        match cap {
            HypervisorCap::ImmediateExit => true,
            HypervisorCap::UserMemory => true,
            HypervisorCap::Xcrs => {
                Whpx::check_whpx_feature(WhpxFeature::Xsave).unwrap_or_else(|e| {
                    error!(
                        "failed to check whpx feature {:?}: {}",
                        WhpxFeature::Xsave,
                        e
                    );
                    false
                })
            }
            // under whpx, guests rely on this leaf to calibrate their clocksource.
            HypervisorCap::CalibratedTscLeafRequired => true,
            _ => false,
        }
    }
}

/// Build a CpuIdEntry for a given `function`/`index` from the host results for that
/// `function`/`index`.
fn cpuid_entry_from_host(function: u32, index: u32) -> CpuIdEntry {
    // Safe because arguments are passed by value
    let result = unsafe { __cpuid_count(function, index) };
    CpuIdEntry {
        function,
        index,
        flags: 0,
        cpuid: result,
    }
}

impl HypervisorX86_64 for Whpx {
    /// Get the system supported CPUID values.
    ///
    /// WHPX does not have an API for getting this information, so we just return the host values
    /// instead. This is not technically accurate, since WHPX does modify the contents of various
    /// leaves, but in practice this is fine because this function is only used for pre-setting
    /// the contents of certain leaves that we can safely base off of the host value.
    fn get_supported_cpuid(&self) -> Result<CpuId> {
        Ok(CpuId {
            cpu_id_entries: vec![
                // Leaf 0 just contains information about the max leaf. WHPX seems to set this to
                // a value lower than the host value but we want it to be at least 0x15. We set it
                // to the host value here assuming that the leaves above 0x15 probably won't hurt
                // the guest.
                cpuid_entry_from_host(0, 0),
                // crosvm overrides the entirety of leaves 2, 0x80000005, and 0x80000006 to the
                // host value, so we just return the host value here.
                cpuid_entry_from_host(2, 0),
                cpuid_entry_from_host(0x80000005, 0),
                cpuid_entry_from_host(0x80000006, 0),
            ],
        })
    }

    /// Get the system emulated CPUID values.
    /// TODO: this is only used by the plugin
    fn get_emulated_cpuid(&self) -> Result<CpuId> {
        Ok(CpuId::new(0))
    }

    /// Gets the list of supported MSRs.
    /// TODO: this is only used by the plugin
    fn get_msr_index_list(&self) -> Result<Vec<u32>> {
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_whpx() {
        Whpx::new().expect("failed to instantiate whpx");
    }

    #[test]
    fn clone_whpx() {
        let whpx = Whpx::new().expect("failed to instantiate whpx");
        let _whpx_clone = whpx.try_clone().unwrap();
    }

    #[test]
    fn check_capability() {
        let whpx = Whpx::new().expect("failed to instantiate whpx");
        assert!(whpx.check_capability(HypervisorCap::UserMemory));
        assert!(whpx.check_capability(HypervisorCap::Xcrs));
        assert!(whpx.check_capability(HypervisorCap::ImmediateExit));
        assert!(!whpx.check_capability(HypervisorCap::S390UserSigp));
    }
}

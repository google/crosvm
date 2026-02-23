// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Hypervisor.framework (HVF) backend for macOS on Apple Silicon.
//!
//! This module provides virtualization support using Apple's native hypervisor
//! framework, enabling crosvm to run VMs on macOS with aarch64 guests.

mod bindings;
mod vcpu;
mod vm;

pub use bindings::HvfError;
pub use vcpu::HvfVcpu;
pub use vm::HvfVm;

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use base::Error;
use base::Result;

use crate::Hypervisor;
use crate::HypervisorCap;

/// Global flag to track if a VM has been created.
/// HVF only supports one VM per process.
static VM_CREATED: AtomicBool = AtomicBool::new(false);

/// The Hvf struct represents the Hypervisor.framework hypervisor.
///
/// Unlike KVM, HVF is stateless at the hypervisor level - there's no
/// file descriptor to maintain. The actual VM state is managed by the
/// framework itself.
#[derive(Clone)]
pub struct Hvf {
    /// Marker to track this hypervisor instance
    _marker: Arc<()>,
}

impl Hvf {
    /// Creates a new Hvf hypervisor instance.
    ///
    /// This doesn't create a VM yet - that happens when `create_vm` is called.
    /// HVF is available on all Apple Silicon Macs running macOS 11.0+.
    pub fn new() -> Result<Self> {
        // Check if we can get the max VCPU count - this verifies HVF is available
        let mut max_vcpu_count: u32 = 0;
        // SAFETY: We pass a valid pointer to receive the count
        let ret = unsafe { bindings::hv_vm_get_max_vcpu_count(&mut max_vcpu_count) };
        if ret != bindings::HV_SUCCESS {
            return Err(Error::new(libc::ENOTSUP));
        }

        Ok(Hvf {
            _marker: Arc::new(()),
        })
    }

    /// Returns the maximum number of VCPUs supported.
    pub fn get_max_vcpu_count() -> Result<u32> {
        let mut max_vcpu_count: u32 = 0;
        // SAFETY: We pass a valid pointer
        let ret = unsafe { bindings::hv_vm_get_max_vcpu_count(&mut max_vcpu_count) };
        bindings::check_ret(ret).map_err(|_| Error::new(libc::ENOTSUP))?;
        Ok(max_vcpu_count)
    }

    /// Checks if a VM has already been created in this process.
    pub fn vm_created() -> bool {
        VM_CREATED.load(Ordering::SeqCst)
    }

    /// Marks that a VM has been created.
    pub(crate) fn mark_vm_created() -> Result<()> {
        if VM_CREATED
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            // A VM already exists
            return Err(Error::new(libc::EEXIST));
        }
        Ok(())
    }

    /// Marks that the VM has been destroyed.
    pub(crate) fn mark_vm_destroyed() {
        VM_CREATED.store(false, Ordering::SeqCst);
    }
}

impl Hypervisor for Hvf {
    fn try_clone(&self) -> Result<Self> {
        Ok(Hvf {
            _marker: self._marker.clone(),
        })
    }

    fn check_capability(&self, cap: HypervisorCap) -> bool {
        match cap {
            HypervisorCap::UserMemory => true,
            HypervisorCap::ImmediateExit => true,
            HypervisorCap::HypervisorInitializedBootContext => false,
            HypervisorCap::StaticSwiotlbAllocationRequired => false,
            #[cfg(target_arch = "x86_64")]
            HypervisorCap::Xcrs => false,
            #[cfg(target_arch = "x86_64")]
            HypervisorCap::CalibratedTscLeafRequired => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hvf_creation() {
        // This test will only pass on macOS with HVF support
        if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
            let hvf = Hvf::new();
            assert!(hvf.is_ok(), "Failed to create HVF instance");
        }
    }

    #[test]
    fn test_check_capability() {
        if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
            if let Ok(hvf) = Hvf::new() {
                assert!(hvf.check_capability(HypervisorCap::UserMemory));
                assert!(hvf.check_capability(HypervisorCap::ImmediateExit));
            }
        }
    }
}

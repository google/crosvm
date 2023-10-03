// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::arch::x86_64::CpuidResult;
use std::arch::x86_64::__cpuid;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use base::AsRawDescriptor;
use base::RawDescriptor;
use base::Result;
use base::SafeDescriptor;

use crate::CpuId;
use crate::CpuIdEntry;
use crate::Hypervisor;
use crate::HypervisorCap;
use crate::HypervisorX86_64;

mod haxm_sys;
// This is a HAXM-specific capability, so it's not present in the VmCap enum, and the
// register_vm_log function does not exist on the Vm trait. But windows.rs will use it when
// creating Haxm Vm instances, so we expose the cap constant here.
pub use haxm_sys::HAX_CAP_VM_LOG;
use haxm_sys::*;

mod vcpu;
pub use vcpu::*;
mod vm;
pub use vm::*;

#[cfg(windows)]
mod win;
#[cfg(windows)]
use win::*;

#[cfg(any(target_os = "android", target_os = "linux"))]
mod linux;
#[cfg(any(target_os = "android", target_os = "linux"))]
use linux::*;

static USE_GHAXM: AtomicBool = AtomicBool::new(true);

/// Returns whether ghaxm variant is in use vs. the upstream haxm variant.
pub fn get_use_ghaxm() -> bool {
    USE_GHAXM.load(Ordering::Relaxed)
}

/// Sets whether to use ghaxm variant vs. the upstream haxm variant.
pub fn set_use_ghaxm(use_ghaxm: bool) {
    USE_GHAXM.store(use_ghaxm, Ordering::Relaxed);
}

pub struct Haxm {
    haxm: SafeDescriptor,
}

impl AsRawDescriptor for Haxm {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.haxm.as_raw_descriptor()
    }
}

impl Haxm {
    /// Opens HAXM device and returns a Haxm object on success.
    pub fn new() -> Result<Haxm> {
        Ok(Haxm {
            haxm: open_haxm_device(get_use_ghaxm())?,
        })
    }
}

impl Hypervisor for Haxm {
    fn check_capability(&self, cap: HypervisorCap) -> bool {
        // under haxm, guests rely on this leaf to calibrate their
        // clocksource.
        matches!(
            cap,
            HypervisorCap::UserMemory | HypervisorCap::CalibratedTscLeafRequired
        )
    }

    /// Makes a shallow clone of this `Hypervisor`.
    fn try_clone(&self) -> Result<Self> {
        Ok(Haxm {
            haxm: self.haxm.try_clone()?,
        })
    }
}

impl HypervisorX86_64 for Haxm {
    fn get_supported_cpuid(&self) -> Result<CpuId> {
        // Start with cpuids that HAXM supports from
        // https://github.com/intel/haxm/blob/v7.6.1/core/cpuid.c#L170
        let mut supported_features_1_ecx = (Feature1Ecx::SSE3
            | Feature1Ecx::SSSE3
            | Feature1Ecx::PCID
            | Feature1Ecx::SSE41
            | Feature1Ecx::SSE42
            | Feature1Ecx::CMPXCHG16B
            | Feature1Ecx::MOVBE
            | Feature1Ecx::AESNI
            | Feature1Ecx::PCLMULQDQ
            | Feature1Ecx::POPCNT
            | Feature1Ecx::FMA
            | Feature1Ecx::XSAVE
            | Feature1Ecx::OSXSAVE
            | Feature1Ecx::AVX
            | Feature1Ecx::F16C
            | Feature1Ecx::RDRAND)
            .bits();
        let mut supported_features_1_edx = (Feature1Edx::PAT
            | Feature1Edx::FPU
            | Feature1Edx::VME
            | Feature1Edx::DE
            | Feature1Edx::TSC
            | Feature1Edx::MSR
            | Feature1Edx::PAE
            | Feature1Edx::MCE
            | Feature1Edx::CX8
            | Feature1Edx::APIC
            | Feature1Edx::SEP
            | Feature1Edx::MTRR
            | Feature1Edx::PGE
            | Feature1Edx::MCA
            | Feature1Edx::CMOV
            | Feature1Edx::CLFSH
            | Feature1Edx::MMX
            | Feature1Edx::FXSR
            | Feature1Edx::SSE
            | Feature1Edx::SSE2
            | Feature1Edx::SS
            | Feature1Edx::PSE
            | Feature1Edx::HTT)
            .bits();

        let mut supported_features_80000001_edx = (Feature80000001Edx::NX
            | Feature80000001Edx::SYSCALL
            | Feature80000001Edx::RDTSCP
            | Feature80000001Edx::EM64T)
            .bits();

        let mut supported_features_80000001_ecx =
            (Feature80000001Ecx::LAHF | Feature80000001Ecx::ABM | Feature80000001Ecx::PREFETCHW)
                .bits();

        let result = unsafe { __cpuid(0x1) };

        // Filter HAXM supported cpuids by host-supported cpuids
        supported_features_1_ecx &= result.ecx;
        supported_features_1_edx &= result.edx;

        let result = unsafe { __cpuid(0x80000001) };

        supported_features_80000001_edx &= result.edx;
        supported_features_80000001_ecx &= result.ecx;

        let cpuid_7 = unsafe { __cpuid(0x7) };
        let cpuid_15 = unsafe { __cpuid(0x15) };
        let cpuid_16 = unsafe { __cpuid(0x16) };

        Ok(CpuId {
            cpu_id_entries: vec![
                CpuIdEntry {
                    function: 0x1,
                    index: 0,
                    flags: 0,
                    cpuid: CpuidResult {
                        eax: 0,
                        ebx: 0,
                        ecx: supported_features_1_ecx,
                        edx: supported_features_1_edx,
                    },
                },
                CpuIdEntry {
                    function: 0x7,
                    index: 0,
                    flags: 0,
                    cpuid: CpuidResult {
                        eax: cpuid_7.eax,
                        ebx: cpuid_7.ebx,
                        ecx: cpuid_7.ecx,
                        edx: cpuid_7.edx,
                    },
                },
                CpuIdEntry {
                    function: 0x15,
                    index: 0,
                    flags: 0,
                    cpuid: CpuidResult {
                        eax: cpuid_15.eax,
                        ebx: cpuid_15.ebx,
                        ecx: cpuid_15.ecx,
                        edx: cpuid_15.edx,
                    },
                },
                CpuIdEntry {
                    function: 0x16,
                    index: 0,
                    flags: 0,
                    cpuid: CpuidResult {
                        eax: cpuid_16.eax,
                        ebx: cpuid_16.ebx,
                        ecx: cpuid_16.ecx,
                        edx: cpuid_16.edx,
                    },
                },
                CpuIdEntry {
                    function: 0x80000001,
                    index: 0,
                    flags: 0,
                    cpuid: CpuidResult {
                        eax: 0,
                        ebx: 0,
                        ecx: supported_features_80000001_ecx,
                        edx: supported_features_80000001_edx,
                    },
                },
            ],
        })
    }

    fn get_emulated_cpuid(&self) -> Result<CpuId> {
        // HAXM does not emulate any cpuids that the host does not support
        Ok(CpuId::new(0))
    }

    /// Gets the list of supported MSRs.
    fn get_msr_index_list(&self) -> Result<Vec<u32>> {
        // HAXM supported MSRs come from
        // https://github.com/intel/haxm/blob/v7.6.1/core/vcpu.c#L3296
        let mut msrs = vec![
            IA32_TSC,
            IA32_FEATURE_CONTROL,
            IA32_PLATFORM_ID,
            IA32_APIC_BASE,
            IA32_EFER,
            IA32_STAR,
            IA32_LSTAR,
            IA32_CSTAR,
            IA32_SF_MASK,
            IA32_KERNEL_GS_BASE,
            IA32_TSC_AUX,
            IA32_FS_BASE,
            IA32_GS_BASE,
            IA32_SYSENTER_CS,
            IA32_SYSENTER_ESP,
            IA32_SYSENTER_EIP,
            IA32_MTRRCAP,
            MTRRFIX64K_00000,
            IA32_CR_PAT,
            IA32_MTRR_DEF_TYPE,
            IA32_MCG_CAP,
            IA32_MCG_STATUS,
            IA32_MCG_CTL,
            IA32_MC0_CTL,
            IA32_P5_MC_TYPE,
            IA32_MC0_STATUS,
            IA32_P5_MC_ADDR,
            IA32_MC0_ADDR,
            IA32_MC0_MISC,
            IA32_THERM_DIODE_OFFSET,
            IA32_FSB_FREQ,
            IA32_TEMP_TARGET,
            IA32_BBL_CR_CTL3,
            IA32_DEBUGCTL,
            IA32_CPUID_FEATURE_MASK,
            IA32_EBC_FREQUENCY_ID,
            IA32_EBC_HARD_POWERON,
            IA32_EBC_SOFT_POWERON,
            IA32_BIOS_SIGN_ID,
            IA32_MISC_ENABLE,
            IA32_PERF_CAPABILITIES,
            IA32_PMC0,
            IA32_PMC1,
            IA32_PMC2,
            IA32_PMC3,
            IA32_PERFEVTSEL0,
            IA32_PERFEVTSEL1,
            IA32_PERFEVTSEL2,
            IA32_PERFEVTSEL3,
        ];
        msrs.extend(IA32_MTRR_PHYSBASE0..IA32_MTRR_PHYSMASK9);
        msrs.extend(MTRRFIX16K_80000..MTRRFIX16K_A0000);
        msrs.extend(MTRRFIX4K_C0000..MTRRFIX4K_F8000);
        msrs.extend(IA32_MC0_CTL2..IA32_MC8_CTL2);
        Ok(msrs)
    }
}

// TODO(b:241252288): Enable tests disabled with dummy feature flag - enable_haxm_tests.
#[cfg(test)]
#[cfg(feature = "enable_haxm_tests")]
mod tests {
    use super::*;

    #[test]
    fn new_haxm() {
        Haxm::new().expect("failed to instantiate HAXM");
    }

    #[test]
    fn check_capability() {
        let haxm = Haxm::new().expect("failed to instantiate HAXM");
        assert!(haxm.check_capability(HypervisorCap::UserMemory));
        assert!(!haxm.check_capability(HypervisorCap::ImmediateExit));
    }

    #[test]
    fn check_supported_cpuid() {
        let haxm = Haxm::new().expect("failed to instantiate HAXM");
        let cpuid = haxm
            .get_supported_cpuid()
            .expect("failed to get supported cupid");

        // HAXM returns five leaves: 0x1, 0x7, 0x15, 0x16, and 0x80000001
        assert_eq!(cpuid.cpu_id_entries.len(), 5);

        // Check some simple cpuids that we know should be enabled
        let entry = cpuid
            .cpu_id_entries
            .iter()
            .find(|entry| entry.function == 0x1)
            .expect("failed to get leaf 0x1");

        // FPU should definitely exist
        assert_ne!(entry.cpuid.edx & Feature1Edx::FPU.bits(), 0);
        // SSSE3 almost certainly set
        assert_ne!(entry.cpuid.ecx & Feature1Ecx::SSSE3.bits(), 0);
        // VMX should not be set, HAXM does not support nested virt
        assert_eq!(entry.cpuid.ecx & Feature1Ecx::VMX.bits(), 0);

        // Check that leaf 0x15 is in the results
        cpuid
            .cpu_id_entries
            .iter()
            .find(|entry| entry.function == 0x15)
            .expect("failed to get leaf 0x15");

        // Check that leaf 0x16 is in the results
        cpuid
            .cpu_id_entries
            .iter()
            .find(|entry| entry.function == 0x16)
            .expect("failed to get leaf 0x16");

        let entry = cpuid
            .cpu_id_entries
            .iter()
            .find(|entry| entry.function == 0x80000001)
            .expect("failed to get leaf 0x80000001");
        // NX should be set, Windows 8+ and HAXM require it
        assert_ne!(entry.cpuid.edx & Feature80000001Edx::NX.bits(), 0);
    }

    #[test]
    fn check_msr_index_list() {
        let haxm = Haxm::new().expect("failed to instantiate HAXM");
        let msr_index_list = haxm
            .get_msr_index_list()
            .expect("failed to get HAXM msr index list");

        assert!(msr_index_list.contains(&IA32_TSC));
    }
}

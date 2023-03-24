// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::arch::x86_64::CpuidResult;
use std::arch::x86_64::__cpuid;
use std::arch::x86_64::__cpuid_count;
use std::cmp;
use std::result;

use devices::Apic;
use devices::IrqChipCap;
use devices::IrqChipX86_64;
use hypervisor::CpuConfigX86_64;
use hypervisor::CpuHybridType;
use hypervisor::CpuIdEntry;
use hypervisor::HypervisorCap;
use hypervisor::HypervisorX86_64;
use hypervisor::VcpuX86_64;
use remain::sorted;
use thiserror::Error;

use crate::CpuManufacturer;

#[sorted]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    #[error("GetSupportedCpus ioctl failed: {0}")]
    GetSupportedCpusFailed(base::Error),
    #[error("SetSupportedCpus ioctl failed: {0}")]
    SetSupportedCpusFailed(base::Error),
}

pub type Result<T> = result::Result<T, Error>;

// CPUID bits in ebx, ecx, and edx.
pub const EBX_CLFLUSH_CACHELINE: u32 = 8; // Flush a cache line size.
pub const EBX_CLFLUSH_SIZE_SHIFT: u32 = 8; // Bytes flushed when executing CLFLUSH.
pub const EBX_CPU_COUNT_SHIFT: u32 = 16; // Index of this CPU.
pub const EBX_CPUID_SHIFT: u32 = 24; // Index of this CPU.
pub const ECX_EPB_SHIFT: u32 = 3; // "Energy Performance Bias" bit.
pub const ECX_X2APIC_SHIFT: u32 = 21; // APIC supports extended xAPIC (x2APIC) standard.
pub const ECX_TSC_DEADLINE_TIMER_SHIFT: u32 = 24; // TSC deadline mode of APIC timer.
pub const ECX_HYPERVISOR_SHIFT: u32 = 31; // Flag to be set when the cpu is running on a hypervisor.
pub const EDX_HTT_SHIFT: u32 = 28; // Hyper Threading Enabled.
pub const ECX_TOPO_TYPE_SHIFT: u32 = 8; // Topology Level type.
pub const ECX_TOPO_SMT_TYPE: u32 = 1; // SMT type.
pub const ECX_TOPO_CORE_TYPE: u32 = 2; // CORE type.
pub const ECX_HCFC_PERF_SHIFT: u32 = 0; // Presence of IA32_MPERF and IA32_APERF.
pub const EAX_CPU_CORES_SHIFT: u32 = 26; // Index of cpu cores in the same physical package.
pub const EDX_HYBRID_CPU_SHIFT: u32 = 15; // Hybrid. The processor is identified as a hybrid part.
pub const EAX_HWP_SHIFT: u32 = 7; // Intel Hardware P-states.
pub const EAX_HWP_NOTIFICATION_SHIFT: u32 = 8; // IA32_HWP_INTERRUPT MSR is supported
pub const EAX_HWP_EPP_SHIFT: u32 = 10; // HWP Energy Perf. Preference.
pub const EAX_ITMT_SHIFT: u32 = 14; // Intel Turbo Boost Max Technology 3.0 available.
pub const EAX_CORE_TEMP: u32 = 0; // Core Temperature
pub const EAX_PKG_TEMP: u32 = 6; // Package Temperature
pub const EAX_CORE_TYPE_SHIFT: u32 = 24; // Hybrid information. Hybrid core type.

const EAX_CORE_TYPE_ATOM: u32 = 0x20; // Hybrid Atom CPU.
const EAX_CORE_TYPE_CORE: u32 = 0x40; // Hybrid Core CPU.

/// All of the context required to emulate the CPUID instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpuIdContext {
    /// Id of the Vcpu associated with this context.
    vcpu_id: usize,
    /// The total number of vcpus on this VM.
    cpu_count: usize,
    /// Whether or not the IrqChip's APICs support X2APIC.
    x2apic: bool,
    /// Whether or not the IrqChip's APICs support a TSC deadline timer.
    tsc_deadline_timer: bool,
    /// The frequency at which the IrqChip's APICs run.
    apic_frequency: u32,
    /// The TSC frequency in Hz, if it could be determined.
    tsc_frequency: Option<u64>,
    /// CPU feature configurations.
    cpu_config: CpuConfigX86_64,
    /// __cpuid_count or a fake function for test.
    cpuid_count: unsafe fn(u32, u32) -> CpuidResult,
    /// __cpuid or a fake function for test.
    cpuid: unsafe fn(u32) -> CpuidResult,
}

impl CpuIdContext {
    pub fn new(
        vcpu_id: usize,
        cpu_count: usize,
        irq_chip: Option<&dyn IrqChipX86_64>,
        cpu_config: CpuConfigX86_64,
        calibrated_tsc_leaf_required: bool,
        cpuid_count: unsafe fn(u32, u32) -> CpuidResult,
        cpuid: unsafe fn(u32) -> CpuidResult,
    ) -> CpuIdContext {
        CpuIdContext {
            vcpu_id,
            cpu_count,
            x2apic: irq_chip.map_or(false, |chip| chip.check_capability(IrqChipCap::X2Apic)),
            tsc_deadline_timer: irq_chip.map_or(false, |chip| {
                chip.check_capability(IrqChipCap::TscDeadlineTimer)
            }),
            apic_frequency: irq_chip.map_or(Apic::frequency(), |chip| chip.lapic_frequency()),
            tsc_frequency: if calibrated_tsc_leaf_required || cpu_config.force_calibrated_tsc_leaf {
                devices::tsc::tsc_frequency().ok()
            } else {
                None
            },
            cpu_config,
            cpuid_count,
            cpuid,
        }
    }
}

/// Adjust a CPUID instruction result to return values that work with crosvm.
///
/// Given an input CpuIdEntry `entry`, which represents what the Hypervisor would normally return
/// for a given CPUID instruction result, adjust that result to reflect the capabilities of crosvm.
/// The `ctx` argument contains all of the Vm-specific and Vcpu-specific information required to
/// return the appropriate results.
pub fn adjust_cpuid(entry: &mut CpuIdEntry, ctx: &CpuIdContext) {
    match entry.function {
        0 => {
            if ctx.tsc_frequency.is_some() {
                // We add leaf 0x15 for the TSC frequency if it is available.
                entry.cpuid.eax = cmp::max(0x15, entry.cpuid.eax);
            }
        }
        1 => {
            // X86 hypervisor feature
            if entry.index == 0 {
                entry.cpuid.ecx |= 1 << ECX_HYPERVISOR_SHIFT;
            }
            if ctx.x2apic {
                entry.cpuid.ecx |= 1 << ECX_X2APIC_SHIFT;
            } else {
                entry.cpuid.ecx &= !(1 << ECX_X2APIC_SHIFT);
            }
            if ctx.tsc_deadline_timer {
                entry.cpuid.ecx |= 1 << ECX_TSC_DEADLINE_TIMER_SHIFT;
            }

            if ctx.cpu_config.host_cpu_topology {
                entry.cpuid.ebx |= EBX_CLFLUSH_CACHELINE << EBX_CLFLUSH_SIZE_SHIFT;

                // Expose HT flag to Guest.
                let result = unsafe { (ctx.cpuid)(entry.function) };
                entry.cpuid.edx |= result.edx & (1 << EDX_HTT_SHIFT);
                return;
            }

            entry.cpuid.ebx = (ctx.vcpu_id << EBX_CPUID_SHIFT) as u32
                | (EBX_CLFLUSH_CACHELINE << EBX_CLFLUSH_SIZE_SHIFT);
            if ctx.cpu_count > 1 {
                // This field is only valid if CPUID.1.EDX.HTT[bit 28]= 1.
                entry.cpuid.ebx |= (ctx.cpu_count as u32) << EBX_CPU_COUNT_SHIFT;
                // A value of 0 for HTT indicates there is only a single logical
                // processor in the package and software should assume only a
                // single APIC ID is reserved.
                entry.cpuid.edx |= 1 << EDX_HTT_SHIFT;
            }
        }
        2 | // Cache and TLB Descriptor information
        0x80000002 | 0x80000003 | 0x80000004 | // Processor Brand String
        0x80000005 | 0x80000006 // L1 and L2 cache information
            => entry.cpuid = unsafe { (ctx.cpuid)(entry.function) },
        4 => {
            entry.cpuid = unsafe { (ctx.cpuid_count)(entry.function, entry.index) };

            if ctx.cpu_config.host_cpu_topology {
                return;
            }

            entry.cpuid.eax &= !0xFC000000;
            if ctx.cpu_count > 1 {
                let cpu_cores = if ctx.cpu_config.no_smt {
                    ctx.cpu_count as u32
                } else if ctx.cpu_count % 2 == 0 {
                    (ctx.cpu_count >> 1) as u32
                } else {
                    1
                };
                entry.cpuid.eax |= (cpu_cores - 1) << EAX_CPU_CORES_SHIFT;
            }
        }
        6 => {
            // Safe because we pass 6 for this call and the host
            // supports the `cpuid` instruction
            let result = unsafe { (ctx.cpuid)(entry.function) };

            if ctx.cpu_config.enable_hwp {
                entry.cpuid.eax |= result.eax & (1 << EAX_HWP_SHIFT);
                entry.cpuid.eax |= result.eax & (1 << EAX_HWP_NOTIFICATION_SHIFT);
                entry.cpuid.eax |= result.eax & (1 << EAX_HWP_EPP_SHIFT);
                entry.cpuid.ecx |= result.ecx & (1 << ECX_EPB_SHIFT);

                if ctx.cpu_config.itmt {
                    entry.cpuid.eax |= result.eax & (1 << EAX_ITMT_SHIFT);
                }
            }

            if ctx.cpu_config.enable_pnp_data {
                // Expose core temperature, package temperature
                // and APEF/MPERF to guest
                entry.cpuid.eax |= result.eax & (1 << EAX_CORE_TEMP);
                entry.cpuid.eax |= result.eax & (1 << EAX_PKG_TEMP);
                entry.cpuid.ecx |= result.ecx & (1 << ECX_HCFC_PERF_SHIFT);
            }
        }
        7 => {
            if ctx.cpu_config.host_cpu_topology && entry.index == 0 {
                // Safe because we pass 7 and 0 for this call and the host supports the
                // `cpuid` instruction
                let result = unsafe { (ctx.cpuid_count)(entry.function, entry.index) };
                entry.cpuid.edx |= result.edx & (1 << EDX_HYBRID_CPU_SHIFT);
            }
            if ctx.cpu_config.hybrid_type.is_some() && entry.index == 0 {
                entry.cpuid.edx |= 1 << EDX_HYBRID_CPU_SHIFT;
            }
        }
        0x15 => {
            if let Some(tsc_freq) = ctx.tsc_frequency {
                // A calibrated TSC is required by the hypervisor or was forced by the user.
                entry.cpuid = devices::tsc::fake_tsc_frequency_cpuid(tsc_freq, ctx.apic_frequency);
            } else if ctx.cpu_config.enable_pnp_data {
                // Expose TSC frequency to guest
                // Safe because we pass 0x15 for this call and the host
                // supports the `cpuid` instruction
                entry.cpuid = unsafe { (ctx.cpuid)(entry.function) };
            }
        }
        0x1A => {
            // Hybrid information leaf.
            if ctx.cpu_config.host_cpu_topology {
                // Safe because we pass 0x1A for this call and the host supports the
                // `cpuid` instruction
                entry.cpuid = unsafe { (ctx.cpuid)(entry.function) };
            }
            if let Some(hybrid) = &ctx.cpu_config.hybrid_type {
                match hybrid {
                    CpuHybridType::Atom => {
                        entry.cpuid.eax |= EAX_CORE_TYPE_ATOM << EAX_CORE_TYPE_SHIFT;
                    }
                    CpuHybridType::Core => {
                        entry.cpuid.eax |= EAX_CORE_TYPE_CORE << EAX_CORE_TYPE_SHIFT;
                    }
                }
            }
        }
        0xB | 0x1F => {
            if ctx.cpu_config.host_cpu_topology {
                return;
            }
            // Extended topology enumeration / V2 Extended topology enumeration
            // NOTE: these will need to be split if any of the fields that differ between
            // the two versions are to be set.
            // On AMD, these leaves are not used, so it is currently safe to leave in.
            entry.cpuid.edx = ctx.vcpu_id as u32; // x2APIC ID
            if entry.index == 0 {
                if ctx.cpu_config.no_smt || (ctx.cpu_count == 1) {
                    // Make it so that all VCPUs appear as different,
                    // non-hyperthreaded cores on the same package.
                    entry.cpuid.eax = 0; // Shift to get id of next level
                    entry.cpuid.ebx = 1; // Number of logical cpus at this level
                } else if ctx.cpu_count % 2 == 0 {
                    // Each core has 2 hyperthreads
                    entry.cpuid.eax = 1; // Shift to get id of next level
                    entry.cpuid.ebx = 2; // Number of logical cpus at this level
                } else {
                    // One core contain all the cpu_count hyperthreads
                    let cpu_bits: u32 = 32 - ((ctx.cpu_count - 1) as u32).leading_zeros();
                    entry.cpuid.eax = cpu_bits; // Shift to get id of next level
                    entry.cpuid.ebx = ctx.cpu_count as u32; // Number of logical cpus at this level
                }
                entry.cpuid.ecx = (ECX_TOPO_SMT_TYPE << ECX_TOPO_TYPE_SHIFT) | entry.index;
            } else if entry.index == 1 {
                let cpu_bits: u32 = 32 - ((ctx.cpu_count - 1) as u32).leading_zeros();
                entry.cpuid.eax = cpu_bits;
                // Number of logical cpus at this level
                entry.cpuid.ebx = (ctx.cpu_count as u32) & 0xffff;
                entry.cpuid.ecx = (ECX_TOPO_CORE_TYPE << ECX_TOPO_TYPE_SHIFT) | entry.index;
            } else {
                entry.cpuid.eax = 0;
                entry.cpuid.ebx = 0;
                entry.cpuid.ecx = 0;
            }
        }
        _ => (),
    }
}

/// Adjust all the entries in `cpuid` based on crosvm's cpuid logic and `ctx`. Calls `adjust_cpuid`
/// on each entry in `cpuid`, and adds any entries that should exist and are missing from `cpuid`.
pub fn filter_cpuid(cpuid: &mut hypervisor::CpuId, ctx: &CpuIdContext) {
    // Add an empty leaf 0x15 if we have a tsc_frequency and it's not in the current set of leaves.
    // It will be filled with the appropriate frequency information by `adjust_cpuid`.
    if ctx.tsc_frequency.is_some()
        && !cpuid
            .cpu_id_entries
            .iter()
            .any(|entry| entry.function == 0x15)
    {
        cpuid.cpu_id_entries.push(CpuIdEntry {
            function: 0x15,
            index: 0,
            flags: 0,
            cpuid: CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            },
        })
    }

    let entries = &mut cpuid.cpu_id_entries;
    for entry in entries.iter_mut() {
        adjust_cpuid(entry, ctx);
    }
}

/// Sets up the cpuid entries for the given vcpu.  Can fail if there are too many CPUs specified or
/// if an ioctl returns an error.
///
/// # Arguments
///
/// * `hypervisor` - `HypervisorX86_64` impl for getting supported CPU IDs.
/// * `irq_chip` - `IrqChipX86_64` for adjusting appropriate IrqChip CPUID bits.
/// * `vcpu` - `VcpuX86_64` for setting CPU ID.
/// * `vcpu_id` - The vcpu index of `vcpu`.
/// * `cpu_config` - CPU feature configurations.
pub fn setup_cpuid(
    hypervisor: &dyn HypervisorX86_64,
    irq_chip: &dyn IrqChipX86_64,
    vcpu: &dyn VcpuX86_64,
    vcpu_id: usize,
    nrcpus: usize,
    cpu_config: CpuConfigX86_64,
) -> Result<()> {
    let mut cpuid = hypervisor
        .get_supported_cpuid()
        .map_err(Error::GetSupportedCpusFailed)?;

    filter_cpuid(
        &mut cpuid,
        &CpuIdContext::new(
            vcpu_id,
            nrcpus,
            Some(irq_chip),
            cpu_config,
            hypervisor.check_capability(HypervisorCap::CalibratedTscLeafRequired),
            __cpuid_count,
            __cpuid,
        ),
    );

    vcpu.set_cpuid(&cpuid)
        .map_err(Error::SetSupportedCpusFailed)
}

const MANUFACTURER_ID_FUNCTION: u32 = 0x00000000;
const AMD_EBX: u32 = u32::from_le_bytes([b'A', b'u', b't', b'h']);
const AMD_EDX: u32 = u32::from_le_bytes([b'e', b'n', b't', b'i']);
const AMD_ECX: u32 = u32::from_le_bytes([b'c', b'A', b'M', b'D']);
const INTEL_EBX: u32 = u32::from_le_bytes([b'G', b'e', b'n', b'u']);
const INTEL_EDX: u32 = u32::from_le_bytes([b'i', b'n', b'e', b'I']);
const INTEL_ECX: u32 = u32::from_le_bytes([b'n', b't', b'e', b'l']);

pub fn cpu_manufacturer() -> CpuManufacturer {
    // safe because MANUFACTURER_ID_FUNCTION is a well known cpuid function,
    // and we own the result value afterwards.
    let result = unsafe { __cpuid(MANUFACTURER_ID_FUNCTION) };
    if result.ebx == AMD_EBX && result.edx == AMD_EDX && result.ecx == AMD_ECX {
        return CpuManufacturer::Amd;
    } else if result.ebx == INTEL_EBX && result.edx == INTEL_EDX && result.ecx == INTEL_ECX {
        return CpuManufacturer::Intel;
    }
    CpuManufacturer::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_manufacturer_test() {
        // this should be amd or intel. We don't support other processors for virtualization.
        let manufacturer = cpu_manufacturer();
        assert_ne!(manufacturer, CpuManufacturer::Unknown);
    }

    #[test]
    fn cpuid_copies_register() {
        let fake_cpuid_count = |_function: u32, _index: u32| CpuidResult {
            eax: 27,
            ebx: 18,
            ecx: 28,
            edx: 18,
        };
        let fake_cpuid = |_function: u32| CpuidResult {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        };
        let cpu_config = CpuConfigX86_64 {
            force_calibrated_tsc_leaf: false,
            host_cpu_topology: true,
            enable_hwp: false,
            enable_pnp_data: false,
            no_smt: false,
            itmt: false,
            hybrid_type: None,
        };
        let ctx = CpuIdContext {
            vcpu_id: 0,
            cpu_count: 0,
            x2apic: false,
            tsc_deadline_timer: false,
            apic_frequency: 0,
            tsc_frequency: None,
            cpu_config,
            cpuid_count: fake_cpuid_count,
            cpuid: fake_cpuid,
        };
        let mut cpu_id_entry = CpuIdEntry {
            function: 0x4,
            index: 0,
            flags: 0,
            cpuid: CpuidResult {
                eax: 31,
                ebx: 41,
                ecx: 59,
                edx: 26,
            },
        };
        adjust_cpuid(&mut cpu_id_entry, &ctx);
        assert_eq!(cpu_id_entry.cpuid.eax, 27)
    }
}

// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::arch::x86_64::{__cpuid, __cpuid_count};
use std::fmt::{self, Display};
use std::result;

use devices::{IrqChipCap, IrqChipX86_64};
use hypervisor::{HypervisorX86_64, VcpuX86_64};

#[derive(Debug, PartialEq)]
pub enum Error {
    GetSupportedCpusFailed(base::Error),
    SetSupportedCpusFailed(base::Error),
}
pub type Result<T> = result::Result<T, Error>;

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            GetSupportedCpusFailed(e) => write!(f, "GetSupportedCpus ioctl failed: {}", e),
            SetSupportedCpusFailed(e) => write!(f, "SetSupportedCpus ioctl failed: {}", e),
        }
    }
}

// CPUID bits in ebx, ecx, and edx.
const EBX_CLFLUSH_CACHELINE: u32 = 8; // Flush a cache line size.
const EBX_CLFLUSH_SIZE_SHIFT: u32 = 8; // Bytes flushed when executing CLFLUSH.
const EBX_CPU_COUNT_SHIFT: u32 = 16; // Index of this CPU.
const EBX_CPUID_SHIFT: u32 = 24; // Index of this CPU.
const ECX_EPB_SHIFT: u32 = 3; // "Energy Performance Bias" bit.
const ECX_X2APIC_SHIFT: u32 = 21; // APIC supports extended xAPIC (x2APIC) standard.
const ECX_TSC_DEADLINE_TIMER_SHIFT: u32 = 24; // TSC deadline mode of APIC timer.
const ECX_HYPERVISOR_SHIFT: u32 = 31; // Flag to be set when the cpu is running on a hypervisor.
const EDX_HTT_SHIFT: u32 = 28; // Hyper Threading Enabled.
const ECX_TOPO_TYPE_SHIFT: u32 = 8; // Topology Level type.
const ECX_TOPO_SMT_TYPE: u32 = 1; // SMT type.
const ECX_TOPO_CORE_TYPE: u32 = 2; // CORE type.
const EAX_CPU_CORES_SHIFT: u32 = 26; // Index of cpu cores in the same physical package.

fn filter_cpuid(
    vcpu_id: usize,
    cpu_count: usize,
    cpuid: &mut hypervisor::CpuId,
    irq_chip: &dyn IrqChipX86_64,
    no_smt: bool,
) {
    let entries = &mut cpuid.cpu_id_entries;

    for entry in entries {
        match entry.function {
            1 => {
                // X86 hypervisor feature
                if entry.index == 0 {
                    entry.ecx |= 1 << ECX_HYPERVISOR_SHIFT;
                }
                if irq_chip.check_capability(IrqChipCap::X2Apic) {
                    entry.ecx |= 1 << ECX_X2APIC_SHIFT;
                } else {
                    entry.ecx &= !(1 << ECX_X2APIC_SHIFT);
                }
                if irq_chip.check_capability(IrqChipCap::TscDeadlineTimer) {
                    entry.ecx |= 1 << ECX_TSC_DEADLINE_TIMER_SHIFT;
                }
                entry.ebx = (vcpu_id << EBX_CPUID_SHIFT) as u32
                    | (EBX_CLFLUSH_CACHELINE << EBX_CLFLUSH_SIZE_SHIFT);
                if cpu_count > 1 {
                    entry.ebx |= (cpu_count as u32) << EBX_CPU_COUNT_SHIFT;
                    entry.edx |= 1 << EDX_HTT_SHIFT;
                }
            }
            2 | 0x80000005 | 0x80000006 => unsafe {
                let result = __cpuid(entry.function);
                entry.eax = result.eax;
                entry.ebx = result.ebx;
                entry.ecx = result.ecx;
                entry.edx = result.edx;
            },
            4 => {
                unsafe {
                    let result = __cpuid_count(entry.function, entry.index);
                    entry.eax = result.eax;
                    entry.ebx = result.ebx;
                    entry.ecx = result.ecx;
                    entry.edx = result.edx;
                }
                entry.eax &= !0xFC000000;
                if cpu_count > 1 {
                    let cpu_cores = if no_smt {
                        cpu_count as u32
                    } else if cpu_count % 2 == 0 {
                        (cpu_count >> 1) as u32
                    } else {
                        1
                    };
                    entry.eax |= (cpu_cores - 1) << EAX_CPU_CORES_SHIFT;
                }
            }
            6 => {
                // Clear X86 EPB feature.  No frequency selection in the hypervisor.
                entry.ecx &= !(1 << ECX_EPB_SHIFT);
            }
            0xB | 0x1F => {
                // Extended topology enumeration / V2 Extended topology enumeration
                // NOTE: these will need to be split if any of the fields that differ between
                // the two versions are to be set.
                entry.edx = vcpu_id as u32; // x2APIC ID
                if entry.index == 0 {
                    if no_smt || (cpu_count == 1) {
                        // Make it so that all VCPUs appear as different,
                        // non-hyperthreaded cores on the same package.
                        entry.eax = 0; // Shift to get id of next level
                        entry.ebx = 1; // Number of logical cpus at this level
                    } else if cpu_count % 2 == 0 {
                        // Each core has 2 hyperthreads
                        entry.eax = 1; // Shift to get id of next level
                        entry.ebx = 2; // Number of logical cpus at this level
                    } else {
                        // One core contain all the cpu_count hyperthreads
                        let cpu_bits: u32 = 32 - ((cpu_count - 1) as u32).leading_zeros();
                        entry.eax = cpu_bits; // Shift to get id of next level
                        entry.ebx = cpu_count as u32; // Number of logical cpus at this level
                    }
                    entry.ecx = (ECX_TOPO_SMT_TYPE << ECX_TOPO_TYPE_SHIFT) | entry.index;
                } else if entry.index == 1 {
                    let cpu_bits: u32 = 32 - ((cpu_count - 1) as u32).leading_zeros();
                    entry.eax = cpu_bits;
                    entry.ebx = (cpu_count as u32) & 0xffff; // Number of logical cpus at this level
                    entry.ecx = (ECX_TOPO_CORE_TYPE << ECX_TOPO_TYPE_SHIFT) | entry.index;
                } else {
                    entry.eax = 0;
                    entry.ebx = 0;
                    entry.ecx = 0;
                }
            }
            _ => (),
        }
    }
}

/// Sets up the cpuid entries for the given vcpu.  Can fail if there are too many CPUs specified or
/// if an ioctl returns an error.
///
/// # Arguments
///
/// * `hypervisor` - `HypervisorX86_64` impl for getting supported CPU IDs.
/// * `vcpu` - `VcpuX86_64` for setting CPU ID.
/// * `vcpu_id` - The vcpu index of `vcpu`.
/// * `nrcpus` - The number of vcpus being used by this VM.
pub fn setup_cpuid(
    hypervisor: &dyn HypervisorX86_64,
    irq_chip: &dyn IrqChipX86_64,
    vcpu: &dyn VcpuX86_64,
    vcpu_id: usize,
    nrcpus: usize,
    no_smt: bool,
) -> Result<()> {
    let mut cpuid = hypervisor
        .get_supported_cpuid()
        .map_err(Error::GetSupportedCpusFailed)?;

    filter_cpuid(vcpu_id, nrcpus, &mut cpuid, irq_chip, no_smt);

    vcpu.set_cpuid(&cpuid)
        .map_err(Error::SetSupportedCpusFailed)
}

/// get host cpu max physical address bits
pub fn phy_max_address_bits() -> u32 {
    let mut phys_bits: u32 = 36;

    let highest_ext_function = unsafe { __cpuid(0x80000000) };
    if highest_ext_function.eax >= 0x80000008 {
        let addr_size = unsafe { __cpuid(0x80000008) };
        phys_bits = addr_size.eax & 0xff;
    }

    phys_bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use hypervisor::CpuIdEntry;

    #[test]
    fn feature_and_vendor_name() {
        let mut cpuid = hypervisor::CpuId::new(2);
        let guest_mem =
            vm_memory::GuestMemory::new(&[(vm_memory::GuestAddress(0), 0x10000)]).unwrap();
        let kvm = hypervisor::kvm::Kvm::new().unwrap();
        let vm = hypervisor::kvm::KvmVm::new(&kvm, guest_mem).unwrap();
        let irq_chip = devices::KvmKernelIrqChip::new(vm, 1).unwrap();

        let entries = &mut cpuid.cpu_id_entries;
        entries.push(CpuIdEntry {
            function: 0,
            ..Default::default()
        });
        entries.push(CpuIdEntry {
            function: 1,
            ecx: 0x10,
            edx: 0,
            ..Default::default()
        });
        filter_cpuid(1, 2, &mut cpuid, &irq_chip, false);

        let entries = &mut cpuid.cpu_id_entries;
        assert_eq!(entries[0].function, 0);
        assert_eq!(1, (entries[1].ebx >> EBX_CPUID_SHIFT) & 0x000000ff);
        assert_eq!(2, (entries[1].ebx >> EBX_CPU_COUNT_SHIFT) & 0x000000ff);
        assert_eq!(
            EBX_CLFLUSH_CACHELINE,
            (entries[1].ebx >> EBX_CLFLUSH_SIZE_SHIFT) & 0x000000ff
        );
        assert_ne!(0, entries[1].ecx & (1 << ECX_HYPERVISOR_SHIFT));
        assert_ne!(0, entries[1].edx & (1 << EDX_HTT_SHIFT));
    }
}

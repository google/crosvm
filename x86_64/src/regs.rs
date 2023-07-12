// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem;
use std::result;

use base::warn;
use hypervisor::Register;
use hypervisor::Sregs;
use hypervisor::VcpuX86_64;
use hypervisor::Vm;
use remain::sorted;
use thiserror::Error;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

use crate::gdt;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    /// Failed to get sregs for this cpu.
    #[error("failed to get sregs for this cpu: {0}")]
    GetSRegsIoctlFailed(base::Error),
    /// Failed to get base registers for this cpu.
    #[error("failed to get base registers for this cpu: {0}")]
    GettingRegistersIoctl(base::Error),
    /// Failed to set sregs for this cpu.
    #[error("failed to set sregs for this cpu: {0}")]
    SetSRegsIoctlFailed(base::Error),
    /// Failed to set base registers for this cpu.
    #[error("failed to set base registers for this cpu: {0}")]
    SettingRegistersIoctl(base::Error),
    /// Writing the GDT to RAM failed.
    #[error("writing the GDT to RAM failed")]
    WriteGDTFailure,
    /// Writing the IDT to RAM failed.
    #[error("writing the IDT to RAM failed")]
    WriteIDTFailure,
    /// Writing PDE to RAM failed.
    #[error("writing PDE to RAM failed")]
    WritePDEAddress,
    /// Writing PDPTE to RAM failed.
    #[error("writing PDPTE to RAM failed")]
    WritePDPTEAddress,
    /// Writing PML4 to RAM failed.
    #[error("writing PML4 to RAM failed")]
    WritePML4Address,
}

pub type Result<T> = result::Result<T, Error>;

const MTRR_MEMTYPE_UC: u8 = 0x0;
const MTRR_MEMTYPE_WB: u8 = 0x6;
const MTRR_VAR_VALID: u64 = 0x800;
const MTRR_ENABLE: u64 = 0x800;
const MTRR_PHYS_BASE_MSR: u32 = 0x200;
const MTRR_PHYS_MASK_MSR: u32 = 0x201;
const VAR_MTRR_NUM_MASK: u64 = 0xFF;

// Returns the value of the highest bit in a 64-bit value. Equivalent to
// 1 << HighBitSet(x)
fn get_power_of_two(data: u64) -> u64 {
    1 << (64 - data.leading_zeros() - 1)
}

// Returns the max length which suitable for mtrr setting based on the
// specified (base, len)
fn get_max_len(base: u64, len: u64) -> u64 {
    let mut ret = get_power_of_two(len);

    while base % ret != 0 {
        ret >>= 1;
    }

    ret
}

// For the specified (Base, Len), returns (base, len) pair which could be
// set into mtrr register. mtrr requires: the base-address alignment value can't be
// less than its length
fn get_mtrr_pairs(base: u64, len: u64) -> Vec<(u64, u64)> {
    let mut vecs = Vec::new();

    let mut remains = len;
    let mut new = base;
    while remains != 0 {
        let max = get_max_len(new, remains);
        vecs.push((new, max));
        remains -= max;
        new += max;
    }

    vecs
}

/// Returns the number of variable MTRR entries supported by `vcpu`.
pub fn vcpu_supported_variable_mtrrs(vcpu: &dyn VcpuX86_64) -> usize {
    // Get VAR MTRR num from MSR_MTRRcap
    let mut msrs = vec![Register {
        id: crate::msr_index::MSR_MTRRcap,
        ..Default::default()
    }];
    if vcpu.get_msrs(&mut msrs).is_err() {
        warn!("get msrs fail, guest with pass through device may be very slow");
        0
    } else {
        (msrs[0].value & VAR_MTRR_NUM_MASK) as usize
    }
}

/// Returns `true` if the given MSR `id` is a MTRR entry.
pub fn is_mtrr_msr(id: u32) -> bool {
    // Variable MTRR MSRs are pairs starting at 0x200 (MTRR_PHYS_BASE_MSR) / 0x201
    // (MTRR_PHYS_MASK_MSR) and extending up to 0xFF pairs at most.
    (id >= MTRR_PHYS_BASE_MSR && id <= MTRR_PHYS_BASE_MSR + 2 * VAR_MTRR_NUM_MASK as u32)
        || id == crate::msr_index::MSR_MTRRdefType
}

/// Returns the count of variable MTRR entries specified by the list of `msrs`.
pub fn count_variable_mtrrs(msrs: &[Register]) -> usize {
    // Each variable MTRR takes up two MSRs (base + mask), so divide by 2. This will also count the
    // MTRRdefType entry, but that is only one extra and the division truncates, so it won't affect
    // the final count.
    msrs.iter().filter(|msr| is_mtrr_msr(msr.id)).count() / 2
}

/// Returns a set of MSRs containing the MTRR configuration.
pub fn mtrr_msrs(vm: &dyn Vm, pci_start: u64) -> Vec<Register> {
    // Set pci_start .. 4G as UC
    // all others are set to default WB
    let pci_len = (1 << 32) - pci_start;
    let vecs = get_mtrr_pairs(pci_start, pci_len);

    let mut entries = Vec::new();

    let phys_mask: u64 = (1 << vm.get_guest_phys_addr_bits()) - 1;
    for (idx, (base, len)) in vecs.iter().enumerate() {
        let reg_idx = idx as u32 * 2;
        entries.push(Register {
            id: MTRR_PHYS_BASE_MSR + reg_idx,
            value: base | MTRR_MEMTYPE_UC as u64,
        });
        let mask: u64 = len.wrapping_neg() & phys_mask | MTRR_VAR_VALID;
        entries.push(Register {
            id: MTRR_PHYS_MASK_MSR + reg_idx,
            value: mask,
        });
    }
    // Disable fixed MTRRs and enable variable MTRRs, set default type as WB
    entries.push(Register {
        id: crate::msr_index::MSR_MTRRdefType,
        value: MTRR_ENABLE | MTRR_MEMTYPE_WB as u64,
    });
    entries
}

/// Returns the default value of MSRs at reset.
///
/// Currently only sets IA32_TSC to 0.
pub fn default_msrs() -> Vec<Register> {
    vec![
        Register {
            id: crate::msr_index::MSR_IA32_TSC,
            value: 0x0,
        },
        Register {
            id: crate::msr_index::MSR_IA32_MISC_ENABLE,
            value: crate::msr_index::MSR_IA32_MISC_ENABLE_FAST_STRING as u64,
        },
    ]
}

/// Configure Model specific registers for long (64-bit) mode.
pub fn long_mode_msrs() -> Vec<Register> {
    vec![
        Register {
            id: crate::msr_index::MSR_IA32_SYSENTER_CS,
            value: 0x0,
        },
        Register {
            id: crate::msr_index::MSR_IA32_SYSENTER_ESP,
            value: 0x0,
        },
        Register {
            id: crate::msr_index::MSR_IA32_SYSENTER_EIP,
            value: 0x0,
        },
        // x86_64 specific msrs, we only run on x86_64 not x86
        Register {
            id: crate::msr_index::MSR_STAR,
            value: 0x0,
        },
        Register {
            id: crate::msr_index::MSR_CSTAR,
            value: 0x0,
        },
        Register {
            id: crate::msr_index::MSR_KERNEL_GS_BASE,
            value: 0x0,
        },
        Register {
            id: crate::msr_index::MSR_SYSCALL_MASK,
            value: 0x0,
        },
        Register {
            id: crate::msr_index::MSR_LSTAR,
            value: 0x0,
        },
        // end of x86_64 specific code
        Register {
            id: crate::msr_index::MSR_IA32_TSC,
            value: 0x0,
        },
        Register {
            id: crate::msr_index::MSR_IA32_MISC_ENABLE,
            value: crate::msr_index::MSR_IA32_MISC_ENABLE_FAST_STRING as u64,
        },
    ]
}

const X86_CR0_PE: u64 = 0x1;
const X86_CR0_PG: u64 = 0x80000000;
const X86_CR4_PAE: u64 = 0x20;

const EFER_LME: u64 = 0x100;
const EFER_LMA: u64 = 0x400;

const BOOT_GDT_OFFSET: u64 = 0x1500;
const BOOT_IDT_OFFSET: u64 = 0x1528;

const BOOT_GDT_MAX: usize = 5;

fn write_gdt_table(table: &[u64], guest_mem: &GuestMemory) -> Result<()> {
    let boot_gdt_addr = GuestAddress(BOOT_GDT_OFFSET);
    for (index, entry) in table.iter().enumerate() {
        let addr = boot_gdt_addr
            .checked_add((index * mem::size_of::<u64>()) as u64)
            .ok_or(Error::WriteGDTFailure)?;
        if !guest_mem.is_valid_range(addr, mem::size_of::<u64>() as u64) {
            return Err(Error::WriteGDTFailure);
        }

        guest_mem
            .write_obj_at_addr(*entry, addr)
            .map_err(|_| Error::WriteGDTFailure)?;
    }
    Ok(())
}

fn write_idt_value(val: u64, guest_mem: &GuestMemory) -> Result<()> {
    let boot_idt_addr = GuestAddress(BOOT_IDT_OFFSET);
    guest_mem
        .write_obj_at_addr(val, boot_idt_addr)
        .map_err(|_| Error::WriteIDTFailure)
}

/// Configures the GDT, IDT, and segment registers for long mode.
pub fn configure_segments_and_sregs(mem: &GuestMemory, sregs: &mut Sregs) -> Result<()> {
    // reference: https://docs.kernel.org/arch/x86/boot.html?highlight=__BOOT_CS#id1
    let gdt_table: [u64; BOOT_GDT_MAX] = [
        gdt::gdt_entry(0, 0, 0),            // NULL
        gdt::gdt_entry(0, 0, 0),            // NULL
        gdt::gdt_entry(0xa09b, 0, 0xfffff), // CODE
        gdt::gdt_entry(0xc093, 0, 0xfffff), // DATA
        gdt::gdt_entry(0x808b, 0, 0xfffff), // TSS
    ];

    let code_seg = gdt::segment_from_gdt(gdt_table[2], 2);
    let data_seg = gdt::segment_from_gdt(gdt_table[3], 3);
    let tss_seg = gdt::segment_from_gdt(gdt_table[4], 4);

    // Write segments
    write_gdt_table(&gdt_table[..], mem)?;
    sregs.gdt.base = BOOT_GDT_OFFSET;
    sregs.gdt.limit = mem::size_of_val(&gdt_table) as u16 - 1;

    write_idt_value(0, mem)?;
    sregs.idt.base = BOOT_IDT_OFFSET;
    sregs.idt.limit = mem::size_of::<u64>() as u16 - 1;

    sregs.cs = code_seg;
    sregs.ds = data_seg;
    sregs.es = data_seg;
    sregs.fs = data_seg;
    sregs.gs = data_seg;
    sregs.ss = data_seg;
    sregs.tr = tss_seg;

    /* 64-bit protected mode */
    sregs.cr0 |= X86_CR0_PE;
    sregs.efer |= EFER_LME;

    Ok(())
}

/// Configures the system page tables and control registers for long mode with paging.
pub fn setup_page_tables(mem: &GuestMemory, sregs: &mut Sregs) -> Result<()> {
    // Puts PML4 right after zero page but aligned to 4k.
    let boot_pml4_addr = GuestAddress(0x9000);
    let boot_pdpte_addr = GuestAddress(0xa000);
    let boot_pde_addr = GuestAddress(0xb000);

    // Entry covering VA [0..512GB)
    mem.write_obj_at_addr(boot_pdpte_addr.offset() | 0x03, boot_pml4_addr)
        .map_err(|_| Error::WritePML4Address)?;

    // Entry covering VA [0..1GB)
    mem.write_obj_at_addr(boot_pde_addr.offset() | 0x03, boot_pdpte_addr)
        .map_err(|_| Error::WritePDPTEAddress)?;

    // 512 2MB entries together covering VA [0..1GB). Note we are assuming
    // CPU supports 2MB pages (/proc/cpuinfo has 'pse'). All modern CPUs do.
    for i in 0..512 {
        mem.write_obj_at_addr((i << 21) + 0x83u64, boot_pde_addr.unchecked_add(i * 8))
            .map_err(|_| Error::WritePDEAddress)?;
    }
    sregs.cr3 = boot_pml4_addr.offset();
    sregs.cr4 |= X86_CR4_PAE;
    sregs.cr0 |= X86_CR0_PG;
    sregs.efer |= EFER_LMA; // Long mode is active. Must be auto-enabled with CR0_PG.
    Ok(())
}

#[cfg(test)]
mod tests {
    use vm_memory::GuestAddress;
    use vm_memory::GuestMemory;

    use super::*;

    fn create_guest_mem() -> GuestMemory {
        GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap()
    }

    fn read_u64(gm: &GuestMemory, offset: u64) -> u64 {
        let read_addr = GuestAddress(offset);
        gm.read_obj_from_addr(read_addr).unwrap()
    }

    #[test]
    fn segments_and_sregs() {
        let mut sregs = Default::default();
        let gm = create_guest_mem();
        configure_segments_and_sregs(&gm, &mut sregs).unwrap();

        assert_eq!(0x0, read_u64(&gm, BOOT_GDT_OFFSET));
        assert_eq!(0xaf9b000000ffff, read_u64(&gm, BOOT_GDT_OFFSET + 0x10));
        assert_eq!(0xcf93000000ffff, read_u64(&gm, BOOT_GDT_OFFSET + 0x18));
        assert_eq!(0x8f8b000000ffff, read_u64(&gm, BOOT_GDT_OFFSET + 0x20));
        assert_eq!(0x0, read_u64(&gm, BOOT_IDT_OFFSET));

        assert_eq!(0, sregs.cs.base);
        assert_eq!(0xfffff, sregs.ds.limit);
        assert_eq!(0x10, sregs.cs.selector);
        assert_eq!(0x18, sregs.ds.selector);
        assert_eq!(0x18, sregs.es.selector);
        assert_eq!(0x18, sregs.ss.selector);
        assert_eq!(1, sregs.fs.present);
        assert_eq!(1, sregs.gs.g);
        assert_eq!(0, sregs.ss.avl);
        assert_eq!(0, sregs.tr.base);
        assert_eq!(0xfffff, sregs.tr.limit);
        assert_eq!(0, sregs.tr.avl);
        assert_eq!(X86_CR0_PE, sregs.cr0 & X86_CR0_PE);
        assert_eq!(EFER_LME, sregs.efer);
    }

    #[test]
    fn page_tables() {
        let mut sregs = Default::default();
        let gm = create_guest_mem();
        setup_page_tables(&gm, &mut sregs).unwrap();

        assert_eq!(0xa003, read_u64(&gm, 0x9000));
        assert_eq!(0xb003, read_u64(&gm, 0xa000));
        for i in 0..512 {
            assert_eq!((i << 21) + 0x83u64, read_u64(&gm, 0xb000 + i * 8));
        }

        assert_eq!(0x9000, sregs.cr3);
        assert_eq!(X86_CR4_PAE, sregs.cr4);
        assert_eq!(X86_CR0_PG, sregs.cr0 & X86_CR0_PG);
    }
}

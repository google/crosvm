// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt::{self, Display};
use std::{mem, result};

use base::{self, warn};
use hypervisor::{Fpu, Register, Regs, Sregs, VcpuX86_64};
use vm_memory::{GuestAddress, GuestMemory};

use crate::gdt;

#[derive(Debug)]
pub enum Error {
    /// Setting up msrs failed.
    MsrIoctlFailed(base::Error),
    /// Failed to configure the FPU.
    FpuIoctlFailed(base::Error),
    /// Failed to get sregs for this cpu.
    GetSRegsIoctlFailed(base::Error),
    /// Failed to set base registers for this cpu.
    SettingRegistersIoctl(base::Error),
    /// Failed to set sregs for this cpu.
    SetSRegsIoctlFailed(base::Error),
    /// Writing the GDT to RAM failed.
    WriteGDTFailure,
    /// Writing the IDT to RAM failed.
    WriteIDTFailure,
    /// Writing PML4 to RAM failed.
    WritePML4Address,
    /// Writing PDPTE to RAM failed.
    WritePDPTEAddress,
    /// Writing PDE to RAM failed.
    WritePDEAddress,
}
pub type Result<T> = result::Result<T, Error>;

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            MsrIoctlFailed(e) => write!(f, "setting up msrs failed: {}", e),
            FpuIoctlFailed(e) => write!(f, "failed to configure the FPU: {}", e),
            GetSRegsIoctlFailed(e) => write!(f, "failed to get sregs for this cpu: {}", e),
            SettingRegistersIoctl(e) => {
                write!(f, "failed to set base registers for this cpu: {}", e)
            }
            SetSRegsIoctlFailed(e) => write!(f, "failed to set sregs for this cpu: {}", e),
            WriteGDTFailure => write!(f, "writing the GDT to RAM failed"),
            WriteIDTFailure => write!(f, "writing the IDT to RAM failed"),
            WritePML4Address => write!(f, "writing PML4 to RAM failed"),
            WritePDPTEAddress => write!(f, "writing PDPTE to RAM failed"),
            WritePDEAddress => write!(f, "writing PDE to RAM failed"),
        }
    }
}

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

fn append_mtrr_entries(vpu: &dyn VcpuX86_64, pci_start: u64, entries: &mut Vec<Register>) {
    // Get VAR MTRR num from MSR_MTRRcap
    let mut msrs = vec![Register {
        id: crate::msr_index::MSR_MTRRcap,
        ..Default::default()
    }];
    if vpu.get_msrs(&mut msrs).is_err() {
        warn!("get msrs fail, guest with pass through device may be very slow");
        return;
    }
    let var_num = msrs[0].value & VAR_MTRR_NUM_MASK;

    // Set pci_start .. 4G as UC
    // all others are set to default WB
    let pci_len = (1 << 32) - pci_start;
    let vecs = get_mtrr_pairs(pci_start, pci_len);
    if vecs.len() as u64 > var_num {
        warn!(
            "mtrr fail for pci mmio, please check pci_start addr,
              guest with pass through device may be very slow"
        );
        return;
    }

    let phys_mask: u64 = (1 << crate::cpuid::phy_max_address_bits()) - 1;
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
}

fn create_msr_entries(vcpu: &dyn VcpuX86_64, pci_start: u64) -> Vec<Register> {
    let mut entries = vec![
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
    ];
    append_mtrr_entries(vcpu, pci_start, &mut entries);
    entries
}

/// Configure Model specific registers for x86
///
/// # Arguments
///
/// * `vcpu` - Structure for the vcpu that holds the vcpu fd.
pub fn setup_msrs(vcpu: &dyn VcpuX86_64, pci_start: u64) -> Result<()> {
    let msrs = create_msr_entries(vcpu, pci_start);
    vcpu.set_msrs(&msrs).map_err(Error::MsrIoctlFailed)
}

/// Configure FPU registers for x86
///
/// # Arguments
///
/// * `vcpu` - Structure for the vcpu that holds the vcpu fd.
pub fn setup_fpu(vcpu: &dyn VcpuX86_64) -> Result<()> {
    let fpu = Fpu {
        fcw: 0x37f,
        mxcsr: 0x1f80,
        ..Default::default()
    };

    vcpu.set_fpu(&fpu).map_err(Error::FpuIoctlFailed)
}

/// Configure base registers for x86
///
/// # Arguments
///
/// * `vcpu` - Structure for the vcpu that holds the vcpu fd.
/// * `boot_ip` - Starting instruction pointer.
/// * `boot_sp` - Starting stack pointer.
/// * `boot_si` - Must point to zero page address per Linux ABI.
pub fn setup_regs(vcpu: &dyn VcpuX86_64, boot_ip: u64, boot_sp: u64, boot_si: u64) -> Result<()> {
    let regs = Regs {
        rflags: 0x0000000000000002u64,
        rip: boot_ip,
        rsp: boot_sp,
        rbp: boot_sp,
        rsi: boot_si,
        ..Default::default()
    };

    vcpu.set_regs(&regs).map_err(Error::SettingRegistersIoctl)
}

const X86_CR0_PE: u64 = 0x1;
const X86_CR0_PG: u64 = 0x80000000;
const X86_CR4_PAE: u64 = 0x20;

const EFER_LME: u64 = 0x100;
const EFER_LMA: u64 = 0x400;

const BOOT_GDT_OFFSET: u64 = 0x500;
const BOOT_IDT_OFFSET: u64 = 0x520;

const BOOT_GDT_MAX: usize = 4;

fn write_gdt_table(table: &[u64], guest_mem: &GuestMemory) -> Result<()> {
    let boot_gdt_addr = GuestAddress(BOOT_GDT_OFFSET);
    for (index, entry) in table.iter().enumerate() {
        let addr = guest_mem
            .checked_offset(boot_gdt_addr, (index * mem::size_of::<u64>()) as u64)
            .ok_or(Error::WriteGDTFailure)?;
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

fn configure_segments_and_sregs(mem: &GuestMemory, sregs: &mut Sregs) -> Result<()> {
    let gdt_table: [u64; BOOT_GDT_MAX as usize] = [
        gdt::gdt_entry(0, 0, 0),            // NULL
        gdt::gdt_entry(0xa09b, 0, 0xfffff), // CODE
        gdt::gdt_entry(0xc093, 0, 0xfffff), // DATA
        gdt::gdt_entry(0x808b, 0, 0xfffff), // TSS
    ];

    let code_seg = gdt::segment_from_gdt(gdt_table[1], 1);
    let data_seg = gdt::segment_from_gdt(gdt_table[2], 2);
    let tss_seg = gdt::segment_from_gdt(gdt_table[3], 3);

    // Write segments
    write_gdt_table(&gdt_table[..], mem)?;
    sregs.gdt.base = BOOT_GDT_OFFSET as u64;
    sregs.gdt.limit = mem::size_of_val(&gdt_table) as u16 - 1;

    write_idt_value(0, mem)?;
    sregs.idt.base = BOOT_IDT_OFFSET as u64;
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

fn setup_page_tables(mem: &GuestMemory, sregs: &mut Sregs) -> Result<()> {
    // Puts PML4 right after zero page but aligned to 4k.
    let boot_pml4_addr = GuestAddress(0x9000);
    let boot_pdpte_addr = GuestAddress(0xa000);
    let boot_pde_addr = GuestAddress(0xb000);

    // Entry covering VA [0..512GB)
    mem.write_obj_at_addr(boot_pdpte_addr.offset() as u64 | 0x03, boot_pml4_addr)
        .map_err(|_| Error::WritePML4Address)?;

    // Entry covering VA [0..1GB)
    mem.write_obj_at_addr(boot_pde_addr.offset() as u64 | 0x03, boot_pdpte_addr)
        .map_err(|_| Error::WritePDPTEAddress)?;

    // 512 2MB entries together covering VA [0..1GB). Note we are assuming
    // CPU supports 2MB pages (/proc/cpuinfo has 'pse'). All modern CPUs do.
    for i in 0..512 {
        mem.write_obj_at_addr((i << 21) + 0x83u64, boot_pde_addr.unchecked_add(i * 8))
            .map_err(|_| Error::WritePDEAddress)?;
    }
    sregs.cr3 = boot_pml4_addr.offset() as u64;
    sregs.cr4 |= X86_CR4_PAE;
    sregs.cr0 |= X86_CR0_PG;
    sregs.efer |= EFER_LMA; // Long mode is active. Must be auto-enabled with CR0_PG.
    Ok(())
}

/// Configures the segment registers and system page tables for a given CPU.
///
/// # Arguments
///
/// * `mem` - The memory that will be passed to the guest.
/// * `vcpu` - The VCPU to configure registers on.
pub fn setup_sregs(mem: &GuestMemory, vcpu: &dyn VcpuX86_64) -> Result<()> {
    let mut sregs = vcpu.get_sregs().map_err(Error::GetSRegsIoctlFailed)?;

    configure_segments_and_sregs(mem, &mut sregs)?;
    setup_page_tables(mem, &mut sregs)?; // TODO(dgreid) - Can this be done once per system instead?

    vcpu.set_sregs(&sregs).map_err(Error::SetSRegsIoctlFailed)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vm_memory::{GuestAddress, GuestMemory};

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
        assert_eq!(0xaf9b000000ffff, read_u64(&gm, BOOT_GDT_OFFSET + 8));
        assert_eq!(0xcf93000000ffff, read_u64(&gm, BOOT_GDT_OFFSET + 16));
        assert_eq!(0x8f8b000000ffff, read_u64(&gm, BOOT_GDT_OFFSET + 24));
        assert_eq!(0x0, read_u64(&gm, BOOT_IDT_OFFSET));

        assert_eq!(0, sregs.cs.base);
        assert_eq!(0xfffff, sregs.ds.limit);
        assert_eq!(0x10, sregs.es.selector);
        assert_eq!(1, sregs.fs.present);
        assert_eq!(1, sregs.gs.g);
        assert_eq!(0, sregs.ss.avl);
        assert_eq!(0, sregs.tr.base);
        assert_eq!(0xfffff, sregs.tr.limit);
        assert_eq!(0, sregs.tr.avl);
        assert_eq!(X86_CR0_PE, sregs.cr0);
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
        assert_eq!(X86_CR0_PG, sregs.cr0);
    }
}

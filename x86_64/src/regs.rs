// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::alloc::Layout;
use std::fmt::{self, Display};
use std::{mem, result};

use assertions::const_assert;
use kvm;
use kvm_sys::kvm_fpu;
use kvm_sys::kvm_msr_entry;
use kvm_sys::kvm_msrs;
use kvm_sys::kvm_regs;
use kvm_sys::kvm_sregs;
use sys_util::{self, GuestAddress, GuestMemory, LayoutAllocation};

use crate::gdt;

#[derive(Debug)]
pub enum Error {
    /// Setting up msrs failed.
    MsrIoctlFailed(sys_util::Error),
    /// Failed to configure the FPU.
    FpuIoctlFailed(sys_util::Error),
    /// Failed to get sregs for this cpu.
    GetSRegsIoctlFailed(sys_util::Error),
    /// Failed to set base registers for this cpu.
    SettingRegistersIoctl(sys_util::Error),
    /// Failed to set sregs for this cpu.
    SetSRegsIoctlFailed(sys_util::Error),
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

fn create_msr_entries() -> Vec<kvm_msr_entry> {
    let mut entries = Vec::<kvm_msr_entry>::new();

    entries.push(kvm_msr_entry {
        index: crate::msr_index::MSR_IA32_SYSENTER_CS,
        data: 0x0,
        ..Default::default()
    });
    entries.push(kvm_msr_entry {
        index: crate::msr_index::MSR_IA32_SYSENTER_ESP,
        data: 0x0,
        ..Default::default()
    });
    entries.push(kvm_msr_entry {
        index: crate::msr_index::MSR_IA32_SYSENTER_EIP,
        data: 0x0,
        ..Default::default()
    });
    // x86_64 specific msrs, we only run on x86_64 not x86
    entries.push(kvm_msr_entry {
        index: crate::msr_index::MSR_STAR,
        data: 0x0,
        ..Default::default()
    });
    entries.push(kvm_msr_entry {
        index: crate::msr_index::MSR_CSTAR,
        data: 0x0,
        ..Default::default()
    });
    entries.push(kvm_msr_entry {
        index: crate::msr_index::MSR_KERNEL_GS_BASE,
        data: 0x0,
        ..Default::default()
    });
    entries.push(kvm_msr_entry {
        index: crate::msr_index::MSR_SYSCALL_MASK,
        data: 0x0,
        ..Default::default()
    });
    entries.push(kvm_msr_entry {
        index: crate::msr_index::MSR_LSTAR,
        data: 0x0,
        ..Default::default()
    });
    // end of x86_64 specific code
    entries.push(kvm_msr_entry {
        index: crate::msr_index::MSR_IA32_TSC,
        data: 0x0,
        ..Default::default()
    });
    entries.push(kvm_msr_entry {
        index: crate::msr_index::MSR_IA32_MISC_ENABLE,
        data: crate::msr_index::MSR_IA32_MISC_ENABLE_FAST_STRING as u64,
        ..Default::default()
    });

    entries
}

/// Configure Model specific registers for x86
///
/// # Arguments
///
/// * `vcpu` - Structure for the vcpu that holds the vcpu fd.
pub fn setup_msrs(vcpu: &kvm::Vcpu) -> Result<()> {
    const SIZE_OF_MSRS: usize = mem::size_of::<kvm_msrs>();
    const SIZE_OF_ENTRY: usize = mem::size_of::<kvm_msr_entry>();
    const ALIGN_OF_MSRS: usize = mem::align_of::<kvm_msrs>();
    const ALIGN_OF_ENTRY: usize = mem::align_of::<kvm_msr_entry>();
    const_assert!(ALIGN_OF_MSRS >= ALIGN_OF_ENTRY);

    let entry_vec = create_msr_entries();
    let size = SIZE_OF_MSRS + entry_vec.len() * SIZE_OF_ENTRY;
    let layout = Layout::from_size_align(size, ALIGN_OF_MSRS).expect("impossible layout");
    let mut allocation = LayoutAllocation::zeroed(layout);

    // Safe to obtain an exclusive reference because there are no other
    // references to the allocation yet and all-zero is a valid bit pattern.
    let msrs = unsafe { allocation.as_mut::<kvm_msrs>() };

    unsafe {
        // Mapping the unsized array to a slice is unsafe becase the length isn't known.  Providing
        // the length used to create the struct guarantees the entire slice is valid.
        let entries: &mut [kvm_msr_entry] = msrs.entries.as_mut_slice(entry_vec.len());
        entries.copy_from_slice(&entry_vec);
    }
    msrs.nmsrs = entry_vec.len() as u32;

    vcpu.set_msrs(msrs).map_err(Error::MsrIoctlFailed)?;

    Ok(())

    // msrs allocation is deallocated.
}

/// Configure FPU registers for x86
///
/// # Arguments
///
/// * `vcpu` - Structure for the vcpu that holds the vcpu fd.
pub fn setup_fpu(vcpu: &kvm::Vcpu) -> Result<()> {
    let fpu: kvm_fpu = kvm_fpu {
        fcw: 0x37f,
        mxcsr: 0x1f80,
        ..Default::default()
    };

    vcpu.set_fpu(&fpu).map_err(Error::FpuIoctlFailed)?;

    Ok(())
}

/// Configure base registers for x86
///
/// # Arguments
///
/// * `vcpu` - Structure for the vcpu that holds the vcpu fd.
/// * `boot_ip` - Starting instruction pointer.
/// * `boot_sp` - Starting stack pointer.
/// * `boot_si` - Must point to zero page address per Linux ABI.
pub fn setup_regs(vcpu: &kvm::Vcpu, boot_ip: u64, boot_sp: u64, boot_si: u64) -> Result<()> {
    let regs: kvm_regs = kvm_regs {
        rflags: 0x0000000000000002u64,
        rip: boot_ip,
        rsp: boot_sp,
        rbp: boot_sp,
        rsi: boot_si,
        ..Default::default()
    };

    vcpu.set_regs(&regs).map_err(Error::SettingRegistersIoctl)?;

    Ok(())
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

fn configure_segments_and_sregs(mem: &GuestMemory, sregs: &mut kvm_sregs) -> Result<()> {
    let gdt_table: [u64; BOOT_GDT_MAX as usize] = [
        gdt::gdt_entry(0, 0, 0),            // NULL
        gdt::gdt_entry(0xa09b, 0, 0xfffff), // CODE
        gdt::gdt_entry(0xc093, 0, 0xfffff), // DATA
        gdt::gdt_entry(0x808b, 0, 0xfffff), // TSS
    ];

    let code_seg = gdt::kvm_segment_from_gdt(gdt_table[1], 1);
    let data_seg = gdt::kvm_segment_from_gdt(gdt_table[2], 2);
    let tss_seg = gdt::kvm_segment_from_gdt(gdt_table[3], 3);

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

fn setup_page_tables(mem: &GuestMemory, sregs: &mut kvm_sregs) -> Result<()> {
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
/// * `vcpu_fd` - The FD returned from the KVM_CREATE_VCPU ioctl.
pub fn setup_sregs(mem: &GuestMemory, vcpu: &kvm::Vcpu) -> Result<()> {
    let mut sregs: kvm_sregs = vcpu.get_sregs().map_err(Error::GetSRegsIoctlFailed)?;

    configure_segments_and_sregs(mem, &mut sregs)?;
    setup_page_tables(mem, &mut sregs)?; // TODO(dgreid) - Can this be done once per system instead?

    vcpu.set_sregs(&sregs).map_err(Error::SetSRegsIoctlFailed)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sys_util::{GuestAddress, GuestMemory};

    fn create_guest_mem() -> GuestMemory {
        GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap()
    }

    fn read_u64(gm: &GuestMemory, offset: u64) -> u64 {
        let read_addr = GuestAddress(offset);
        gm.read_obj_from_addr(read_addr).unwrap()
    }

    #[test]
    fn segments_and_sregs() {
        let mut sregs: kvm_sregs = Default::default();
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
        let mut sregs: kvm_sregs = Default::default();
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

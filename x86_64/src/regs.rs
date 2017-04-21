// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::Cursor;
use std::mem;
use std::result;

use byteorder::{LittleEndian, WriteBytesExt};

use kvm;
use kvm_sys::kvm_fpu;
use kvm_sys::kvm_msr_entry;
use kvm_sys::kvm_msrs;
use kvm_sys::kvm_regs;
use kvm_sys::kvm_sregs;
use gdt;
use sys_util;

#[derive(Debug)]
pub enum Error {
    MsrIoctlFailed(sys_util::Error),
    FpuIoctlFailed(sys_util::Error),
    SettingRegistersIoctl(sys_util::Error),
    SRegsIoctlFailed(sys_util::Error),
}
pub type Result<T> = result::Result<T, Error>;

fn create_msr_entries() -> Vec<kvm_msr_entry> {
    let mut entries = Vec::<kvm_msr_entry>::new();

    entries.push(kvm_msr_entry {
                     index: ::msr_index::MSR_IA32_SYSENTER_CS,
                     data: 0x0,
                     ..Default::default()
                 });
    entries.push(kvm_msr_entry {
                     index: ::msr_index::MSR_IA32_SYSENTER_ESP,
                     data: 0x0,
                     ..Default::default()
                 });
    entries.push(kvm_msr_entry {
                     index: ::msr_index::MSR_IA32_SYSENTER_EIP,
                     data: 0x0,
                     ..Default::default()
                 });
    // x86_64 specific msrs, we only run on x86_64 not x86
    entries.push(kvm_msr_entry {
                     index: ::msr_index::MSR_STAR,
                     data: 0x0,
                     ..Default::default()
                 });
    entries.push(kvm_msr_entry {
                     index: ::msr_index::MSR_CSTAR,
                     data: 0x0,
                     ..Default::default()
                 });
    entries.push(kvm_msr_entry {
                     index: ::msr_index::MSR_KERNEL_GS_BASE,
                     data: 0x0,
                     ..Default::default()
                 });
    entries.push(kvm_msr_entry {
                     index: ::msr_index::MSR_SYSCALL_MASK,
                     data: 0x0,
                     ..Default::default()
                 });
    entries.push(kvm_msr_entry {
                     index: ::msr_index::MSR_LSTAR,
                     data: 0x0,
                     ..Default::default()
                 });
    // end of x86_64 specific code
    entries.push(kvm_msr_entry {
                     index: ::msr_index::MSR_IA32_TSC,
                     data: 0x0,
                     ..Default::default()
                 });
    entries.push(kvm_msr_entry {
                     index: ::msr_index::MSR_IA32_MISC_ENABLE,
                     data: ::msr_index::MSR_IA32_MISC_ENABLE_FAST_STRING as u64,
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
    let entry_vec = create_msr_entries();
    let vec_size_bytes = mem::size_of::<kvm_msrs>() +
                         (entry_vec.len() * mem::size_of::<kvm_msr_entry>());
    let vec: Vec<u8> = Vec::with_capacity(vec_size_bytes);
    let mut msrs: &mut kvm_msrs = unsafe {
        // Converting the vector's memory to a struct is unsafe.  Carefully using the read-only
        // vector to size and set the members ensures no out-of-bounds erros below.
        &mut *(vec.as_ptr() as *mut kvm_msrs)
    };

    unsafe {
        // Mapping the unsized array to a slice is unsafe becase the length isn't known.  Providing
        // the length used to create the struct guarantees the entire slice is valid.
        let entries: &mut [kvm_msr_entry] = msrs.entries.as_mut_slice(entry_vec.len());
        entries.copy_from_slice(&entry_vec);
    }
    msrs.nmsrs = entry_vec.len() as u32;

    vcpu.set_msrs(&msrs)
        .map_err(|e| Error::MsrIoctlFailed(e))?;

    Ok(())
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

    vcpu.set_fpu(&fpu)
        .map_err(|e| Error::FpuIoctlFailed(e))?;

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

    vcpu.set_regs(&regs)
        .map_err(|e| Error::SettingRegistersIoctl(e))?;

    Ok(())
}

const X86_CR0_PE: u64 = 0x1;
const X86_CR0_PG: u64 = 0x80000000;
const X86_CR4_PAE: u64 = 0x20;

const EFER_LME: u64 = 0x100;

const BOOT_GDT_OFFSET: usize = 0x500;
const BOOT_IDT_OFFSET: usize = 0x520;

const BOOT_GDT_MAX: usize = 4;

fn write_gdt_table(table: &[u64; BOOT_GDT_MAX], out: &mut [u8]) {
    let mut writer = Cursor::new(&mut out[BOOT_GDT_OFFSET..
                                      (BOOT_GDT_OFFSET + mem::size_of_val(table))]);
    for entry in table.iter() {
        writer.write_u64::<LittleEndian>(*entry).unwrap(); // Can't fail if the above slice worked.
    }
}

fn write_idt_value(val: u64, out: &mut [u8]) {
    let mut writer = Cursor::new(&mut out[BOOT_IDT_OFFSET..
                                      (BOOT_IDT_OFFSET + mem::size_of::<u64>())]);
    writer.write_u64::<LittleEndian>(val).unwrap(); // Can't fail if the above slice worked.
}

fn configure_segments_and_sregs(mem: &mut [u8], sregs: &mut kvm_sregs) {
    let gdt_table: [u64; BOOT_GDT_MAX as usize] = [
        gdt::gdt_entry(0, 0, 0), // NULL
        gdt::gdt_entry(0xa09b, 0, 0xfffff), // CODE
        gdt::gdt_entry(0xc093, 0, 0xfffff), // DATA
        gdt::gdt_entry(0x808b, 0, 0xfffff), // TSS
    ];

    let code_seg = gdt::kvm_segment_from_gdt(gdt_table[1], 1);
    let data_seg = gdt::kvm_segment_from_gdt(gdt_table[2], 2);
    let tss_seg = gdt::kvm_segment_from_gdt(gdt_table[3], 3);

    // Write segments
    write_gdt_table(&gdt_table, mem);
    sregs.gdt.base = BOOT_GDT_OFFSET as u64;
    sregs.gdt.limit = mem::size_of_val(&gdt_table) as u16 - 1;

    write_idt_value(0, mem);
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
}

fn setup_page_tables(mem: &mut [u8], sregs: &mut kvm_sregs) {
    // Puts PML4 right after zero page but aligned to 4k.
    const BOOT_PML4_OFFSET: usize = 0x9000;
    const BOOT_PDPTE_OFFSET: usize = 0xa000;
    const TABLE_LEN: usize = 4096;

    {
        let out_slice = &mut mem[BOOT_PML4_OFFSET..(BOOT_PML4_OFFSET + TABLE_LEN)];
        for v in out_slice.iter_mut() {
            *v = 0;
        }
        let mut writer = Cursor::new(out_slice);
        // write_u64 Can't fail if the above slice works.
        writer
            .write_u64::<LittleEndian>(BOOT_PDPTE_OFFSET as u64 | 3)
            .unwrap();
    }
    {
        let out_slice = &mut mem[BOOT_PDPTE_OFFSET..(BOOT_PDPTE_OFFSET + TABLE_LEN)];
        for v in out_slice.iter_mut() {
            *v = 0;
        }
        let mut writer = Cursor::new(out_slice);
        writer.write_u64::<LittleEndian>(0x83).unwrap(); // Can't fail if the slice works.
    }
    sregs.cr3 = BOOT_PML4_OFFSET as u64;
    sregs.cr4 |= X86_CR4_PAE;
    sregs.cr0 |= X86_CR0_PG;
}

/// Configures the segment registers and system page tables for a given CPU.
///
/// # Arguments
///
/// * `guest_mem` - The memory that will be passed to the guest.
/// * `vcpu_fd` - The FD returned from the KVM_CREATE_VCPU ioctl.
pub fn setup_sregs(mem: &mut [u8], vcpu: &kvm::Vcpu) -> Result<()> {
    let mut sregs: kvm_sregs = vcpu.get_sregs()
        .map_err(|e| Error::SRegsIoctlFailed(e))?;

    configure_segments_and_sregs(mem, &mut sregs);
    setup_page_tables(mem, &mut sregs); // TODO(dgreid) - Can this be done once per system instead?

    vcpu.set_sregs(&sregs)
        .map_err(|e| Error::SRegsIoctlFailed(e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use byteorder::{LittleEndian, ReadBytesExt};
    use std::io::Cursor;
    use super::*;

    #[test]
    fn segments_and_sregs() {
        let mut sregs: kvm_sregs = Default::default();
        let mut mem_vec: Vec<u8> = Vec::with_capacity(0x10000);
        unsafe {
            mem_vec.set_len(0x10000);
        }
        configure_segments_and_sregs(mem_vec.as_mut_slice(), &mut sregs);
        let mut reader = Cursor::new(&mem_vec.as_slice()[BOOT_GDT_OFFSET..]);
        assert_eq!(0, reader.read_u64::<LittleEndian>().unwrap());
        assert_eq!(0xaf9b000000ffff, reader.read_u64::<LittleEndian>().unwrap());
        assert_eq!(0xcf93000000ffff, reader.read_u64::<LittleEndian>().unwrap());
        assert_eq!(0x8f8b000000ffff, reader.read_u64::<LittleEndian>().unwrap());
        let mut reader = Cursor::new(&mem_vec.as_slice()[BOOT_IDT_OFFSET..]);
        assert_eq!(0, reader.read_u64::<LittleEndian>().unwrap());
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
        let mut mem_vec: Vec<u8> = Vec::with_capacity(0x10000);
        unsafe {
            mem_vec.set_len(0x10000);
        }
        setup_page_tables(mem_vec.as_mut_slice(), &mut sregs);
        let mut reader = Cursor::new(&mem_vec.as_slice()[0x9000..]);
        assert_eq!(0xa003, reader.read_u64::<LittleEndian>().unwrap());
        let mut reader = Cursor::new(&mem_vec.as_slice()[0xa000..]);
        assert_eq!(0x83, reader.read_u64::<LittleEndian>().unwrap());
        assert_eq!(0x9000, sregs.cr3);
        assert_eq!(X86_CR4_PAE, sregs.cr4);
        assert_eq!(X86_CR0_PG, sregs.cr0);
    }
}

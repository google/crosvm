// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern crate byteorder;
extern crate kvm;
extern crate kvm_sys;
extern crate libc;
extern crate sys_util;

#[allow(dead_code)]
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
mod bootparam;

#[allow(dead_code)]
#[allow(non_upper_case_globals)]
mod msr_index;

mod cpuid;
mod gdt;
mod interrupts;
mod regs;

use std::io::Write;
use std::mem;
use std::result;

use bootparam::boot_params;
use bootparam::E820_RAM;

#[derive(Debug)]
pub enum Error {
    /// Error configuring the VCPU.
    CpuSetup(cpuid::Error),
    /// Error configuring the VCPU registers.
    RegisterConfiguration(regs::Error),
    /// Error configuring the VCPU floating point registers.
    FpuRegisterConfiguration(regs::Error),
    /// Error configuring the VCPU segment registers.
    SegmentRegisterConfiguration(regs::Error),
    /// Error configuring the VCPU local interrupt.
    LocalIntConfiguration(interrupts::Error),
    /// Error writing the zero page of guest memory.
    ZeroPageSetup,
    /// The zero page extends past the end of guest_mem.
    ZeroPagePastRamEnd,
    /// Invalid e820 setup params.
    E820Configuration,
}
pub type Result<T> = result::Result<T, Error>;

const ZERO_PAGE_OFFSET: usize = 0x7000;
const BOOT_STACK_POINTER: usize = 0x8000;
const KERNEL_64BIT_ENTRY_OFFSET: usize = 0x200;

/// Configures the vcpu and should be called once per vcpu from the vcpu's thread.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `kernel_load_offset` - Offset from `guest_mem` at which the kernel starts.
/// * `kvm` - The /dev/kvm object that created vcpu.
/// * `vcpu` - The VCPU object to configure.
/// * `num_cpus` - The number of vcpus that will be given to the guest.
pub fn configure_vcpu(guest_mem: &mut [u8],
                      kernel_load_offset: usize,
                      kvm: &kvm::Kvm,
                      vcpu: &kvm::Vcpu,
                      num_cpus: usize)
                      -> Result<()> {
    cpuid::setup_cpuid(&kvm, &vcpu, 0, num_cpus as u64).map_err(|e| Error::CpuSetup(e))?;
    regs::setup_msrs(&vcpu).map_err(|e| Error::RegisterConfiguration(e))?;
    regs::setup_regs(&vcpu, (kernel_load_offset + KERNEL_64BIT_ENTRY_OFFSET) as u64, BOOT_STACK_POINTER as u64, ZERO_PAGE_OFFSET as u64).map_err(|e| Error::RegisterConfiguration(e))?;
    regs::setup_fpu(&vcpu).map_err(|e| Error::FpuRegisterConfiguration(e))?;
    regs::setup_sregs(guest_mem, &vcpu).map_err(|e| Error::SegmentRegisterConfiguration(e))?;
    interrupts::set_lint(&vcpu).map_err(|e| Error::LocalIntConfiguration(e))?;
    Ok(())
}

/// Configures the system and should be called once per vm before starting vcpu threads.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `kernel_offset` - Offset into `guest_mem` where the kernel was loaded.
/// * `cmdline_offset` - Offset into `guest_mem` where the kernel command line was loaded.
/// * `cmdline_size` - Size of the kernel command line in bytes including the null terminator.
pub fn configure_system(guest_mem: &mut [u8],
                        kernel_offset: usize,
                        cmdline_offset: usize,
                        cmdline_size: usize)
                        -> Result<()> {
    const EBDA_START: u64 = 0x0009fc00;
    const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
    const KERNEL_HDR_MAGIC: u32 = 0x53726448;
    const KERNEL_LOADER_OTHER: u8 = 0xff;
    const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x1000000; // Must be non-zero.
    const KVM_32BIT_MAX_MEM_SIZE: u64 = (1 << 32);
    const KVM_32BIT_GAP_SIZE: u64 = (768 << 20);
    const KVM_32BIT_GAP_START: u64 = (KVM_32BIT_MAX_MEM_SIZE - KVM_32BIT_GAP_SIZE);

    let mut params: boot_params = Default::default();

    params.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    params.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    params.hdr.header = KERNEL_HDR_MAGIC;
    params.hdr.cmd_line_ptr = cmdline_offset as u32;
    params.hdr.cmdline_size = cmdline_size as u32;
    params.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;

    add_e820_entry(&mut params, 0, EBDA_START, E820_RAM)?;

    let mem_size = guest_mem.len() as u64;
    if mem_size < KVM_32BIT_GAP_START {
        add_e820_entry(&mut params,
                       kernel_offset as u64,
                       mem_size - kernel_offset as u64,
                       E820_RAM)?;
    } else {
        add_e820_entry(&mut params,
                       kernel_offset as u64,
                       KVM_32BIT_GAP_START - kernel_offset as u64,
                       E820_RAM)?;
        if mem_size > KVM_32BIT_MAX_MEM_SIZE {
            add_e820_entry(&mut params,
                           KVM_32BIT_MAX_MEM_SIZE,
                           mem_size - KVM_32BIT_MAX_MEM_SIZE,
                           E820_RAM)?;
        }
    }

    let zero_page_end = ZERO_PAGE_OFFSET + mem::size_of::<boot_params>();
    if zero_page_end as usize > guest_mem.len() {
        return Err(Error::ZeroPagePastRamEnd);
    }
    let mut zero_page_slice = &mut guest_mem[ZERO_PAGE_OFFSET..zero_page_end as usize];
    unsafe {
        // Dereferencing the pointer to params is safe here because it is valid, it can't be
        // destroyed after it is created at the top of this function,  and we drop it as soon as the
        // data is written.
        let ptr = &params as *const boot_params as *const u8;
        let bp_slice: &[u8] = std::slice::from_raw_parts(ptr, mem::size_of::<boot_params>());
        zero_page_slice.write_all(bp_slice)
            .map_err(|_| Error::ZeroPageSetup)?;
    }


    Ok(())
}

/// Add an e820 region to the e820 map.
/// Returns Ok(()) if successful, or an error if there is no space left in the map.
fn add_e820_entry(params: &mut boot_params, addr: u64, size: u64, mem_type: u32) -> Result<()> {
    if params.e820_entries >= params.e820_map.len() as u8 {
        return Err(Error::E820Configuration);
    }

    params.e820_map[params.e820_entries as usize].addr = addr;
    params.e820_map[params.e820_entries as usize].size = size;
    params.e820_map[params.e820_entries as usize].type_ = mem_type;
    params.e820_entries += 1;

    Ok(())
}

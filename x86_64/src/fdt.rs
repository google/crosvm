// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use arch::android::create_android_fdt;
use arch::fdt::{begin_node, end_node, finish_fdt, start_fdt, Error};
use data_model::DataInit;
use std::fs::File;
use std::mem;
use sys_util::{GuestAddress, GuestMemory};

use crate::bootparam::setup_data;
use crate::{SETUP_DTB, X86_64_FDT_MAX_SIZE};

// Like `setup_data` without the incomplete array field at the end, which allows us to safely
// implement Copy, Clone, and DataInit.
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct setup_data_hdr {
    pub next: u64,
    pub type_: u32,
    pub len: u32,
}

unsafe impl DataInit for setup_data_hdr {}

/// Creates a flattened device tree containing all of the parameters for the
/// kernel and loads it into the guest memory at the specified offset.
///
/// # Arguments
///
/// * `fdt_max_size` - The amount of space reserved for the device tree
/// * `guest_mem` - The guest memory object
/// * `fdt_load_offset` - The offset into physical memory for the device tree
/// * `android_fstab` - the File object for the android fstab
pub fn create_fdt(
    fdt_max_size: usize,
    guest_mem: &GuestMemory,
    fdt_load_offset: u64,
    android_fstab: File,
) -> Result<usize, Error> {
    // Reserve space for the setup_data
    let fdt_data_size = fdt_max_size - mem::size_of::<setup_data>();

    let mut fdt = vec![0; fdt_data_size];
    start_fdt(&mut fdt, fdt_data_size)?;

    // The whole thing is put into one giant node with some top level properties
    begin_node(&mut fdt, "")?;
    create_android_fdt(&mut fdt, android_fstab)?;
    end_node(&mut fdt)?;

    // Allocate another buffer so we can format and then write fdt to guest
    let mut fdt_final = vec![0; fdt_data_size];
    finish_fdt(&mut fdt, &mut fdt_final, fdt_data_size)?;

    assert_eq!(
        mem::size_of::<setup_data>(),
        mem::size_of::<setup_data_hdr>()
    );
    let mut hdr: setup_data_hdr = Default::default();
    hdr.next = 0;
    hdr.type_ = SETUP_DTB;
    hdr.len = fdt_data_size as u32;

    assert!(fdt_data_size as u64 <= X86_64_FDT_MAX_SIZE);

    let fdt_address = GuestAddress(fdt_load_offset);
    guest_mem
        .checked_offset(fdt_address, fdt_data_size as u64)
        .ok_or(Error::FdtGuestMemoryWriteError)?;
    guest_mem
        .write_obj_at_addr(hdr, fdt_address)
        .map_err(|_| Error::FdtGuestMemoryWriteError)?;

    let fdt_data_address = GuestAddress(fdt_load_offset + mem::size_of::<setup_data>() as u64);
    let written = guest_mem
        .write_at_addr(fdt_final.as_slice(), fdt_data_address)
        .map_err(|_| Error::FdtGuestMemoryWriteError)?;
    if written < fdt_data_size {
        return Err(Error::FdtGuestMemoryWriteError);
    }
    Ok(fdt_data_size)
}

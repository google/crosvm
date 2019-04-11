// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use arch::fdt::{begin_node, end_node, finish_fdt, property_string, start_fdt, Error};
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::mem;
use sys_util::{GuestAddress, GuestMemory};

use crate::bootparam::setup_data;
use crate::bootparam::SETUP_DTB;
use crate::X86_64_FDT_MAX_SIZE;

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
    android_fstab: &mut File,
) -> Result<usize, Error> {
    // Reserve space for the setup_data
    let fdt_data_size = fdt_max_size - mem::size_of::<setup_data>();

    let mut fdt = vec![0; fdt_data_size];
    start_fdt(&mut fdt, fdt_data_size)?;

    // The whole thing is put into one giant node with some top level properties
    begin_node(&mut fdt, "")?;
    begin_node(&mut fdt, "firmware")?;
    begin_node(&mut fdt, "android")?;
    property_string(&mut fdt, "compatible", "android,firmware")?;
    begin_node(&mut fdt, "fstab")?;
    property_string(&mut fdt, "compatible", "android,fstab")?;
    let file = BufReader::new(android_fstab);
    for line in file.lines().filter_map(|l| l.ok()) {
        let vec = line.split(" ").collect::<Vec<&str>>();
        assert_eq!(vec.len(), 5);
        let partition = &vec[1][1..];
        begin_node(&mut fdt, partition)?;
        property_string(&mut fdt, "compatible", &("android,".to_owned() + partition))?;
        property_string(&mut fdt, "dev", vec[0])?;
        property_string(&mut fdt, "type", vec[2])?;
        property_string(&mut fdt, "mnt_flags", vec[3])?;
        property_string(&mut fdt, "fsmgr_flags", vec[4])?;
        end_node(&mut fdt)?;
    }
    end_node(&mut fdt)?;
    end_node(&mut fdt)?;
    end_node(&mut fdt)?;
    end_node(&mut fdt)?;

    // Allocate another buffer so we can format and then write fdt to guest
    let mut fdt_final = vec![0; fdt_data_size];
    finish_fdt(&mut fdt, &mut fdt_final, fdt_data_size)?;

    let mut hdr: setup_data = Default::default();
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

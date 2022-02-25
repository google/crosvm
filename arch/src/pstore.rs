// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::OpenOptions;
use std::io;

use crate::Pstore;
use base::MemoryMappingBuilder;
use hypervisor::Vm;
use remain::sorted;
use resources::SystemAllocator;
use resources::{Alloc, MmioType};
use thiserror::Error;
use vm_memory::GuestAddress;

/// Error for pstore.
#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to create pstore backend file: {0}")]
    IoError(io::Error),
    #[error("failed to get file mapped address: {0}")]
    MmapError(base::MmapError),
    #[error("failed to allocate pstore region: {0}")]
    ResourcesError(resources::Error),
    #[error("file to add pstore region to mmio: {0}")]
    SysUtilError(base::Error),
}

type Result<T> = std::result::Result<T, Error>;

pub struct RamoopsRegion {
    pub address: u64,
    pub size: u32,
}

/// Creates a mmio memory region for pstore.
pub fn create_memory_region(
    vm: &mut impl Vm,
    resources: &mut SystemAllocator,
    pstore: &Pstore,
) -> Result<RamoopsRegion> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&pstore.path)
        .map_err(Error::IoError)?;
    file.set_len(pstore.size as u64).map_err(Error::IoError)?;

    let address = resources
        .mmio_allocator(MmioType::High)
        .allocate(pstore.size as u64, Alloc::Pstore, "pstore".to_owned())
        .map_err(Error::ResourcesError)?;

    let memory_mapping = MemoryMappingBuilder::new(pstore.size as usize)
        .from_file(&file)
        .build()
        .map_err(Error::MmapError)?;

    vm.add_memory_region(
        GuestAddress(address),
        Box::new(memory_mapping),
        false,
        false,
    )
    .map_err(Error::SysUtilError)?;

    Ok(RamoopsRegion {
        address,
        size: pstore.size,
    })
}

pub fn add_ramoops_kernel_cmdline(
    cmdline: &mut kernel_cmdline::Cmdline,
    ramoops_region: &RamoopsRegion,
) -> std::result::Result<(), kernel_cmdline::Error> {
    // It seems that default record_size is only 4096 byte even if crosvm allocates
    // more memory. It means that one crash can only 4096 byte.
    // Set record_size and console_size to 1/4 of allocated memory size.
    // This configulation is same as the host.
    let ramoops_opts = [
        ("mem_address", ramoops_region.address),
        ("mem_size", ramoops_region.size as u64),
    ];
    for (name, val) in &ramoops_opts {
        cmdline.insert_str(format!("ramoops.{}={:#x}", name, val))?;
    }
    Ok(())
}

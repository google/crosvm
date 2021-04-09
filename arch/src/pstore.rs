// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt::{self, Display};
use std::fs::OpenOptions;
use std::io;

use crate::Pstore;
use base::MemoryMappingBuilder;
use hypervisor::Vm;
use resources::SystemAllocator;
use resources::{Alloc, MmioType};
use vm_memory::GuestAddress;

/// Error for pstore.
#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    MmapError(base::MmapError),
    ResourcesError(resources::Error),
    SysUtilError(base::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            IoError(e) => write!(f, "failed to create pstore backend file: {}", e),
            MmapError(e) => write!(f, "failed to get file mapped address: {}", e),
            ResourcesError(e) => write!(f, "failed to allocate pstore region: {}", e),
            SysUtilError(e) => write!(f, "file to add pstore region to mmio: {}", e),
        }
    }
}

impl std::error::Error for Error {}
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

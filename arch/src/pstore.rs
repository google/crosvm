// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::OpenOptions;

use crate::Pstore;
use anyhow::{bail, Context, Result};
use base::MemoryMappingBuilder;
use hypervisor::Vm;
use resources::MemRegion;
use vm_memory::GuestAddress;

pub struct RamoopsRegion {
    pub address: u64,
    pub size: u32,
}

/// Creates a mmio memory region for pstore.
pub fn create_memory_region(
    vm: &mut impl Vm,
    region: &MemRegion,
    pstore: &Pstore,
) -> Result<RamoopsRegion> {
    if region.size < pstore.size.into() {
        bail!("insufficient space for pstore {:?} {}", region, pstore.size);
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&pstore.path)
        .context("failed to open pstore")?;
    file.set_len(pstore.size as u64)
        .context("failed to set pstore length")?;

    let memory_mapping = MemoryMappingBuilder::new(pstore.size as usize)
        .from_file(&file)
        .build()
        .context("failed to mmap pstore")?;

    vm.add_memory_region(
        GuestAddress(region.base),
        Box::new(memory_mapping),
        false,
        false,
    )
    .context("failed to add pstore region")?;

    Ok(RamoopsRegion {
        address: region.base,
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

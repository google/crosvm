// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::OpenOptions;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::MemoryMappingBuilder;
use hypervisor::MemCacheType;
use hypervisor::Vm;
use resources::AddressRange;
use vm_memory::GuestAddress;

use crate::Pstore;

mod sys;

pub struct RamoopsRegion {
    pub address: u64,
    pub size: u32,
}

/// Creates a mmio memory region for pstore.
pub fn create_memory_region(
    vm: &mut impl Vm,
    region: AddressRange,
    pstore: &Pstore,
) -> Result<RamoopsRegion> {
    let region_size = region.len().context("failed to get region len")?;
    if region_size < pstore.size.into() {
        bail!("insufficient space for pstore {} {}", region, pstore.size);
    }

    let mut open_opts = OpenOptions::new();
    open_opts.read(true).write(true).create(true);
    sys::set_extra_open_opts(&mut open_opts);

    let file = open_opts
        .open(&pstore.path)
        .context("failed to open pstore")?;
    file.set_len(pstore.size as u64)
        .context("failed to set pstore length")?;

    let memory_mapping = MemoryMappingBuilder::new(pstore.size as usize)
        .from_file(&file)
        .build()
        .context("failed to mmap pstore")?;

    vm.add_memory_region(
        GuestAddress(region.start),
        Box::new(memory_mapping),
        false,
        false,
        MemCacheType::CacheCoherent,
    )
    .context("failed to add pstore region")?;

    Ok(RamoopsRegion {
        address: region.start,
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

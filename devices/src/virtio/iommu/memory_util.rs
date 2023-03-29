// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Utilities to access GuestMemory with IO virtual addresses and iommu

use anyhow::Context;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use crate::virtio::iommu::ExportedRegion;

/// A wrapper that works with gpa, or iova and an iommu.
pub fn read_obj_from_addr_wrapper<T: FromBytes>(
    mem: &GuestMemory,
    exported_region: Option<&ExportedRegion>,
    addr: GuestAddress,
) -> anyhow::Result<T> {
    if let Some(exported_region) = exported_region {
        exported_region.read_obj_from_addr::<T>(mem, addr.offset())
    } else {
        mem.read_obj_from_addr_volatile::<T>(addr)
            .context("read_obj_from_addr failed")
    }
}

/// A wrapper that works with gpa, or iova and an iommu.
pub fn write_obj_at_addr_wrapper<T: FromBytes + AsBytes>(
    mem: &GuestMemory,
    exported_region: Option<&ExportedRegion>,
    val: T,
    addr: GuestAddress,
) -> anyhow::Result<()> {
    if let Some(exported_region) = exported_region {
        exported_region.write_obj_at_addr(mem, val, addr.offset())
    } else {
        mem.write_obj_at_addr_volatile(val, addr)
            .context("write_obj_at_addr failed")
    }
}

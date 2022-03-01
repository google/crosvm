// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Utilities to access GuestMemory with IO virtual addresses and iommu

use std::convert::TryInto;
use std::sync::Arc;
use sync::Mutex;

use anyhow::{bail, Context};
use data_model::DataInit;
use vm_memory::{GuestAddress, GuestMemory};

use crate::virtio::iommu::IpcMemoryMapper;
use crate::virtio::memory_mapper::{Permission, Translate};

/// A wrapper that works with gpa, or iova and an iommu.
pub fn is_valid_wrapper<T: Translate>(
    mem: &GuestMemory,
    iommu: &Option<T>,
    addr: GuestAddress,
    size: u64,
) -> anyhow::Result<bool> {
    if let Some(iommu) = iommu {
        is_valid(mem, iommu, addr.offset(), size)
    } else {
        Ok(addr
            .checked_add(size as u64)
            .map_or(false, |v| mem.address_in_range(v)))
    }
}

/// Translates `iova` into gpa regions (or 1 gpa region when it is contiguous), and check if the
/// gpa regions are all valid in `mem`.
pub fn is_valid<T: Translate>(
    mem: &GuestMemory,
    iommu: &T,
    iova: u64,
    size: u64,
) -> anyhow::Result<bool> {
    match iommu.translate(iova, size) {
        Ok(regions) => {
            for r in regions {
                if !mem.address_in_range(r.gpa) || mem.checked_offset(r.gpa, r.len).is_none() {
                    return Ok(false);
                }
            }
        }
        Err(e) => bail!("failed to translate iova to gpa: {}", e),
    }
    Ok(true)
}

/// A wrapper that works with gpa, or iova and an iommu.
pub fn read_obj_from_addr_wrapper<T: DataInit>(
    mem: &GuestMemory,
    iommu: &Option<Arc<Mutex<IpcMemoryMapper>>>,
    addr: GuestAddress,
) -> anyhow::Result<T> {
    if let Some(iommu) = iommu {
        read_obj_from_addr::<T>(mem, &iommu.lock(), addr.offset())
    } else {
        mem.read_obj_from_addr::<T>(addr)
            .context("read_obj_from_addr failed")
    }
}

/// A version of `GuestMemory::read_obj_from_addr` that works with iova and iommu.
pub fn read_obj_from_addr<T: DataInit>(
    mem: &GuestMemory,
    iommu: &IpcMemoryMapper,
    iova: u64,
) -> anyhow::Result<T> {
    let regions = iommu
        .translate(
            iova,
            std::mem::size_of::<T>()
                .try_into()
                .context("u64 doesn't fit in usize")?,
        )
        .context("failed to translate iova to gpa")?;
    let mut buf = vec![0u8; std::mem::size_of::<T>()];
    let mut addr: usize = 0;
    for r in regions {
        if (r.perm as u8 & Permission::Read as u8) == 0 {
            bail!("gpa is not readable");
        }
        mem.read_at_addr(&mut buf[addr..(addr + r.len as usize)], r.gpa)
            .context("failed to read from gpa")?;
        addr += r.len as usize;
    }
    Ok(*T::from_slice(&buf).context("failed to construct obj")?)
}

/// A wrapper that works with gpa, or iova and an iommu.
pub fn write_obj_at_addr_wrapper<T: DataInit>(
    mem: &GuestMemory,
    iommu: &Option<Arc<Mutex<IpcMemoryMapper>>>,
    val: T,
    addr: GuestAddress,
) -> anyhow::Result<()> {
    if let Some(iommu) = iommu {
        write_obj_at_addr(mem, &iommu.lock(), val, addr.offset())
    } else {
        mem.write_obj_at_addr(val, addr)
            .context("write_obj_at_addr failed")
    }
}

/// A version of `GuestMemory::write_obj_at_addr` that works with iova and iommu.
pub fn write_obj_at_addr<T: DataInit>(
    mem: &GuestMemory,
    iommu: &IpcMemoryMapper,
    val: T,
    iova: u64,
) -> anyhow::Result<()> {
    let regions = iommu
        .translate(
            iova,
            std::mem::size_of::<T>()
                .try_into()
                .context("u64 doesn't fit in usize")?,
        )
        .context("failed to translate iova to gpa")?;
    let buf = val.as_slice();
    let mut addr: usize = 0;
    for r in regions {
        if (r.perm as u8 & Permission::Read as u8) == 0 {
            bail!("gpa is not writable");
        }
        mem.write_at_addr(&buf[addr..(addr + (r.len as usize))], r.gpa)
            .context("failed to write to gpa")?;
        addr += r.len as usize;
    }
    Ok(())
}

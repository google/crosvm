// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Manages system resources that can be allocated to VMs and their devices.

use std::fmt::Display;

use serde::{Deserialize, Serialize};

pub use crate::address_allocator::AddressAllocator;
pub use crate::system_allocator::{MmioType, SystemAllocator};

mod address_allocator;
mod system_allocator;

/// Used to tag SystemAllocator allocations.
#[derive(Debug, Eq, PartialEq, Hash, Copy, Clone, Serialize, Deserialize)]
pub enum Alloc {
    /// An anonymous resource allocation.
    /// Should only be instantiated through `SystemAllocator::get_anon_alloc()`.
    /// Avoid using these. Instead, use / create a more descriptive Alloc variant.
    Anon(usize),
    /// A PCI BAR region with associated bus, device, function and bar numbers.
    PciBar { bus: u8, dev: u8, func: u8, bar: u8 },
    /// GPU render node region.
    GpuRenderNode,
    /// Pmem device region with associated device index.
    PmemDevice(usize),
    /// pstore region.
    Pstore,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    AllocSizeZero,
    BadAlignment,
    ExistingAlloc(Alloc),
    InvalidAlloc(Alloc),
    MissingHighMMIOAddresses,
    MissingLowMMIOAddresses,
    NoIoAllocator,
    OutOfSpace,
    OutOfBounds,
    PoolOverflow { base: u64, size: u64 },
    PoolSizeZero,
    RegionOverlap { base: u64, size: u64 },
    BadAlloc(Alloc),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use self::Error::*;
        match self {
            AllocSizeZero => write!(f, "Allocation cannot have size of 0"),
            BadAlignment => write!(f, "Pool alignment must be a power of 2"),
            ExistingAlloc(tag) => write!(f, "Alloc already exists: {:?}", tag),
            InvalidAlloc(tag) => write!(f, "Invalid Alloc: {:?}", tag),
            MissingHighMMIOAddresses => write!(f, "High MMIO address range not specified"),
            MissingLowMMIOAddresses => write!(f, "Low MMIO address range not specified"),
            NoIoAllocator => write!(f, "No IO address range specified"),
            OutOfSpace => write!(f, "Out of space"),
            OutOfBounds => write!(f, "Out of bounds"),
            PoolOverflow { base, size } => write!(f, "base={} + size={} overflows", base, size),
            PoolSizeZero => write!(f, "Pool cannot have size of 0"),
            RegionOverlap { base, size } => {
                write!(f, "Overlapping region base={} size={}", base, size)
            }
            BadAlloc(tag) => write!(f, "Alloc does not exists: {:?}", tag),
        }
    }
}

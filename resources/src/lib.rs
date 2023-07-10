// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Manages system resources that can be allocated to VMs and their devices.

use remain::sorted;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

pub use crate::address_range::AddressRange;
pub use crate::system_allocator::AllocOptions;
pub use crate::system_allocator::MmioType;
pub use crate::system_allocator::SystemAllocator;
pub use crate::system_allocator::SystemAllocatorConfig;

pub mod address_allocator;
mod address_range;
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
    /// A PCI bridge window with associated bus, dev, function.
    PciBridgeWindow { bus: u8, dev: u8, func: u8 },
    /// A PCI bridge prefetch window with associated bus, dev, function.
    PciBridgePrefetchWindow { bus: u8, dev: u8, func: u8 },
    /// File-backed memory mapping.
    FileBacked(u64),
}

#[sorted]
#[derive(Error, Debug, Eq, PartialEq)]
pub enum Error {
    #[error("Allocation cannot have size of 0")]
    AllocSizeZero,
    #[error("Pool alignment must be a power of 2")]
    BadAlignment,
    #[error("Alloc does not exist: {0:?}")]
    BadAlloc(Alloc),
    #[error("Alloc already exists: {0:?}")]
    ExistingAlloc(Alloc),
    #[error("Invalid Alloc: {0:?}")]
    InvalidAlloc(Alloc),
    #[error("IO port out of range: {0}")]
    IOPortOutOfRange(AddressRange),
    #[error("Platform MMIO address range not specified")]
    MissingPlatformMMIOAddresses,
    #[error("No IO address range specified")]
    NoIoAllocator,
    #[error("Out of bounds")]
    OutOfBounds,
    #[error("Out of space")]
    OutOfSpace,
    #[error("base={base} + size={size} overflows")]
    PoolOverflow { base: u64, size: u64 },
    #[error("Overlapping region {0}")]
    RegionOverlap(AddressRange),
}

pub type Result<T> = std::result::Result<T, Error>;

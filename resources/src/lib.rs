// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Manages system resources that can be allocated to VMs and their devices.

#[cfg(feature = "wl-dmabuf")]
extern crate gpu_buffer;
extern crate libc;
extern crate msg_socket;
extern crate sys_util;

use std::fmt::Display;

pub use crate::address_allocator::AddressAllocator;
pub use crate::gpu_allocator::{
    GpuAllocatorError, GpuMemoryAllocator, GpuMemoryDesc, GpuMemoryPlaneDesc,
};
pub use crate::system_allocator::SystemAllocator;

mod address_allocator;
mod gpu_allocator;
mod system_allocator;

/// Used to tag SystemAllocator allocations.
#[derive(Debug, Eq, PartialEq, Hash)]
pub enum Alloc {
    /// An anonymous resource allocation.
    /// Should only be instantiated through `SystemAllocator::get_anon_alloc()`.
    /// Avoid using these. Instead, use / create a more descriptive Alloc variant.
    Anon(usize),
    /// A PCI BAR region with associated bus, device, and bar numbers.
    PciBar { bus: u8, dev: u8, bar: u8 },
    /// GPU render node region.
    GpuRenderNode,
    /// Pmem device region with associated device index.
    PmemDevice(usize),
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    AllocSizeZero,
    BadAlignment,
    CreateGpuAllocator(GpuAllocatorError),
    ExistingAlloc(Alloc),
    MissingDeviceAddresses,
    MissingMMIOAddresses,
    NoIoAllocator,
    OutOfSpace,
    PoolOverflow { base: u64, size: u64 },
    PoolSizeZero,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use self::Error::*;
        match self {
            AllocSizeZero => write!(f, "Allocation cannot have size of 0"),
            BadAlignment => write!(f, "Pool alignment must be a power of 2"),
            CreateGpuAllocator(e) => write!(f, "Failed to create GPU allocator: {:?}", e),
            ExistingAlloc(tag) => write!(f, "Alloc already exists: {:?}", tag),
            MissingDeviceAddresses => write!(f, "Device address range not specified"),
            MissingMMIOAddresses => write!(f, "MMIO address range not specified"),
            NoIoAllocator => write!(f, "No IO address range specified"),
            OutOfSpace => write!(f, "Out of space"),
            PoolOverflow { base, size } => write!(f, "base={} + size={} overflows", base, size),
            PoolSizeZero => write!(f, "Pool cannot have size of 0"),
        }
    }
}

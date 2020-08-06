// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::{wrap_descriptor, AsRawDescriptor, MappedRegion, MmapError, Protection};
use data_model::volatile_memory::*;
use data_model::DataInit;
use sys_util::MemoryMapping as SysUtilMmap;

pub type Result<T> = std::result::Result<T, MmapError>;

/// See [MemoryMapping](sys_util::MemoryMapping) for struct- and method-level
/// documentation.
#[derive(Debug)]
pub struct MemoryMapping(SysUtilMmap);
impl MemoryMapping {
    pub fn new(size: usize) -> Result<MemoryMapping> {
        SysUtilMmap::new(size).map(|mmap| MemoryMapping(mmap))
    }

    pub fn from_descriptor(descriptor: &dyn AsRawDescriptor, size: usize) -> Result<MemoryMapping> {
        SysUtilMmap::from_fd(&wrap_descriptor(descriptor), size).map(|mmap| MemoryMapping(mmap))
    }

    pub fn from_descriptor_offset(
        descriptor: &dyn AsRawDescriptor,
        size: usize,
        offset: u64,
    ) -> Result<MemoryMapping> {
        SysUtilMmap::from_fd_offset(&wrap_descriptor(descriptor), size, offset)
            .map(|mmap| MemoryMapping(mmap))
    }

    pub fn new_protection(size: usize, prot: Protection) -> Result<MemoryMapping> {
        SysUtilMmap::new_protection(size, prot).map(|mmap| MemoryMapping(mmap))
    }

    pub fn from_descriptor_offset_protection(
        descriptor: &dyn AsRawDescriptor,
        size: usize,
        offset: u64,
        prot: Protection,
    ) -> Result<MemoryMapping> {
        SysUtilMmap::from_fd_offset_protection(&wrap_descriptor(descriptor), size, offset, prot)
            .map(|mmap| MemoryMapping(mmap))
    }

    pub unsafe fn new_protection_fixed(
        addr: *mut u8,
        size: usize,
        prot: Protection,
    ) -> Result<MemoryMapping> {
        SysUtilMmap::new_protection_fixed(addr, size, prot).map(|mmap| MemoryMapping(mmap))
    }

    pub unsafe fn from_descriptor_offset_protection_fixed(
        addr: *mut u8,
        descriptor: &dyn AsRawDescriptor,
        size: usize,
        offset: u64,
        prot: Protection,
    ) -> Result<MemoryMapping> {
        SysUtilMmap::from_fd_offset_protection_fixed(
            addr,
            &wrap_descriptor(descriptor),
            size,
            offset,
            prot,
        )
        .map(|mmap| MemoryMapping(mmap))
    }

    pub fn from_descriptor_offset_populate(
        descriptor: &dyn AsRawDescriptor,
        size: usize,
        offset: u64,
    ) -> Result<MemoryMapping> {
        SysUtilMmap::from_fd_offset_populate(&wrap_descriptor(descriptor), size, offset)
            .map(|mmap| MemoryMapping(mmap))
    }

    pub fn write_slice(&self, buf: &[u8], offset: usize) -> Result<usize> {
        self.0.write_slice(buf, offset)
    }

    pub fn read_slice(&self, buf: &mut [u8], offset: usize) -> Result<usize> {
        self.0.read_slice(buf, offset)
    }

    pub fn write_obj<T: DataInit>(&self, val: T, offset: usize) -> Result<()> {
        self.0.write_obj(val, offset)
    }

    pub fn read_obj<T: DataInit>(&self, offset: usize) -> Result<T> {
        self.0.read_obj(offset)
    }

    pub fn msync(&self) -> Result<()> {
        self.0.msync()
    }

    pub fn read_to_memory(
        &self,
        mem_offset: usize,
        src: &dyn AsRawDescriptor,
        count: usize,
    ) -> Result<()> {
        self.0
            .read_to_memory(mem_offset, &wrap_descriptor(src), count)
    }

    pub fn write_from_memory(
        &self,
        mem_offset: usize,
        dst: &dyn AsRawDescriptor,
        count: usize,
    ) -> Result<()> {
        self.0
            .write_from_memory(mem_offset, &wrap_descriptor(dst), count)
    }

    pub fn remove_range(&self, mem_offset: usize, count: usize) -> Result<()> {
        self.0.remove_range(mem_offset, count)
    }
}

impl VolatileMemory for MemoryMapping {
    fn get_slice(&self, offset: usize, count: usize) -> VolatileMemoryResult<VolatileSlice> {
        self.0.get_slice(offset, count)
    }
}

// Safe because it exclusively forwards calls to a safe implementation.
unsafe impl MappedRegion for MemoryMapping {
    fn as_ptr(&self) -> *mut u8 {
        self.0.as_ptr()
    }

    fn size(&self) -> usize {
        self.0.size()
    }
}

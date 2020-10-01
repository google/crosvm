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

pub struct MemoryMappingBuilder<'a> {
    descriptor: Option<&'a dyn AsRawDescriptor>,
    size: usize,
    offset: Option<u64>,
    protection: Option<Protection>,
    populate: bool,
}

/// Builds a MemoryMapping object from the specified arguments.
impl<'a> MemoryMappingBuilder<'a> {
    /// Creates a new builder specifying size of the memory region in bytes.
    pub fn new(size: usize) -> MemoryMappingBuilder<'a> {
        MemoryMappingBuilder {
            descriptor: None,
            size,
            offset: None,
            protection: None,
            populate: false,
        }
    }

    /// Build the memory mapping given the specified descriptor to mapped memory
    ///
    /// Default: Create a new memory mapping.
    pub fn from_descriptor(mut self, descriptor: &'a dyn AsRawDescriptor) -> MemoryMappingBuilder {
        self.descriptor = Some(descriptor);
        self
    }

    /// Offset in bytes from the beginning of the mapping to start the mmap.
    ///
    /// Default: No offset
    pub fn offset(mut self, offset: u64) -> MemoryMappingBuilder<'a> {
        self.offset = Some(offset);
        self
    }

    /// Protection (e.g. readable/writable) of the memory region.
    ///
    /// Default: Read/write
    pub fn protection(mut self, protection: Protection) -> MemoryMappingBuilder<'a> {
        self.protection = Some(protection);
        self
    }

    /// Request that the mapped pages are pre-populated
    ///
    /// Default: Do not populate
    pub fn populate(mut self) -> MemoryMappingBuilder<'a> {
        self.populate = true;
        self
    }

    /// Build a MemoryMapping from the provided options.
    pub fn build(self) -> Result<MemoryMapping> {
        match self.descriptor {
            None => {
                if self.populate {
                    // Population not supported for new mmaps
                    return Err(MmapError::InvalidArgument);
                }
                MemoryMappingBuilder::wrap(SysUtilMmap::new_protection(
                    self.size,
                    self.protection.unwrap_or(Protection::read_write()),
                ))
            }
            Some(descriptor) => {
                MemoryMappingBuilder::wrap(SysUtilMmap::from_fd_offset_protection_populate(
                    &wrap_descriptor(descriptor),
                    self.size,
                    self.offset.unwrap_or(0),
                    self.protection.unwrap_or(Protection::read_write()),
                    self.populate,
                ))
            }
        }
    }

    /// Build a MemoryMapping from the provided options at a fixed address. Note this
    /// is a separate function from build in order to isolate unsafe behavior.
    ///
    /// # Safety
    ///
    /// Function should not be called before the caller unmaps any mmap'd regions already
    /// present at `(addr..addr+size)`. If another MemoryMapping object holds the same
    /// address space, the destructors of those objects will conflict and the space could
    /// be unmapped while still in use.
    pub unsafe fn build_fixed(self, addr: *mut u8) -> Result<MemoryMapping> {
        if self.populate {
            // Population not supported for fixed mapping.
            return Err(MmapError::InvalidArgument);
        }
        match self.descriptor {
            None => MemoryMappingBuilder::wrap(SysUtilMmap::new_protection_fixed(
                addr,
                self.size,
                self.protection.unwrap_or(Protection::read_write()),
            )),
            Some(descriptor) => {
                MemoryMappingBuilder::wrap(SysUtilMmap::from_fd_offset_protection_fixed(
                    addr,
                    &wrap_descriptor(descriptor),
                    self.size,
                    self.offset.unwrap_or(0),
                    self.protection.unwrap_or(Protection::read_write()),
                ))
            }
        }
    }

    fn wrap(result: Result<SysUtilMmap>) -> Result<MemoryMapping> {
        result.map(|mmap| MemoryMapping(mmap))
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

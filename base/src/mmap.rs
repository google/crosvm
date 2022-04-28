// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::{
    descriptor::{AsRawDescriptor, SafeDescriptor},
    platform::{MappedRegion, MemoryMapping as SysUtilMmap, MmapError},
    Protection, SharedMemory,
};

use data_model::{volatile_memory::*, DataInit};
use std::fs::File;

pub type Result<T> = std::result::Result<T, MmapError>;

/// See [MemoryMapping](crate::platform::MemoryMapping) for struct- and method-level
/// documentation.
#[derive(Debug)]
pub struct MemoryMapping {
    pub(crate) mapping: SysUtilMmap,

    // File backed mappings on Windows need to keep the underlying file open while the mapping is
    // open.
    // This will be a None in non-windows case. The variable will not be read so the '^_'.
    //
    // TODO(b:230902713) There was a concern about relying on the kernel's refcounting to keep the
    // file object's locks (e.g. exclusive read/write) in place. We need to revisit/validate that
    // concern.
    pub(crate) _file_descriptor: Option<SafeDescriptor>,
}

impl MemoryMapping {
    pub fn write_slice(&self, buf: &[u8], offset: usize) -> Result<usize> {
        self.mapping.write_slice(buf, offset)
    }

    pub fn read_slice(&self, buf: &mut [u8], offset: usize) -> Result<usize> {
        self.mapping.read_slice(buf, offset)
    }

    pub fn write_obj<T: DataInit>(&self, val: T, offset: usize) -> Result<()> {
        self.mapping.write_obj(val, offset)
    }

    pub fn read_obj<T: DataInit>(&self, offset: usize) -> Result<T> {
        self.mapping.read_obj(offset)
    }

    pub fn msync(&self) -> Result<()> {
        self.mapping.msync()
    }
}

pub struct MemoryMappingBuilder<'a> {
    pub(crate) descriptor: Option<&'a dyn AsRawDescriptor>,
    pub(crate) is_file_descriptor: bool,
    pub(crate) size: usize,
    pub(crate) offset: Option<u64>,
    pub(crate) protection: Option<Protection>,
    pub(crate) populate: bool,
}

/// Builds a MemoryMapping object from the specified arguments.
impl<'a> MemoryMappingBuilder<'a> {
    /// Creates a new builder specifying size of the memory region in bytes.
    pub fn new(size: usize) -> MemoryMappingBuilder<'a> {
        MemoryMappingBuilder {
            descriptor: None,
            size,
            is_file_descriptor: false,
            offset: None,
            protection: None,
            populate: false,
        }
    }

    /// Build the memory mapping given the specified File to mapped memory
    ///
    /// Default: Create a new memory mapping.
    ///
    /// Note: this is a forward looking interface to accomodate platforms that
    /// require special handling for file backed mappings.
    #[allow(clippy::wrong_self_convention, unused_mut)]
    pub fn from_file(mut self, file: &'a File) -> MemoryMappingBuilder {
        // On Windows, files require special handling (next day shipping if possible).
        self.is_file_descriptor = true;

        self.descriptor = Some(file as &dyn AsRawDescriptor);
        self
    }

    /// Build the memory mapping given the specified SharedMemory to mapped memory
    ///
    /// Default: Create a new memory mapping.
    pub fn from_shared_memory(mut self, shm: &'a SharedMemory) -> MemoryMappingBuilder {
        self.descriptor = Some(shm as &dyn AsRawDescriptor);
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

    /// Build a MemoryMapping from the provided options at a fixed address. Note this
    /// is a separate function from build in order to isolate unsafe behavior.
    ///
    /// # Safety
    ///
    /// Function should not be called before the caller unmaps any mmap'd regions already
    /// present at `(addr..addr+size)`. If another MemoryMapping object holds the same
    /// address space, the destructors of those objects will conflict and the space could
    /// be unmapped while still in use.
    ///
    /// WARNING: On windows, this is not compatible with from_file.
    /// TODO(b:230901659): Find a better way to enforce this warning in code.
    pub unsafe fn build_fixed(self, addr: *mut u8) -> Result<MemoryMapping> {
        if self.populate {
            // Population not supported for fixed mapping.
            return Err(MmapError::InvalidArgument);
        }
        match self.descriptor {
            None => MemoryMappingBuilder::wrap(
                SysUtilMmap::new_protection_fixed(
                    addr,
                    self.size,
                    self.protection.unwrap_or_else(Protection::read_write),
                ),
                None,
            ),
            Some(descriptor) => MemoryMappingBuilder::wrap(
                SysUtilMmap::from_descriptor_offset_protection_fixed(
                    addr,
                    descriptor,
                    self.size,
                    self.offset.unwrap_or(0),
                    self.protection.unwrap_or_else(Protection::read_write),
                ),
                None,
            ),
        }
    }
}

impl VolatileMemory for MemoryMapping {
    fn get_slice(&self, offset: usize, count: usize) -> VolatileMemoryResult<VolatileSlice> {
        self.mapping.get_slice(offset, count)
    }
}

// Safe because it exclusively forwards calls to a safe implementation.
unsafe impl MappedRegion for MemoryMapping {
    fn as_ptr(&self) -> *mut u8 {
        self.mapping.as_ptr()
    }

    fn size(&self) -> usize {
        self.mapping.size()
    }
}

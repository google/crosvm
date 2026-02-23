// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Memory mapping support for macOS.

use std::ptr::null_mut;

use libc::c_int;

use crate::errno::Error as ErrnoError;
use crate::AsRawDescriptor;
use crate::MappedRegion;
use crate::MemoryMapping as CrateMemoryMapping;
use crate::MemoryMappingBuilder;
use crate::MmapError as Error;
use crate::MmapResult as Result;
use crate::Protection;
use crate::RawDescriptor;
use crate::SafeDescriptor;

#[derive(Debug)]
pub struct MemoryMapping {
    addr: *mut u8,
    size: usize,
}

unsafe impl Send for MemoryMapping {}
unsafe impl Sync for MemoryMapping {}

impl MemoryMapping {
    pub fn new(size: usize) -> Result<MemoryMapping> {
        MemoryMapping::new_protection(size, None, Protection::read_write())
    }

    pub fn new_protection(
        size: usize,
        align: Option<u64>,
        prot: Protection,
    ) -> Result<MemoryMapping> {
        unsafe { MemoryMapping::try_mmap(None, size, align, prot.into(), None) }
    }

    pub fn from_fd(fd: &dyn AsRawDescriptor, size: usize) -> Result<MemoryMapping> {
        MemoryMapping::from_fd_offset(fd, size, 0)
    }

    pub fn from_fd_offset(
        fd: &dyn AsRawDescriptor,
        size: usize,
        offset: u64,
    ) -> Result<MemoryMapping> {
        MemoryMapping::from_fd_offset_protection(fd, size, offset, Protection::read_write())
    }

    pub fn from_fd_offset_protection(
        fd: &dyn AsRawDescriptor,
        size: usize,
        offset: u64,
        prot: Protection,
    ) -> Result<MemoryMapping> {
        MemoryMapping::from_fd_offset_protection_populate(fd, size, offset, 0, prot, false)
    }

    pub fn from_fd_offset_protection_populate(
        fd: &dyn AsRawDescriptor,
        size: usize,
        offset: u64,
        align: u64,
        prot: Protection,
        _populate: bool, // Ignored on macOS
    ) -> Result<MemoryMapping> {
        unsafe {
            MemoryMapping::try_mmap(
                None,
                size,
                if align > 0 { Some(align) } else { None },
                prot.into(),
                Some((fd.as_raw_descriptor(), offset)),
            )
        }
    }

    unsafe fn try_mmap(
        addr: Option<*mut u8>,
        size: usize,
        align: Option<u64>,
        prot: c_int,
        fd: Option<(RawDescriptor, u64)>,
    ) -> Result<MemoryMapping> {
        let (raw_fd, offset) = fd.unwrap_or((-1, 0));
        let has_fd = fd.is_some();

        if let Some(alignment) = align.filter(|&a| a > 0) {
            let alignment = alignment as usize;

            // Step 1: Reserve address space with anonymous mapping (size + alignment)
            let reserve = libc::mmap(
                addr.map_or(null_mut(), |a| a as *mut libc::c_void),
                size + alignment,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if reserve == libc::MAP_FAILED {
                return Err(Error::SystemCallFailed(ErrnoError::last()));
            }

            // Step 2: Compute aligned address within reserved region
            let aligned = (reserve as usize + alignment - 1) & !(alignment - 1);

            // Step 3: Map actual content at aligned address with MAP_FIXED
            let mut flags = libc::MAP_SHARED | libc::MAP_FIXED;
            if !has_fd {
                flags |= libc::MAP_ANONYMOUS;
            }
            let mapped = libc::mmap(
                aligned as *mut libc::c_void,
                size,
                prot,
                flags,
                raw_fd,
                offset as libc::off_t,
            );
            if mapped == libc::MAP_FAILED {
                libc::munmap(reserve, size + alignment);
                return Err(Error::SystemCallFailed(ErrnoError::last()));
            }

            // Step 4: Unmap unused prefix/suffix of the reserved region
            let prefix_size = aligned - reserve as usize;
            if prefix_size > 0 {
                libc::munmap(reserve, prefix_size);
            }
            let suffix_size = alignment - prefix_size;
            if suffix_size > 0 {
                libc::munmap((aligned + size) as *mut libc::c_void, suffix_size);
            }

            Ok(MemoryMapping {
                addr: aligned as *mut u8,
                size,
            })
        } else {
            // No alignment required - simple mmap
            let mut flags = libc::MAP_SHARED;
            if !has_fd {
                flags |= libc::MAP_ANONYMOUS;
            }

            let mapped = libc::mmap(
                addr.map_or(null_mut(), |a| a as *mut libc::c_void),
                size,
                prot,
                flags,
                raw_fd,
                offset as libc::off_t,
            );
            if mapped == libc::MAP_FAILED {
                return Err(Error::SystemCallFailed(ErrnoError::last()));
            }

            Ok(MemoryMapping {
                addr: mapped as *mut u8,
                size,
            })
        }
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn as_ptr(&self) -> *mut u8 {
        self.addr
    }

    pub(crate) fn range_end(&self, offset: usize, count: usize) -> Result<usize> {
        let mem_end = offset.checked_add(count).ok_or(Error::InvalidAddress)?;
        if mem_end > self.size {
            return Err(Error::InvalidAddress);
        }
        Ok(mem_end)
    }

    pub fn msync(&self) -> Result<()> {
        let ret = unsafe {
            libc::msync(self.addr as *mut libc::c_void, self.size, libc::MS_SYNC)
        };
        if ret != -1 {
            Ok(())
        } else {
            Err(Error::SystemCallFailed(ErrnoError::last()))
        }
    }

    pub fn new_protection_fixed(
        addr: *mut u8,
        size: usize,
        prot: Protection,
    ) -> Result<MemoryMapping> {
        unsafe { MemoryMapping::try_mmap(Some(addr), size, None, prot.into(), None) }
    }

    /// # Safety
    ///
    /// addr must be a valid pointer to memory of at least size bytes.
    pub unsafe fn from_descriptor_offset_protection_fixed(
        addr: *mut u8,
        fd: &dyn AsRawDescriptor,
        size: usize,
        offset: u64,
        prot: Protection,
    ) -> Result<MemoryMapping> {
        MemoryMapping::try_mmap(Some(addr), size, None, prot.into(), Some((fd.as_raw_descriptor(), offset)))
    }
}

impl Drop for MemoryMapping {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.addr as *mut libc::c_void, self.size);
        }
    }
}

unsafe impl MappedRegion for MemoryMapping {
    fn as_ptr(&self) -> *mut u8 {
        self.addr
    }

    fn size(&self) -> usize {
        self.size
    }
}

pub trait MemoryMappingBuilderUnix<'a> {
    fn from_file(self, file: &'a std::fs::File) -> MemoryMappingBuilder<'a>;
    #[allow(clippy::wrong_self_convention)]
    fn from_descriptor(self, descriptor: &'a dyn AsRawDescriptor) -> MemoryMappingBuilder<'a>;
}

impl<'a> MemoryMappingBuilderUnix<'a> for MemoryMappingBuilder<'a> {
    fn from_file(mut self, file: &'a std::fs::File) -> MemoryMappingBuilder<'a> {
        self.descriptor = Some(file as &dyn AsRawDescriptor);
        self
    }

    #[allow(clippy::wrong_self_convention)]
    fn from_descriptor(mut self, descriptor: &'a dyn AsRawDescriptor) -> MemoryMappingBuilder<'a> {
        self.descriptor = Some(descriptor);
        self
    }
}

impl<'a> MemoryMappingBuilder<'a> {
    pub fn build(self) -> Result<CrateMemoryMapping> {
        match self.descriptor {
            None => MemoryMappingBuilder::wrap(
                MemoryMapping::new_protection(
                    self.size,
                    self.align,
                    self.protection.unwrap_or_else(Protection::read_write),
                )?,
                None,
            ),
            Some(descriptor) => MemoryMappingBuilder::wrap(
                MemoryMapping::from_fd_offset_protection_populate(
                    descriptor,
                    self.size,
                    self.offset.unwrap_or(0),
                    self.align.unwrap_or(0),
                    self.protection.unwrap_or_else(Protection::read_write),
                    false,
                )?,
                None,
            ),
        }
    }

    pub(crate) fn wrap(
        mapping: MemoryMapping,
        file_descriptor: Option<&'a dyn AsRawDescriptor>,
    ) -> Result<CrateMemoryMapping> {
        let file_descriptor = match file_descriptor {
            Some(descriptor) => Some(
                SafeDescriptor::try_from(descriptor)
                    .map_err(|_| Error::SystemCallFailed(ErrnoError::last()))?,
            ),
            None => None,
        };
        Ok(CrateMemoryMapping {
            mapping,
            _file_descriptor: file_descriptor,
        })
    }
}

/// MemoryMappingArena provides a reserved virtual address region for memory mappings.
pub struct MemoryMappingArena {
    addr: *mut u8,
    size: usize,
}

// SAFETY: The memory mapping is process-global, so can be sent between threads
unsafe impl Send for MemoryMappingArena {}
// SAFETY: The memory mapping doesn't have interior mutability that could cause races
unsafe impl Sync for MemoryMappingArena {}

impl MemoryMappingArena {
    /// Creates a new MemoryMappingArena with the given size.
    /// The arena is backed by anonymous memory that can be remapped.
    pub fn new(size: usize) -> Result<MemoryMappingArena> {
        // SAFETY: mmap with MAP_ANON|MAP_PRIVATE creates a new anonymous mapping
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_NONE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };

        if addr == libc::MAP_FAILED {
            return Err(Error::SystemCallFailed(ErrnoError::last()));
        }

        Ok(MemoryMappingArena {
            addr: addr as *mut u8,
            size,
        })
    }

    /// Returns a pointer to the start of the arena.
    pub fn as_ptr(&self) -> *mut u8 {
        self.addr
    }

    /// Returns the size of the arena in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Maps `size` bytes starting at `fd_offset` bytes from within the given `fd`
    /// at `offset` bytes from the start of the arena with `prot` protections.
    pub fn add_fd_offset_protection(
        &mut self,
        offset: usize,
        size: usize,
        fd: &dyn AsRawDescriptor,
        fd_offset: u64,
        prot: crate::Protection,
    ) -> crate::errno::Result<()> {
        let prot_flags: libc::c_int = prot.into();
        // SAFETY: We're remapping within our owned arena range
        let addr = unsafe {
            libc::mmap(
                (self.addr as usize + offset) as *mut libc::c_void,
                size,
                prot_flags,
                libc::MAP_SHARED | libc::MAP_FIXED,
                fd.as_raw_descriptor(),
                fd_offset as libc::off_t,
            )
        };
        if addr == libc::MAP_FAILED {
            return crate::errno::errno_result();
        }
        Ok(())
    }

    /// Removes a mapping at `offset` of `size` bytes, replacing with PROT_NONE anonymous mapping.
    pub fn remove(&mut self, offset: usize, size: usize) -> crate::errno::Result<()> {
        // SAFETY: We're remapping within our owned arena range
        let addr = unsafe {
            libc::mmap(
                (self.addr as usize + offset) as *mut libc::c_void,
                size,
                libc::PROT_NONE,
                libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return crate::errno::errno_result();
        }
        Ok(())
    }
}

// SAFETY: The pointer and size point to a memory range owned by this MemoryMappingArena that
// won't be unmapped until it's Dropped.
unsafe impl MappedRegion for MemoryMappingArena {
    fn as_ptr(&self) -> *mut u8 {
        self.addr
    }

    fn size(&self) -> usize {
        self.size
    }

    fn add_fd_mapping(
        &mut self,
        offset: usize,
        size: usize,
        fd: &dyn AsRawDescriptor,
        fd_offset: u64,
        prot: crate::Protection,
    ) -> Result<()> {
        self.add_fd_offset_protection(offset, size, fd, fd_offset, prot)
            .map_err(|e| Error::SystemCallFailed(e))
    }

    fn remove_mapping(&mut self, offset: usize, size: usize) -> Result<()> {
        self.remove(offset, size)
            .map_err(|e| Error::SystemCallFailed(e))
    }
}

impl Drop for MemoryMappingArena {
    fn drop(&mut self) {
        // SAFETY: We own this mapping
        unsafe {
            libc::munmap(self.addr as *mut libc::c_void, self.size);
        }
    }
}

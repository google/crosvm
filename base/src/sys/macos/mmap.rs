// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Memory mapping support for macOS.

use std::ptr::null_mut;

use libc::c_int;
use libc::PROT_READ;
use libc::PROT_WRITE;

use crate::errno::Error as ErrnoError;
use crate::pagesize;
use crate::AsRawDescriptor;
use crate::MappedRegion;
use crate::MemoryMapping as CrateMemoryMapping;
use crate::MemoryMappingBuilder;
use crate::MmapError as Error;
use crate::MmapResult as Result;
use crate::Protection;
use crate::RawDescriptor;
use crate::SafeDescriptor;

impl From<Protection> for c_int {
    #[inline(always)]
    fn from(p: Protection) -> Self {
        let mut value = 0;
        if p.read {
            value |= PROT_READ
        }
        if p.write {
            value |= PROT_WRITE;
        }
        value
    }
}

fn validate_includes_range(mmap_size: usize, offset: usize, range_size: usize) -> Result<()> {
    let end_offset = offset
        .checked_add(range_size)
        .ok_or(Error::InvalidAddress)?;
    if end_offset <= mmap_size {
        Ok(())
    } else {
        Err(Error::InvalidAddress)
    }
}

impl dyn MappedRegion {
    pub fn msync(&self, offset: usize, size: usize) -> Result<()> {
        validate_includes_range(self.size(), offset, size)?;

        let ret = unsafe {
            libc::msync(
                (self.as_ptr() as usize + offset) as *mut libc::c_void,
                size,
                libc::MS_SYNC,
            )
        };
        if ret != -1 {
            Ok(())
        } else {
            Err(Error::SystemCallFailed(ErrnoError::last()))
        }
    }

    pub fn madvise(&self, offset: usize, size: usize, advice: libc::c_int) -> Result<()> {
        validate_includes_range(self.size(), offset, size)?;

        let ret = unsafe {
            libc::madvise(
                (self.as_ptr() as usize + offset) as *mut libc::c_void,
                size,
                advice,
            )
        };
        if ret != -1 {
            Ok(())
        } else {
            Err(Error::SystemCallFailed(ErrnoError::last()))
        }
    }
}

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
        let mut flags = libc::MAP_SHARED;
        if fd.is_none() {
            flags |= libc::MAP_ANONYMOUS;
        }

        let (raw_fd, offset) = fd.unwrap_or((-1, 0));

        let effective_size = if let Some(alignment) = align {
            size + alignment as usize
        } else {
            size
        };

        let addr = libc::mmap(
            addr.map_or(null_mut(), |a| a as *mut libc::c_void),
            effective_size,
            prot,
            flags,
            raw_fd,
            offset as libc::off_t,
        );

        if addr == libc::MAP_FAILED {
            return Err(Error::SystemCallFailed(ErrnoError::last()));
        }

        let mut final_addr = addr as *mut u8;

        if let Some(alignment) = align {
            let aligned = (final_addr as usize + alignment as usize - 1) & !(alignment as usize - 1);
            let prefix_size = aligned - final_addr as usize;
            if prefix_size > 0 {
                libc::munmap(final_addr as *mut libc::c_void, prefix_size);
            }
            let suffix_size = alignment as usize - prefix_size;
            if suffix_size > 0 {
                libc::munmap(
                    (aligned + size) as *mut libc::c_void,
                    suffix_size,
                );
            }
            final_addr = aligned as *mut u8;
        }

        Ok(MemoryMapping {
            addr: final_addr,
            size,
        })
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

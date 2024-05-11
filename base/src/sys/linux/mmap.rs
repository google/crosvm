// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The mmap module provides a safe interface to mmap memory and ensures unmap is called when the
//! mmap object leaves scope.

use std::ptr::null_mut;

use libc::c_int;
use libc::PROT_READ;
use libc::PROT_WRITE;
use log::warn;

use super::Error as ErrnoError;
use crate::pagesize;
use crate::AsRawDescriptor;
use crate::Descriptor;
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

/// Validates that `offset`..`offset+range_size` lies within the bounds of a memory mapping of
/// `mmap_size` bytes.  Also checks for any overflow.
fn validate_includes_range(mmap_size: usize, offset: usize, range_size: usize) -> Result<()> {
    // Ensure offset + size doesn't overflow
    let end_offset = offset
        .checked_add(range_size)
        .ok_or(Error::InvalidAddress)?;
    // Ensure offset + size are within the mapping bounds
    if end_offset <= mmap_size {
        Ok(())
    } else {
        Err(Error::InvalidAddress)
    }
}

impl dyn MappedRegion {
    /// Calls msync with MS_SYNC on a mapping of `size` bytes starting at `offset` from the start of
    /// the region.  `offset`..`offset+size` must be contained within the `MappedRegion`.
    pub fn msync(&self, offset: usize, size: usize) -> Result<()> {
        validate_includes_range(self.size(), offset, size)?;

        // SAFETY:
        // Safe because the MemoryMapping/MemoryMappingArena interface ensures our pointer and size
        // are correct, and we've validated that `offset`..`offset+size` is in the range owned by
        // this `MappedRegion`.
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

    /// Calls madvise on a mapping of `size` bytes starting at `offset` from the start of
    /// the region.  `offset`..`offset+size` must be contained within the `MappedRegion`.
    pub fn madvise(&self, offset: usize, size: usize, advice: libc::c_int) -> Result<()> {
        validate_includes_range(self.size(), offset, size)?;

        // SAFETY:
        // Safe because the MemoryMapping/MemoryMappingArena interface ensures our pointer and size
        // are correct, and we've validated that `offset`..`offset+size` is in the range owned by
        // this `MappedRegion`.
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

/// Wraps an anonymous shared memory mapping in the current process. Provides
/// RAII semantics including munmap when no longer needed.
#[derive(Debug)]
pub struct MemoryMapping {
    addr: *mut u8,
    size: usize,
}

// SAFETY:
// Send and Sync aren't automatically inherited for the raw address pointer.
// Accessing that pointer is only done through the stateless interface which
// allows the object to be shared by multiple threads without a decrease in
// safety.
unsafe impl Send for MemoryMapping {}
// SAFETY: See safety comments for impl Send
unsafe impl Sync for MemoryMapping {}

impl MemoryMapping {
    /// Creates an anonymous shared, read/write mapping of `size` bytes.
    ///
    /// # Arguments
    /// * `size` - Size of memory region in bytes.
    pub fn new(size: usize) -> Result<MemoryMapping> {
        MemoryMapping::new_protection(size, None, Protection::read_write())
    }

    /// Creates an anonymous shared mapping of `size` bytes with `prot` protection.
    ///
    /// # Arguments
    /// * `size` - Size of memory region in bytes.
    /// * `align` - Optional alignment for MemoryMapping::addr.
    /// * `prot` - Protection (e.g. readable/writable) of the memory region.
    pub fn new_protection(
        size: usize,
        align: Option<u64>,
        prot: Protection,
    ) -> Result<MemoryMapping> {
        // SAFETY:
        // This is safe because we are creating an anonymous mapping in a place not already used by
        // any other area in this process.
        unsafe { MemoryMapping::try_mmap(None, size, align, prot.into(), None) }
    }

    /// Maps the first `size` bytes of the given `fd` as read/write.
    ///
    /// # Arguments
    /// * `fd` - File descriptor to mmap from.
    /// * `size` - Size of memory region in bytes.
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

    /// Maps the `size` bytes starting at `offset` bytes of the given `fd` as read/write.
    ///
    /// # Arguments
    /// * `fd` - File descriptor to mmap from.
    /// * `size` - Size of memory region in bytes.
    /// * `offset` - Offset in bytes from the beginning of `fd` to start the mmap.
    /// * `prot` - Protection (e.g. readable/writable) of the memory region.
    pub fn from_fd_offset_protection(
        fd: &dyn AsRawDescriptor,
        size: usize,
        offset: u64,
        prot: Protection,
    ) -> Result<MemoryMapping> {
        MemoryMapping::from_fd_offset_protection_populate(fd, size, offset, 0, prot, false)
    }

    /// Maps `size` bytes starting at `offset` from the given `fd` as read/write, and requests
    /// that the pages are pre-populated.
    /// # Arguments
    /// * `fd` - File descriptor to mmap from.
    /// * `size` - Size of memory region in bytes.
    /// * `offset` - Offset in bytes from the beginning of `fd` to start the mmap.
    /// * `align` - Alignment for MemoryMapping::addr.
    /// * `prot` - Protection (e.g. readable/writable) of the memory region.
    /// * `populate` - Populate (prefault) page tables for a mapping.
    pub fn from_fd_offset_protection_populate(
        fd: &dyn AsRawDescriptor,
        size: usize,
        offset: u64,
        align: u64,
        prot: Protection,
        populate: bool,
    ) -> Result<MemoryMapping> {
        // SAFETY:
        // This is safe because we are creating an anonymous mapping in a place not already used
        // by any other area in this process.
        unsafe {
            MemoryMapping::try_mmap_populate(
                None,
                size,
                Some(align),
                prot.into(),
                Some((fd, offset)),
                populate,
            )
        }
    }

    /// Creates an anonymous shared mapping of `size` bytes with `prot` protection.
    ///
    /// # Arguments
    ///
    /// * `addr` - Memory address to mmap at.
    /// * `size` - Size of memory region in bytes.
    /// * `prot` - Protection (e.g. readable/writable) of the memory region.
    ///
    /// # Safety
    ///
    /// This function should not be called before the caller unmaps any mmap'd regions already
    /// present at `(addr..addr+size)`.
    pub unsafe fn new_protection_fixed(
        addr: *mut u8,
        size: usize,
        prot: Protection,
    ) -> Result<MemoryMapping> {
        MemoryMapping::try_mmap(Some(addr), size, None, prot.into(), None)
    }

    /// Maps the `size` bytes starting at `offset` bytes of the given `fd` with
    /// `prot` protections.
    ///
    /// # Arguments
    ///
    /// * `addr` - Memory address to mmap at.
    /// * `fd` - File descriptor to mmap from.
    /// * `size` - Size of memory region in bytes.
    /// * `offset` - Offset in bytes from the beginning of `fd` to start the mmap.
    /// * `prot` - Protection (e.g. readable/writable) of the memory region.
    ///
    /// # Safety
    ///
    /// This function should not be called before the caller unmaps any mmap'd regions already
    /// present at `(addr..addr+size)`.
    pub unsafe fn from_descriptor_offset_protection_fixed(
        addr: *mut u8,
        fd: &dyn AsRawDescriptor,
        size: usize,
        offset: u64,
        prot: Protection,
    ) -> Result<MemoryMapping> {
        MemoryMapping::try_mmap(Some(addr), size, None, prot.into(), Some((fd, offset)))
    }

    /// Helper wrapper around try_mmap_populate when without MAP_POPULATE
    unsafe fn try_mmap(
        addr: Option<*mut u8>,
        size: usize,
        align: Option<u64>,
        prot: c_int,
        fd: Option<(&dyn AsRawDescriptor, u64)>,
    ) -> Result<MemoryMapping> {
        MemoryMapping::try_mmap_populate(addr, size, align, prot, fd, false)
    }

    /// Helper wrapper around libc::mmap that does some basic validation, and calls
    /// madvise with MADV_DONTDUMP on the created mmap
    unsafe fn try_mmap_populate(
        addr: Option<*mut u8>,
        size: usize,
        align: Option<u64>,
        prot: c_int,
        fd: Option<(&dyn AsRawDescriptor, u64)>,
        populate: bool,
    ) -> Result<MemoryMapping> {
        let mut flags = libc::MAP_SHARED;
        if populate {
            flags |= libc::MAP_POPULATE;
        }
        // If addr is provided, set the (FIXED | NORESERVE) flag, and validate addr alignment.
        let addr = match addr {
            Some(addr) => {
                if (addr as usize) % pagesize() != 0 {
                    return Err(Error::NotPageAligned);
                }
                flags |= libc::MAP_FIXED | libc::MAP_NORESERVE;
                addr as *mut libc::c_void
            }
            None => null_mut(),
        };

        // mmap already PAGE_SIZE align the returned address.
        let align = if align.unwrap_or(0) == pagesize() as u64 {
            Some(0)
        } else {
            align
        };

        // Add an address if an alignment is requested.
        let (addr, orig_addr, orig_size) = match align {
            None | Some(0) => (addr, None, None),
            Some(align) => {
                if !addr.is_null() || !align.is_power_of_two() {
                    return Err(Error::InvalidAlignment);
                }
                let orig_size = size + align as usize;
                let orig_addr = libc::mmap64(
                    null_mut(),
                    orig_size,
                    prot,
                    libc::MAP_PRIVATE | libc::MAP_NORESERVE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                if orig_addr == libc::MAP_FAILED {
                    return Err(Error::SystemCallFailed(ErrnoError::last()));
                }

                flags |= libc::MAP_FIXED;

                let mask = align - 1;
                (
                    (orig_addr.wrapping_add(mask as usize) as u64 & !mask) as *mut libc::c_void,
                    Some(orig_addr),
                    Some(orig_size),
                )
            }
        };

        // If fd is provided, validate fd offset is within bounds. If not, it's anonymous mapping
        // and set the (ANONYMOUS | NORESERVE) flag.
        let (fd, offset) = match fd {
            Some((fd, offset)) => {
                if offset > libc::off64_t::max_value() as u64 {
                    return Err(Error::InvalidOffset);
                }
                // Map private for read-only seal. See below for upstream relax of the restriction.
                // - https://lore.kernel.org/bpf/20231013103208.kdffpyerufr4ygnw@quack3/T/
                // SAFETY:
                // Safe because no third parameter is expected and we check the return result.
                let seals = unsafe { libc::fcntl(fd.as_raw_descriptor(), libc::F_GET_SEALS) };
                if (seals >= 0) && (seals & libc::F_SEAL_WRITE != 0) {
                    flags &= !libc::MAP_SHARED;
                    flags |= libc::MAP_PRIVATE;
                }
                (fd.as_raw_descriptor(), offset as libc::off64_t)
            }
            None => {
                flags |= libc::MAP_ANONYMOUS | libc::MAP_NORESERVE;
                (-1, 0)
            }
        };
        let addr = libc::mmap64(addr, size, prot, flags, fd, offset);
        if addr == libc::MAP_FAILED {
            return Err(Error::SystemCallFailed(ErrnoError::last()));
        }

        // If an original mmap exists, we can now remove the unused regions
        if let Some(orig_addr) = orig_addr {
            let mut unmap_start = orig_addr as usize;
            let mut unmap_end = addr as usize;
            let mut unmap_size = unmap_end - unmap_start;

            if unmap_size > 0 {
                libc::munmap(orig_addr, unmap_size);
            }

            unmap_start = addr as usize + size;
            unmap_end = orig_addr as usize + orig_size.unwrap();
            unmap_size = unmap_end - unmap_start;

            if unmap_size > 0 {
                libc::munmap(unmap_start as *mut libc::c_void, unmap_size);
            }
        }

        // This is safe because we call madvise with a valid address and size.
        let _ = libc::madvise(addr, size, libc::MADV_DONTDUMP);

        // This is safe because KSM's only userspace visible effects are timing
        // and memory consumption; it doesn't affect rust safety semantics.
        // KSM is also disabled by default, and this flag is only a hint.
        let _ = libc::madvise(addr, size, libc::MADV_MERGEABLE);

        Ok(MemoryMapping {
            addr: addr as *mut u8,
            size,
        })
    }

    /// Madvise the kernel to unmap on fork.
    pub fn use_dontfork(&self) -> Result<()> {
        // SAFETY:
        // This is safe because we call madvise with a valid address and size, and we check the
        // return value.
        let ret = unsafe {
            libc::madvise(
                self.as_ptr() as *mut libc::c_void,
                self.size(),
                libc::MADV_DONTFORK,
            )
        };
        if ret == -1 {
            Err(Error::SystemCallFailed(ErrnoError::last()))
        } else {
            Ok(())
        }
    }

    /// Madvise the kernel to use Huge Pages for this mapping.
    pub fn use_hugepages(&self) -> Result<()> {
        const SZ_2M: usize = 2 * 1024 * 1024;

        // THP uses 2M pages, so use THP only on mappings that are at least
        // 2M in size.
        if self.size() < SZ_2M {
            return Ok(());
        }

        // SAFETY:
        // This is safe because we call madvise with a valid address and size, and we check the
        // return value.
        let ret = unsafe {
            libc::madvise(
                self.as_ptr() as *mut libc::c_void,
                self.size(),
                libc::MADV_HUGEPAGE,
            )
        };
        if ret == -1 {
            Err(Error::SystemCallFailed(ErrnoError::last()))
        } else {
            Ok(())
        }
    }

    /// Calls msync with MS_SYNC on the mapping.
    pub fn msync(&self) -> Result<()> {
        // SAFETY:
        // This is safe since we use the exact address and length of a known
        // good memory mapping.
        let ret = unsafe {
            libc::msync(
                self.as_ptr() as *mut libc::c_void,
                self.size(),
                libc::MS_SYNC,
            )
        };
        if ret == -1 {
            return Err(Error::SystemCallFailed(ErrnoError::last()));
        }
        Ok(())
    }

    /// Uses madvise to tell the kernel to remove the specified range.  Subsequent reads
    /// to the pages in the range will return zero bytes.
    pub fn remove_range(&self, mem_offset: usize, count: usize) -> Result<()> {
        self.range_end(mem_offset, count)
            .map_err(|_| Error::InvalidRange(mem_offset, count, self.size()))?;
        // SAFETY: Safe because all the args to madvise are valid and the return
        // value is checked.
        let ret = unsafe {
            // madvising away the region is the same as the guest changing it.
            // Next time it is read, it may return zero pages.
            libc::madvise(
                (self.addr as usize + mem_offset) as *mut _,
                count,
                libc::MADV_REMOVE,
            )
        };
        if ret < 0 {
            Err(Error::SystemCallFailed(super::Error::last()))
        } else {
            Ok(())
        }
    }

    /// Tell the kernel to readahead the range.
    ///
    /// This does not block the thread by I/O wait from reading the backed file. This does not
    /// guarantee that the pages are surely present unless the pages are mlock(2)ed by
    /// `lock_on_fault_unchecked()`.
    ///
    /// The `mem_offset` and `count` must be validated by caller.
    ///
    /// # Arguments
    ///
    /// * `mem_offset` - The offset of the head of the range.
    /// * `count` - The size in bytes of the range.
    pub fn async_prefetch(&self, mem_offset: usize, count: usize) -> Result<()> {
        // Validation
        self.range_end(mem_offset, count)
            .map_err(|_| Error::InvalidRange(mem_offset, count, self.size()))?;
        // SAFETY:
        // Safe because populating the pages from the backed file does not affect the Rust memory
        // safety.
        let ret = unsafe {
            libc::madvise(
                (self.addr as usize + mem_offset) as *mut _,
                count,
                libc::MADV_WILLNEED,
            )
        };
        if ret < 0 {
            Err(Error::SystemCallFailed(super::Error::last()))
        } else {
            Ok(())
        }
    }

    /// Tell the kernel to drop the page cache.
    ///
    /// This cannot be applied to locked pages.
    ///
    /// The `mem_offset` and `count` must be validated by caller.
    ///
    /// NOTE: This function has destructive semantics. It throws away data in the page cache without
    /// writing it to the backing file. If the data is important, the caller should ensure it is
    /// written to disk before calling this function or should use MADV_PAGEOUT instead.
    ///
    /// # Arguments
    ///
    /// * `mem_offset` - The offset of the head of the range.
    /// * `count` - The size in bytes of the range.
    pub fn drop_page_cache(&self, mem_offset: usize, count: usize) -> Result<()> {
        // Validation
        self.range_end(mem_offset, count)
            .map_err(|_| Error::InvalidRange(mem_offset, count, self.size()))?;
        // SAFETY:
        // Safe because dropping the page cache does not affect the Rust memory safety.
        let ret = unsafe {
            libc::madvise(
                (self.addr as usize + mem_offset) as *mut _,
                count,
                libc::MADV_DONTNEED,
            )
        };
        if ret < 0 {
            Err(Error::SystemCallFailed(super::Error::last()))
        } else {
            Ok(())
        }
    }

    /// Lock the resident pages in the range not to be swapped out.
    ///
    /// The remaining nonresident page are locked when they are populated.
    ///
    /// The `mem_offset` and `count` must be validated by caller.
    ///
    /// # Arguments
    ///
    /// * `mem_offset` - The offset of the head of the range.
    /// * `count` - The size in bytes of the range.
    pub fn lock_on_fault(&self, mem_offset: usize, count: usize) -> Result<()> {
        // Validation
        self.range_end(mem_offset, count)
            .map_err(|_| Error::InvalidRange(mem_offset, count, self.size()))?;
        let addr = self.addr as usize + mem_offset;
        // SAFETY:
        // Safe because MLOCK_ONFAULT only affects the swap behavior of the kernel, so it has no
        // impact on rust semantics.
        let ret = unsafe { libc::mlock2(addr as *mut _, count, libc::MLOCK_ONFAULT) };
        if ret < 0 {
            let errno = super::Error::last();
            warn!(
                "failed to mlock at {:#x} with length {}: {}",
                addr as u64,
                self.size(),
                errno,
            );
            Err(Error::SystemCallFailed(errno))
        } else {
            Ok(())
        }
    }

    /// Unlock the range of pages.
    ///
    /// Unlocking non-locked pages does not fail.
    ///
    /// The `mem_offset` and `count` must be validated by caller.
    ///
    /// # Arguments
    ///
    /// * `mem_offset` - The offset of the head of the range.
    /// * `count` - The size in bytes of the range.
    pub fn unlock(&self, mem_offset: usize, count: usize) -> Result<()> {
        // Validation
        self.range_end(mem_offset, count)
            .map_err(|_| Error::InvalidRange(mem_offset, count, self.size()))?;
        // SAFETY:
        // Safe because munlock(2) does not affect the Rust memory safety.
        let ret = unsafe { libc::munlock((self.addr as usize + mem_offset) as *mut _, count) };
        if ret < 0 {
            Err(Error::SystemCallFailed(super::Error::last()))
        } else {
            Ok(())
        }
    }

    // Check that offset+count is valid and return the sum.
    pub(crate) fn range_end(&self, offset: usize, count: usize) -> Result<usize> {
        let mem_end = offset.checked_add(count).ok_or(Error::InvalidAddress)?;
        if mem_end > self.size() {
            return Err(Error::InvalidAddress);
        }
        Ok(mem_end)
    }
}

// SAFETY:
// Safe because the pointer and size point to a memory range owned by this MemoryMapping that won't
// be unmapped until it's Dropped.
unsafe impl MappedRegion for MemoryMapping {
    fn as_ptr(&self) -> *mut u8 {
        self.addr
    }

    fn size(&self) -> usize {
        self.size
    }
}

impl Drop for MemoryMapping {
    fn drop(&mut self) {
        // SAFETY:
        // This is safe because we mmap the area at addr ourselves, and nobody
        // else is holding a reference to it.
        unsafe {
            libc::munmap(self.addr as *mut libc::c_void, self.size);
        }
    }
}

/// Tracks Fixed Memory Maps within an anonymous memory-mapped fixed-sized arena
/// in the current process.
pub struct MemoryMappingArena {
    addr: *mut u8,
    size: usize,
}

// SAFETY:
// Send and Sync aren't automatically inherited for the raw address pointer.
// Accessing that pointer is only done through the stateless interface which
// allows the object to be shared by multiple threads without a decrease in
// safety.
unsafe impl Send for MemoryMappingArena {}
// SAFETY: See safety comments for impl Send
unsafe impl Sync for MemoryMappingArena {}

impl MemoryMappingArena {
    /// Creates an mmap arena of `size` bytes.
    ///
    /// # Arguments
    /// * `size` - Size of memory region in bytes.
    pub fn new(size: usize) -> Result<MemoryMappingArena> {
        // Reserve the arena's memory using an anonymous read-only mmap.
        MemoryMapping::new_protection(size, None, Protection::read()).map(From::from)
    }

    /// Anonymously maps `size` bytes at `offset` bytes from the start of the arena
    /// with `prot` protections. `offset` must be page aligned.
    ///
    /// # Arguments
    /// * `offset` - Page aligned offset into the arena in bytes.
    /// * `size` - Size of memory region in bytes.
    /// * `prot` - Protection (e.g. readable/writable) of the memory region.
    pub fn add_anon_protection(
        &mut self,
        offset: usize,
        size: usize,
        prot: Protection,
    ) -> Result<()> {
        self.try_add(offset, size, prot, None)
    }

    /// Anonymously maps `size` bytes at `offset` bytes from the start of the arena.
    /// `offset` must be page aligned.
    ///
    /// # Arguments
    /// * `offset` - Page aligned offset into the arena in bytes.
    /// * `size` - Size of memory region in bytes.
    pub fn add_anon(&mut self, offset: usize, size: usize) -> Result<()> {
        self.add_anon_protection(offset, size, Protection::read_write())
    }

    /// Maps `size` bytes from the start of the given `fd` at `offset` bytes from
    /// the start of the arena. `offset` must be page aligned.
    ///
    /// # Arguments
    /// * `offset` - Page aligned offset into the arena in bytes.
    /// * `size` - Size of memory region in bytes.
    /// * `fd` - File descriptor to mmap from.
    pub fn add_fd(&mut self, offset: usize, size: usize, fd: &dyn AsRawDescriptor) -> Result<()> {
        self.add_fd_offset(offset, size, fd, 0)
    }

    /// Maps `size` bytes starting at `fs_offset` bytes from within the given `fd`
    /// at `offset` bytes from the start of the arena. `offset` must be page aligned.
    ///
    /// # Arguments
    /// * `offset` - Page aligned offset into the arena in bytes.
    /// * `size` - Size of memory region in bytes.
    /// * `fd` - File descriptor to mmap from.
    /// * `fd_offset` - Offset in bytes from the beginning of `fd` to start the mmap.
    pub fn add_fd_offset(
        &mut self,
        offset: usize,
        size: usize,
        fd: &dyn AsRawDescriptor,
        fd_offset: u64,
    ) -> Result<()> {
        self.add_fd_offset_protection(offset, size, fd, fd_offset, Protection::read_write())
    }

    /// Maps `size` bytes starting at `fs_offset` bytes from within the given `fd`
    /// at `offset` bytes from the start of the arena with `prot` protections.
    /// `offset` must be page aligned.
    ///
    /// # Arguments
    /// * `offset` - Page aligned offset into the arena in bytes.
    /// * `size` - Size of memory region in bytes.
    /// * `fd` - File descriptor to mmap from.
    /// * `fd_offset` - Offset in bytes from the beginning of `fd` to start the mmap.
    /// * `prot` - Protection (e.g. readable/writable) of the memory region.
    pub fn add_fd_offset_protection(
        &mut self,
        offset: usize,
        size: usize,
        fd: &dyn AsRawDescriptor,
        fd_offset: u64,
        prot: Protection,
    ) -> Result<()> {
        self.try_add(offset, size, prot, Some((fd, fd_offset)))
    }

    /// Helper method that calls appropriate MemoryMapping constructor and adds
    /// the resulting map into the arena.
    fn try_add(
        &mut self,
        offset: usize,
        size: usize,
        prot: Protection,
        fd: Option<(&dyn AsRawDescriptor, u64)>,
    ) -> Result<()> {
        // Ensure offset is page-aligned
        if offset % pagesize() != 0 {
            return Err(Error::NotPageAligned);
        }
        validate_includes_range(self.size(), offset, size)?;

        // SAFETY:
        // This is safe since the range has been validated.
        let mmap = unsafe {
            match fd {
                Some((fd, fd_offset)) => MemoryMapping::from_descriptor_offset_protection_fixed(
                    self.addr.add(offset),
                    fd,
                    size,
                    fd_offset,
                    prot,
                )?,
                None => MemoryMapping::new_protection_fixed(self.addr.add(offset), size, prot)?,
            }
        };

        // This mapping will get automatically removed when we drop the whole arena.
        std::mem::forget(mmap);
        Ok(())
    }

    /// Removes `size` bytes at `offset` bytes from the start of the arena. `offset` must be page
    /// aligned.
    ///
    /// # Arguments
    /// * `offset` - Page aligned offset into the arena in bytes.
    /// * `size` - Size of memory region in bytes.
    pub fn remove(&mut self, offset: usize, size: usize) -> Result<()> {
        self.try_add(offset, size, Protection::read(), None)
    }
}

// SAFETY:
// Safe because the pointer and size point to a memory range owned by this MemoryMappingArena that
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
        prot: Protection,
    ) -> Result<()> {
        self.add_fd_offset_protection(offset, size, fd, fd_offset, prot)
    }

    fn remove_mapping(&mut self, offset: usize, size: usize) -> Result<()> {
        self.remove(offset, size)
    }
}

impl From<MemoryMapping> for MemoryMappingArena {
    fn from(mmap: MemoryMapping) -> Self {
        let addr = mmap.as_ptr();
        let size = mmap.size();

        // Forget the original mapping because the `MemoryMappingArena` will take care of calling
        // `munmap` when it is dropped.
        std::mem::forget(mmap);
        MemoryMappingArena { addr, size }
    }
}

impl From<CrateMemoryMapping> for MemoryMappingArena {
    fn from(mmap: CrateMemoryMapping) -> Self {
        MemoryMappingArena::from(mmap.mapping)
    }
}

impl Drop for MemoryMappingArena {
    fn drop(&mut self) {
        // SAFETY:
        // This is safe because we own this memory range, and nobody else is holding a reference to
        // it.
        unsafe {
            libc::munmap(self.addr as *mut libc::c_void, self.size);
        }
    }
}

impl CrateMemoryMapping {
    pub fn use_dontfork(&self) -> Result<()> {
        self.mapping.use_dontfork()
    }

    pub fn use_hugepages(&self) -> Result<()> {
        self.mapping.use_hugepages()
    }

    pub fn from_raw_ptr(addr: RawDescriptor, size: usize) -> Result<CrateMemoryMapping> {
        MemoryMapping::from_fd_offset(&Descriptor(addr), size, 0).map(|mapping| {
            CrateMemoryMapping {
                mapping,
                _file_descriptor: None,
            }
        })
    }
}

pub trait MemoryMappingUnix {
    /// Remove the specified range from the mapping.
    fn remove_range(&self, mem_offset: usize, count: usize) -> Result<()>;
    /// Tell the kernel to readahead the range.
    fn async_prefetch(&self, mem_offset: usize, count: usize) -> Result<()>;
    /// Tell the kernel to drop the page cache.
    fn drop_page_cache(&self, mem_offset: usize, count: usize) -> Result<()>;
    /// Lock the resident pages in the range not to be swapped out.
    fn lock_on_fault(&self, mem_offset: usize, count: usize) -> Result<()>;
    /// Unlock the range of pages.
    fn unlock(&self, mem_offset: usize, count: usize) -> Result<()>;
    /// Disable host swap for this mapping.
    fn lock_all(&self) -> Result<()>;
}

impl MemoryMappingUnix for CrateMemoryMapping {
    fn remove_range(&self, mem_offset: usize, count: usize) -> Result<()> {
        self.mapping.remove_range(mem_offset, count)
    }
    fn async_prefetch(&self, mem_offset: usize, count: usize) -> Result<()> {
        self.mapping.async_prefetch(mem_offset, count)
    }
    fn drop_page_cache(&self, mem_offset: usize, count: usize) -> Result<()> {
        self.mapping.drop_page_cache(mem_offset, count)
    }
    fn lock_on_fault(&self, mem_offset: usize, count: usize) -> Result<()> {
        self.mapping.lock_on_fault(mem_offset, count)
    }
    fn unlock(&self, mem_offset: usize, count: usize) -> Result<()> {
        self.mapping.unlock(mem_offset, count)
    }
    fn lock_all(&self) -> Result<()> {
        self.mapping.lock_on_fault(0, self.mapping.size())
    }
}

pub trait MemoryMappingBuilderUnix<'a> {
    #[allow(clippy::wrong_self_convention)]
    fn from_descriptor(self, descriptor: &'a dyn AsRawDescriptor) -> MemoryMappingBuilder;
}

impl<'a> MemoryMappingBuilderUnix<'a> for MemoryMappingBuilder<'a> {
    /// Build the memory mapping given the specified descriptor to mapped memory
    ///
    /// Default: Create a new memory mapping.
    #[allow(clippy::wrong_self_convention)]
    fn from_descriptor(mut self, descriptor: &'a dyn AsRawDescriptor) -> MemoryMappingBuilder {
        self.descriptor = Some(descriptor);
        self
    }
}

impl<'a> MemoryMappingBuilder<'a> {
    /// Request that the mapped pages are pre-populated
    ///
    /// Default: Do not populate
    pub fn populate(mut self) -> MemoryMappingBuilder<'a> {
        self.populate = true;
        self
    }

    /// Build a MemoryMapping from the provided options.
    pub fn build(self) -> Result<CrateMemoryMapping> {
        match self.descriptor {
            None => {
                if self.populate {
                    // Population not supported for new mmaps
                    return Err(Error::InvalidArgument);
                }
                MemoryMappingBuilder::wrap(
                    MemoryMapping::new_protection(
                        self.size,
                        self.align,
                        self.protection.unwrap_or_else(Protection::read_write),
                    )?,
                    None,
                )
            }
            Some(descriptor) => MemoryMappingBuilder::wrap(
                MemoryMapping::from_fd_offset_protection_populate(
                    descriptor,
                    self.size,
                    self.offset.unwrap_or(0),
                    self.align.unwrap_or(0),
                    self.protection.unwrap_or_else(Protection::read_write),
                    self.populate,
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

#[cfg(test)]
mod tests {
    use tempfile::tempfile;

    use super::*;
    use crate::descriptor::Descriptor;
    use crate::VolatileMemory;
    use crate::VolatileMemoryError;

    #[test]
    fn basic_map() {
        let m = MemoryMappingBuilder::new(1024).build().unwrap();
        assert_eq!(1024, m.size());
    }

    #[test]
    fn map_invalid_size() {
        let res = MemoryMappingBuilder::new(0).build().unwrap_err();
        if let Error::SystemCallFailed(e) = res {
            assert_eq!(e.errno(), libc::EINVAL);
        } else {
            panic!("unexpected error: {}", res);
        }
    }

    #[test]
    fn map_invalid_fd() {
        let fd = Descriptor(-1);
        let res = MemoryMapping::from_fd(&fd, 1024).unwrap_err();
        if let Error::SystemCallFailed(e) = res {
            assert_eq!(e.errno(), libc::EBADF);
        } else {
            panic!("unexpected error: {}", res);
        }
    }

    #[test]
    fn test_write_past_end() {
        let m = MemoryMappingBuilder::new(5).build().unwrap();
        let res = m.write_slice(&[1, 2, 3, 4, 5, 6], 0);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 5);
    }

    #[test]
    fn slice_size() {
        let m = MemoryMappingBuilder::new(5).build().unwrap();
        let s = m.get_slice(2, 3).unwrap();
        assert_eq!(s.size(), 3);
    }

    #[test]
    fn slice_addr() {
        let m = MemoryMappingBuilder::new(5).build().unwrap();
        let s = m.get_slice(2, 3).unwrap();
        // SAFETY: all addresses are known to exist.
        assert_eq!(s.as_ptr(), unsafe { m.as_ptr().offset(2) });
    }

    #[test]
    fn slice_overflow_error() {
        let m = MemoryMappingBuilder::new(5).build().unwrap();
        let res = m.get_slice(std::usize::MAX, 3).unwrap_err();
        assert_eq!(
            res,
            VolatileMemoryError::Overflow {
                base: std::usize::MAX,
                offset: 3,
            }
        );
    }
    #[test]
    fn slice_oob_error() {
        let m = MemoryMappingBuilder::new(5).build().unwrap();
        let res = m.get_slice(3, 3).unwrap_err();
        assert_eq!(res, VolatileMemoryError::OutOfBounds { addr: 6 });
    }

    #[test]
    fn from_fd_offset_invalid() {
        let fd = tempfile().unwrap();
        let res = MemoryMapping::from_fd_offset(&fd, 4096, (libc::off64_t::max_value() as u64) + 1)
            .unwrap_err();
        match res {
            Error::InvalidOffset => {}
            e => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn arena_new() {
        let m = MemoryMappingArena::new(0x40000).unwrap();
        assert_eq!(m.size(), 0x40000);
    }

    #[test]
    fn arena_add() {
        let mut m = MemoryMappingArena::new(0x40000).unwrap();
        assert!(m.add_anon(0, pagesize() * 4).is_ok());
    }

    #[test]
    fn arena_remove() {
        let mut m = MemoryMappingArena::new(0x40000).unwrap();
        assert!(m.add_anon(0, pagesize() * 4).is_ok());
        assert!(m.remove(0, pagesize()).is_ok());
        assert!(m.remove(0, pagesize() * 2).is_ok());
    }

    #[test]
    fn arena_add_alignment_error() {
        let mut m = MemoryMappingArena::new(pagesize() * 2).unwrap();
        assert!(m.add_anon(0, 0x100).is_ok());
        let res = m.add_anon(pagesize() + 1, 0x100).unwrap_err();
        match res {
            Error::NotPageAligned => {}
            e => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn arena_add_oob_error() {
        let mut m = MemoryMappingArena::new(pagesize()).unwrap();
        let res = m.add_anon(0, pagesize() + 1).unwrap_err();
        match res {
            Error::InvalidAddress => {}
            e => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn arena_add_overlapping() {
        let ps = pagesize();
        let mut m =
            MemoryMappingArena::new(12 * ps).expect("failed to create `MemoryMappingArena`");
        m.add_anon(ps * 4, ps * 4)
            .expect("failed to add sub-mapping");

        // Overlap in the front.
        m.add_anon(ps * 2, ps * 3)
            .expect("failed to add front overlapping sub-mapping");

        // Overlap in the back.
        m.add_anon(ps * 7, ps * 3)
            .expect("failed to add back overlapping sub-mapping");

        // Overlap the back of the first mapping, all of the middle mapping, and the front of the
        // last mapping.
        m.add_anon(ps * 3, ps * 6)
            .expect("failed to add mapping that overlaps several mappings");
    }

    #[test]
    fn arena_remove_overlapping() {
        let ps = pagesize();
        let mut m =
            MemoryMappingArena::new(12 * ps).expect("failed to create `MemoryMappingArena`");
        m.add_anon(ps * 4, ps * 4)
            .expect("failed to add sub-mapping");
        m.add_anon(ps * 2, ps * 2)
            .expect("failed to add front overlapping sub-mapping");
        m.add_anon(ps * 8, ps * 2)
            .expect("failed to add back overlapping sub-mapping");

        // Remove the back of the first mapping and the front of the second.
        m.remove(ps * 3, ps * 2)
            .expect("failed to remove front overlapping mapping");

        // Remove the back of the second mapping and the front of the third.
        m.remove(ps * 7, ps * 2)
            .expect("failed to remove back overlapping mapping");

        // Remove a mapping that completely overlaps the middle mapping.
        m.remove(ps * 5, ps * 2)
            .expect("failed to remove fully overlapping mapping");
    }

    #[test]
    fn arena_remove_unaligned() {
        let ps = pagesize();
        let mut m =
            MemoryMappingArena::new(12 * ps).expect("failed to create `MemoryMappingArena`");

        m.add_anon(0, ps).expect("failed to add mapping");
        m.remove(0, ps - 1)
            .expect("failed to remove unaligned mapping");
    }

    #[test]
    fn arena_msync() {
        let size = 0x40000;
        let m = MemoryMappingArena::new(size).unwrap();
        let ps = pagesize();
        <dyn MappedRegion>::msync(&m, 0, ps).unwrap();
        <dyn MappedRegion>::msync(&m, 0, size).unwrap();
        <dyn MappedRegion>::msync(&m, ps, size - ps).unwrap();
        let res = <dyn MappedRegion>::msync(&m, ps, size).unwrap_err();
        match res {
            Error::InvalidAddress => {}
            e => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn arena_madvise() {
        let size = 0x40000;
        let mut m = MemoryMappingArena::new(size).unwrap();
        m.add_anon_protection(0, size, Protection::read_write())
            .expect("failed to add writable protection for madvise MADV_REMOVE");
        let ps = pagesize();
        <dyn MappedRegion>::madvise(&m, 0, ps, libc::MADV_PAGEOUT).unwrap();
        <dyn MappedRegion>::madvise(&m, 0, size, libc::MADV_PAGEOUT).unwrap();
        <dyn MappedRegion>::madvise(&m, ps, size - ps, libc::MADV_REMOVE).unwrap();
        let res = <dyn MappedRegion>::madvise(&m, ps, size, libc::MADV_PAGEOUT).unwrap_err();
        match res {
            Error::InvalidAddress => {}
            e => panic!("unexpected error: {}", e),
        }
    }
}

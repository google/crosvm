// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The mmap module provides a safe interface to mmap memory and ensures unmap is called when the
//! mmap object leaves scope.

use std::io;
use std::ptr::null_mut;

use libc::c_int;
use libc::c_void;
use libc::read;
use libc::write;
use log::warn;
use remain::sorted;

use super::pagesize;
use super::Error as ErrnoError;
use crate::AsRawDescriptor;
use crate::Descriptor;
use crate::MappedRegion;
use crate::MemoryMapping as CrateMemoryMapping;
use crate::MemoryMappingBuilder;
use crate::Protection;
use crate::RawDescriptor;
use crate::SafeDescriptor;

#[sorted]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("`add_fd_mapping` is unsupported")]
    AddFdMappingIsUnsupported,
    #[error("requested memory out of range")]
    InvalidAddress,
    #[error("invalid argument provided when creating mapping")]
    InvalidArgument,
    #[error("requested offset is out of range of off64_t")]
    InvalidOffset,
    #[error("requested memory range spans past the end of the region: offset={0} count={1} region_size={2}")]
    InvalidRange(usize, usize, usize),
    #[error("requested memory is not page aligned")]
    NotPageAligned,
    #[error("failed to read from file to memory: {0}")]
    ReadToMemory(#[source] io::Error),
    #[error("`remove_mapping` is unsupported")]
    RemoveMappingIsUnsupported,
    #[error("mmap related system call failed: {0}")]
    SystemCallFailed(#[source] ErrnoError),
    #[error("failed to write from memory to file: {0}")]
    WriteFromMemory(#[source] io::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

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
}

/// Wraps an anonymous shared memory mapping in the current process. Provides
/// RAII semantics including munmap when no longer needed.
#[derive(Debug)]
pub struct MemoryMapping {
    addr: *mut u8,
    size: usize,
}

// Send and Sync aren't automatically inherited for the raw address pointer.
// Accessing that pointer is only done through the stateless interface which
// allows the object to be shared by multiple threads without a decrease in
// safety.
unsafe impl Send for MemoryMapping {}
unsafe impl Sync for MemoryMapping {}

impl MemoryMapping {
    /// Creates an anonymous shared, read/write mapping of `size` bytes.
    ///
    /// # Arguments
    /// * `size` - Size of memory region in bytes.
    pub fn new(size: usize) -> Result<MemoryMapping> {
        MemoryMapping::new_protection(size, Protection::read_write())
    }

    /// Creates an anonymous shared mapping of `size` bytes with `prot` protection.
    ///
    /// # Arguments
    /// * `size` - Size of memory region in bytes.
    /// * `prot` - Protection (e.g. readable/writable) of the memory region.
    pub fn new_protection(size: usize, prot: Protection) -> Result<MemoryMapping> {
        // This is safe because we are creating an anonymous mapping in a place not already used by
        // any other area in this process.
        unsafe {
            MemoryMapping::try_mmap(
                None,
                size,
                prot.into(),
                libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
                None,
            )
        }
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
    /// * `flags` - flags passed directly to mmap.
    /// * `prot` - Protection (e.g. readable/writable) of the memory region.
    fn from_fd_offset_flags(
        fd: &dyn AsRawDescriptor,
        size: usize,
        offset: u64,
        flags: c_int,
        prot: Protection,
    ) -> Result<MemoryMapping> {
        unsafe {
            // This is safe because we are creating an anonymous mapping in a place not already used
            // by any other area in this process.
            MemoryMapping::try_mmap(None, size, prot.into(), flags, Some((fd, offset)))
        }
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
        MemoryMapping::from_fd_offset_flags(fd, size, offset, libc::MAP_SHARED, prot)
    }

    /// Maps `size` bytes starting at `offset` from the given `fd` as read/write, and requests
    /// that the pages are pre-populated.
    /// # Arguments
    /// * `fd` - File descriptor to mmap from.
    /// * `size` - Size of memory region in bytes.
    /// * `offset` - Offset in bytes from the beginning of `fd` to start the mmap.
    pub fn from_fd_offset_protection_populate(
        fd: &dyn AsRawDescriptor,
        size: usize,
        offset: u64,
        prot: Protection,
        populate: bool,
    ) -> Result<MemoryMapping> {
        let mut flags = libc::MAP_SHARED;
        if populate {
            flags |= libc::MAP_POPULATE;
        }
        MemoryMapping::from_fd_offset_flags(fd, size, offset, flags, prot)
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
        MemoryMapping::try_mmap(
            Some(addr),
            size,
            prot.into(),
            libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
            None,
        )
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
        MemoryMapping::try_mmap(
            Some(addr),
            size,
            prot.into(),
            libc::MAP_SHARED | libc::MAP_NORESERVE,
            Some((fd, offset)),
        )
    }

    /// Helper wrapper around libc::mmap that does some basic validation, and calls
    /// madvise with MADV_DONTDUMP on the created mmap
    unsafe fn try_mmap(
        addr: Option<*mut u8>,
        size: usize,
        prot: c_int,
        flags: c_int,
        fd: Option<(&dyn AsRawDescriptor, u64)>,
    ) -> Result<MemoryMapping> {
        let mut flags = flags;
        // If addr is provided, set the FIXED flag, and validate addr alignment
        let addr = match addr {
            Some(addr) => {
                if (addr as usize) % pagesize() != 0 {
                    return Err(Error::NotPageAligned);
                }
                flags |= libc::MAP_FIXED;
                addr as *mut libc::c_void
            }
            None => null_mut(),
        };
        // If fd is provided, validate fd offset is within bounds
        let (fd, offset) = match fd {
            Some((fd, offset)) => {
                if offset > libc::off64_t::max_value() as u64 {
                    return Err(Error::InvalidOffset);
                }
                (fd.as_raw_descriptor(), offset as libc::off64_t)
            }
            None => (-1, 0),
        };
        let addr = libc::mmap64(addr, size, prot, flags, fd, offset);
        if addr == libc::MAP_FAILED {
            return Err(Error::SystemCallFailed(ErrnoError::last()));
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

    /// Reads data from a file descriptor and writes it to guest memory.
    ///
    /// # Arguments
    /// * `mem_offset` - Begin writing memory at this offset.
    /// * `src` - Read from `src` to memory.
    /// * `count` - Read `count` bytes from `src` to memory.
    ///
    /// # Examples
    ///
    /// * Read bytes from /dev/urandom
    ///
    /// ```
    /// # use base::MemoryMappingBuilder;
    /// # use std::fs::File;
    /// # use std::path::Path;
    /// # fn test_read_random() -> Result<u32, ()> {
    /// #     let mut mem_map = MemoryMappingBuilder::new(1024).build().unwrap();
    ///       let mut file = File::open(Path::new("/dev/urandom")).map_err(|_| ())?;
    ///       mem_map.read_to_memory(32, &mut file, 128).map_err(|_| ())?;
    ///       let rand_val: u32 =  mem_map.read_obj(40).map_err(|_| ())?;
    /// #     Ok(rand_val)
    /// # }
    /// ```
    pub fn read_to_memory(
        &self,
        mut mem_offset: usize,
        src: &dyn AsRawDescriptor,
        mut count: usize,
    ) -> Result<()> {
        self.range_end(mem_offset, count)
            .map_err(|_| Error::InvalidRange(mem_offset, count, self.size()))?;
        while count > 0 {
            // The check above ensures that no memory outside this slice will get accessed by this
            // read call.
            match unsafe {
                read(
                    src.as_raw_descriptor(),
                    self.as_ptr().add(mem_offset) as *mut c_void,
                    count,
                )
            } {
                0 => {
                    return Err(Error::ReadToMemory(io::Error::from(
                        io::ErrorKind::UnexpectedEof,
                    )))
                }
                r if r < 0 => return Err(Error::ReadToMemory(io::Error::last_os_error())),
                ret => {
                    let bytes_read = ret as usize;
                    match count.checked_sub(bytes_read) {
                        Some(count_remaining) => count = count_remaining,
                        None => break,
                    }
                    mem_offset += ret as usize;
                }
            }
        }
        Ok(())
    }

    /// Writes data from memory to a file descriptor.
    ///
    /// # Arguments
    /// * `mem_offset` - Begin reading memory from this offset.
    /// * `dst` - Write from memory to `dst`.
    /// * `count` - Read `count` bytes from memory to `src`.
    ///
    /// # Examples
    ///
    /// * Write 128 bytes to /dev/null
    ///
    /// ```
    /// # use base::platform::MemoryMapping;
    /// # use std::fs::File;
    /// # use std::path::Path;
    /// # fn test_write_null() -> Result<(), ()> {
    /// #     let mut mem_map = MemoryMapping::new(1024).unwrap();
    ///       let mut file = File::open(Path::new("/dev/null")).map_err(|_| ())?;
    ///       mem_map.write_from_memory(32, &mut file, 128).map_err(|_| ())?;
    /// #     Ok(())
    /// # }
    /// ```
    pub fn write_from_memory(
        &self,
        mut mem_offset: usize,
        dst: &dyn AsRawDescriptor,
        mut count: usize,
    ) -> Result<()> {
        self.range_end(mem_offset, count)
            .map_err(|_| Error::InvalidRange(mem_offset, count, self.size()))?;
        while count > 0 {
            // The check above ensures that no memory outside this slice will get accessed by this
            // write call.
            match unsafe {
                write(
                    dst.as_raw_descriptor(),
                    self.as_ptr().add(mem_offset) as *const c_void,
                    count,
                )
            } {
                0 => {
                    return Err(Error::WriteFromMemory(io::Error::from(
                        io::ErrorKind::WriteZero,
                    )))
                }
                ret if ret < 0 => return Err(Error::WriteFromMemory(io::Error::last_os_error())),
                ret => {
                    let bytes_written = ret as usize;
                    match count.checked_sub(bytes_written) {
                        Some(count_remaining) => count = count_remaining,
                        None => break,
                    }
                    mem_offset += ret as usize;
                }
            }
        }
        Ok(())
    }

    /// Uses madvise to tell the kernel to remove the specified range.  Subsequent reads
    /// to the pages in the range will return zero bytes.
    pub fn remove_range(&self, mem_offset: usize, count: usize) -> Result<()> {
        self.range_end(mem_offset, count)
            .map_err(|_| Error::InvalidRange(mem_offset, count, self.size()))?;
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

// Send and Sync aren't automatically inherited for the raw address pointer.
// Accessing that pointer is only done through the stateless interface which
// allows the object to be shared by multiple threads without a decrease in
// safety.
unsafe impl Send for MemoryMappingArena {}
unsafe impl Sync for MemoryMappingArena {}

impl MemoryMappingArena {
    /// Creates an mmap arena of `size` bytes.
    ///
    /// # Arguments
    /// * `size` - Size of memory region in bytes.
    pub fn new(size: usize) -> Result<MemoryMappingArena> {
        // Reserve the arena's memory using an anonymous read-only mmap.
        MemoryMapping::new_protection(size, Protection::read()).map(From::from)
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

    pub fn read_to_memory(
        &self,
        mem_offset: usize,
        src: &dyn AsRawDescriptor,
        count: usize,
    ) -> Result<()> {
        self.mapping.read_to_memory(mem_offset, src, count)
    }

    pub fn write_from_memory(
        &self,
        mem_offset: usize,
        dst: &dyn AsRawDescriptor,
        count: usize,
    ) -> Result<()> {
        self.mapping.write_from_memory(mem_offset, dst, count)
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

pub trait Unix {
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

impl Unix for CrateMemoryMapping {
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
    use data_model::VolatileMemory;
    use data_model::VolatileMemoryError;
    use tempfile::tempfile;

    use super::*;
    use crate::descriptor::Descriptor;

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
}

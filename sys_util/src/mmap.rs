// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The mmap module provides a safe interface to mmap memory and ensures unmap is called when the
//! mmap object leaves scope.

use std::cmp::min;
use std::collections::BTreeMap;
use std::fmt::{self, Display};
use std::io;
use std::mem::{size_of, ManuallyDrop};
use std::os::unix::io::AsRawFd;
use std::ptr::{copy_nonoverlapping, null_mut, read_unaligned, write_unaligned};

use libc::{self, c_int, c_void, read, write};

use data_model::volatile_memory::*;
use data_model::DataInit;

use crate::{errno, pagesize};

#[derive(Debug)]
pub enum Error {
    /// Requested memory out of range.
    InvalidAddress,
    /// Requested offset is out of range of `libc::off_t`.
    InvalidOffset,
    /// Requested mapping is not page aligned
    NotPageAligned,
    /// Overlapping regions
    Overlapping(usize, usize),
    /// Requested memory range spans past the end of the region.
    InvalidRange(usize, usize, usize),
    /// `mmap` returned the given error.
    SystemCallFailed(errno::Error),
    /// Writing to memory failed
    ReadToMemory(io::Error),
    /// Reading from memory failed
    WriteFromMemory(io::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            InvalidAddress => write!(f, "requested memory out of range"),
            InvalidOffset => write!(f, "requested offset is out of range of off_t"),
            NotPageAligned => write!(f, "requested memory is not page aligned"),
            Overlapping(offset, count) => write!(
                f,
                "requested memory range overlaps with existing region: offset={} size={}",
                offset, count
            ),
            InvalidRange(offset, count, region_size) => write!(
                f,
                "requested memory range spans past the end of the region: offset={} count={} region_size={}",
                offset, count, region_size,
            ),
            SystemCallFailed(e) => write!(f, "mmap system call failed: {}", e),
            ReadToMemory(e) => write!(f, "failed to read from file to memory: {}", e),
            WriteFromMemory(e) => write!(f, "failed to write from memory to file: {}", e),
        }
    }
}

/// Memory access type for anonymous shared memory mapping.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Protection(c_int);
impl Protection {
    /// Returns Protection allowing no access.
    #[inline(always)]
    pub fn none() -> Protection {
        Protection(libc::PROT_NONE)
    }

    /// Returns Protection allowing read/write access.
    #[inline(always)]
    pub fn read_write() -> Protection {
        Protection(libc::PROT_READ | libc::PROT_WRITE)
    }

    /// Returns Protection allowing read access.
    #[inline(always)]
    pub fn read() -> Protection {
        Protection(libc::PROT_READ)
    }

    /// Set read events.
    #[inline(always)]
    pub fn set_read(self) -> Protection {
        Protection(self.0 | libc::PROT_READ)
    }

    /// Set write events.
    #[inline(always)]
    pub fn set_write(self) -> Protection {
        Protection(self.0 | libc::PROT_WRITE)
    }
}

impl From<c_int> for Protection {
    fn from(f: c_int) -> Self {
        Protection(f)
    }
}

impl Into<c_int> for Protection {
    fn into(self) -> c_int {
        self.0
    }
}

/// Wraps an anonymous shared memory mapping in the current process.
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
    pub fn from_fd(fd: &dyn AsRawFd, size: usize) -> Result<MemoryMapping> {
        MemoryMapping::from_fd_offset(fd, size, 0)
    }

    pub fn from_fd_offset(fd: &dyn AsRawFd, size: usize, offset: usize) -> Result<MemoryMapping> {
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
        fd: &dyn AsRawFd,
        size: usize,
        offset: usize,
        prot: Protection,
    ) -> Result<MemoryMapping> {
        // This is safe because we are creating an anonymous mapping in a place not already used by
        // any other area in this process.
        unsafe {
            MemoryMapping::try_mmap(
                None,
                size,
                prot.into(),
                libc::MAP_SHARED,
                Some((fd, offset)),
            )
        }
    }

    /// Creates an anonymous shared mapping of `size` bytes with `prot` protection.
    /// Unsafe: unmaps any mmap'd regions already present at (addr..addr+size).
    ///
    /// # Arguments
    /// * `addr` - Memory address to mmap at.
    /// * `size` - Size of memory region in bytes.
    /// * `prot` - Protection (e.g. readable/writable) of the memory region.
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
    /// Unsafe: unmaps any mmap'd regions already present at (addr..addr+size).
    ///
    /// # Arguments
    /// * `addr` - Memory address to mmap at.
    /// * `fd` - File descriptor to mmap from.
    /// * `size` - Size of memory region in bytes.
    /// * `offset` - Offset in bytes from the beginning of `fd` to start the mmap.
    /// * `prot` - Protection (e.g. readable/writable) of the memory region.
    pub unsafe fn from_fd_offset_protection_fixed(
        addr: *mut u8,
        fd: &dyn AsRawFd,
        size: usize,
        offset: usize,
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
        fd: Option<(&AsRawFd, usize)>,
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
                if offset > libc::off_t::max_value() as usize {
                    return Err(Error::InvalidOffset);
                }
                (fd.as_raw_fd(), offset as libc::off_t)
            }
            None => (-1, 0),
        };
        let addr = libc::mmap(addr, size, prot, flags, fd, offset);
        if addr == libc::MAP_FAILED {
            return Err(Error::SystemCallFailed(errno::Error::last()));
        }
        // This is safe because we call madvise with a valid address and size, and we check the
        // return value. We only warn about an error because failure here is not fatal to the mmap.
        if libc::madvise(addr, size, libc::MADV_DONTDUMP) == -1 {
            warn!(
                "failed madvise(MADV_DONTDUMP) on mmap: {}",
                errno::Error::last()
            );
        }
        Ok(MemoryMapping {
            addr: addr as *mut u8,
            size,
        })
    }

    /// Returns a pointer to the beginning of the memory region. Should only be
    /// used for passing this region to ioctls for setting guest memory.
    pub fn as_ptr(&self) -> *mut u8 {
        self.addr
    }

    /// Returns the size of the memory region in bytes.
    pub fn size(&self) -> usize {
        self.size
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
            return Err(Error::SystemCallFailed(errno::Error::last()));
        }
        Ok(())
    }

    /// Writes a slice to the memory region at the specified offset.
    /// Returns the number of bytes written.  The number of bytes written can
    /// be less than the length of the slice if there isn't enough room in the
    /// memory region.
    ///
    /// # Examples
    /// * Write a slice at offset 256.
    ///
    /// ```
    /// #   use sys_util::MemoryMapping;
    /// #   let mut mem_map = MemoryMapping::new(1024).unwrap();
    ///     let res = mem_map.write_slice(&[1,2,3,4,5], 256);
    ///     assert!(res.is_ok());
    ///     assert_eq!(res.unwrap(), 5);
    /// ```
    pub fn write_slice(&self, buf: &[u8], offset: usize) -> Result<usize> {
        match self.size.checked_sub(offset) {
            Some(size_past_offset) => {
                let bytes_copied = min(size_past_offset, buf.len());
                // The bytes_copied equation above ensures we don't copy bytes out of range of
                // either buf or this slice. We also know that the buffers do not overlap because
                // slices can never occupy the same memory as a volatile slice.
                unsafe {
                    copy_nonoverlapping(buf.as_ptr(), self.as_ptr().add(offset), bytes_copied);
                }
                Ok(bytes_copied)
            }
            None => Err(Error::InvalidAddress),
        }
    }

    /// Reads to a slice from the memory region at the specified offset.
    /// Returns the number of bytes read.  The number of bytes read can
    /// be less than the length of the slice if there isn't enough room in the
    /// memory region.
    ///
    /// # Examples
    /// * Read a slice of size 16 at offset 256.
    ///
    /// ```
    /// #   use sys_util::MemoryMapping;
    /// #   let mut mem_map = MemoryMapping::new(1024).unwrap();
    ///     let buf = &mut [0u8; 16];
    ///     let res = mem_map.read_slice(buf, 256);
    ///     assert!(res.is_ok());
    ///     assert_eq!(res.unwrap(), 16);
    /// ```
    pub fn read_slice(&self, buf: &mut [u8], offset: usize) -> Result<usize> {
        match self.size.checked_sub(offset) {
            Some(size_past_offset) => {
                let bytes_copied = min(size_past_offset, buf.len());
                // The bytes_copied equation above ensures we don't copy bytes out of range of
                // either buf or this slice. We also know that the buffers do not overlap because
                // slices can never occupy the same memory as a volatile slice.
                unsafe {
                    copy_nonoverlapping(
                        self.as_ptr().add(offset) as *const u8,
                        buf.as_mut_ptr(),
                        bytes_copied,
                    );
                }
                Ok(bytes_copied)
            }
            None => Err(Error::InvalidAddress),
        }
    }

    /// Writes an object to the memory region at the specified offset.
    /// Returns Ok(()) if the object fits, or Err if it extends past the end.
    ///
    /// # Examples
    /// * Write a u64 at offset 16.
    ///
    /// ```
    /// #   use sys_util::MemoryMapping;
    /// #   let mut mem_map = MemoryMapping::new(1024).unwrap();
    ///     let res = mem_map.write_obj(55u64, 16);
    ///     assert!(res.is_ok());
    /// ```
    pub fn write_obj<T: DataInit>(&self, val: T, offset: usize) -> Result<()> {
        self.range_end(offset, size_of::<T>())?;
        // This is safe because we checked the bounds above.
        unsafe {
            write_unaligned(self.as_ptr().add(offset) as *mut T, val);
        }
        Ok(())
    }

    /// Reads on object from the memory region at the given offset.
    /// Reading from a volatile area isn't strictly safe as it could change
    /// mid-read.  However, as long as the type T is plain old data and can
    /// handle random initialization, everything will be OK.
    ///
    /// # Examples
    /// * Read a u64 written to offset 32.
    ///
    /// ```
    /// #   use sys_util::MemoryMapping;
    /// #   let mut mem_map = MemoryMapping::new(1024).unwrap();
    ///     let res = mem_map.write_obj(55u64, 32);
    ///     assert!(res.is_ok());
    ///     let num: u64 = mem_map.read_obj(32).unwrap();
    ///     assert_eq!(55, num);
    /// ```
    pub fn read_obj<T: DataInit>(&self, offset: usize) -> Result<T> {
        self.range_end(offset, size_of::<T>())?;
        // This is safe because by definition Copy types can have their bits set arbitrarily and
        // still be valid.
        unsafe {
            Ok(read_unaligned(
                self.as_ptr().add(offset) as *const u8 as *const T
            ))
        }
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
    /// # use sys_util::MemoryMapping;
    /// # use std::fs::File;
    /// # use std::path::Path;
    /// # fn test_read_random() -> Result<u32, ()> {
    /// #     let mut mem_map = MemoryMapping::new(1024).unwrap();
    ///       let mut file = File::open(Path::new("/dev/urandom")).map_err(|_| ())?;
    ///       mem_map.read_to_memory(32, &mut file, 128).map_err(|_| ())?;
    ///       let rand_val: u32 =  mem_map.read_obj(40).map_err(|_| ())?;
    /// #     Ok(rand_val)
    /// # }
    /// ```
    pub fn read_to_memory(
        &self,
        mut mem_offset: usize,
        src: &AsRawFd,
        mut count: usize,
    ) -> Result<()> {
        self.range_end(mem_offset, count)
            .map_err(|_| Error::InvalidRange(mem_offset, count, self.size()))?;
        while count > 0 {
            // The check above ensures that no memory outside this slice will get accessed by this
            // read call.
            match unsafe {
                read(
                    src.as_raw_fd(),
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
    /// # use sys_util::MemoryMapping;
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
        dst: &AsRawFd,
        mut count: usize,
    ) -> Result<()> {
        self.range_end(mem_offset, count)
            .map_err(|_| Error::InvalidRange(mem_offset, count, self.size()))?;
        while count > 0 {
            // The check above ensures that no memory outside this slice will get accessed by this
            // write call.
            match unsafe {
                write(
                    dst.as_raw_fd(),
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
            Err(Error::InvalidRange(mem_offset, count, self.size()))
        } else {
            Ok(())
        }
    }

    // Check that offset+count is valid and return the sum.
    fn range_end(&self, offset: usize, count: usize) -> Result<usize> {
        let mem_end = offset.checked_add(count).ok_or(Error::InvalidAddress)?;
        if mem_end > self.size() {
            return Err(Error::InvalidAddress);
        }
        Ok(mem_end)
    }
}

impl VolatileMemory for MemoryMapping {
    fn get_slice(&self, offset: u64, count: u64) -> VolatileMemoryResult<VolatileSlice> {
        let mem_end = calc_offset(offset, count)?;
        if mem_end > self.size as u64 {
            return Err(VolatileMemoryError::OutOfBounds { addr: mem_end });
        }

        // Safe because we checked that offset + count was within our range and we only ever hand
        // out volatile accessors.
        Ok(unsafe { VolatileSlice::new((self.addr as usize + offset as usize) as *mut _, count) })
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
    // When doing in-place swaps of MemoryMappings, the BTreeMap returns a owned
    // instance of the old MemoryMapping. When the old MemoryMapping falls out
    // of scope, it calls munmap on the same region as the new MemoryMapping
    // that was just mapped in. To avoid accidentally munmapping the new,
    // MemoryMapping, all mappings are wrapped in a ManuallyDrop, and then
    // "forgotten" when removed from the BTreeMap
    maps: BTreeMap<usize, ManuallyDrop<MemoryMapping>>,
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
        // The actual MemoryMapping object is forgotten, with
        // MemoryMappingArena manually calling munmap on drop.
        let mmap = MemoryMapping::new_protection(size, Protection::none().set_read())?;
        let addr = mmap.as_ptr();
        let size = mmap.size();
        std::mem::forget(mmap);
        Ok(MemoryMappingArena {
            addr,
            size,
            maps: BTreeMap::new(),
        })
    }

    /// Anonymously maps `size` bytes at `offset` bytes from the start of the arena.
    /// `offset` must be page aligned.
    ///
    /// # Arguments
    /// * `offset` - Page aligned offset into the arena in bytes.
    /// * `size` - Size of memory region in bytes.
    /// * `fd` - File descriptor to mmap from.
    pub fn add_anon(&mut self, offset: usize, size: usize) -> Result<()> {
        self.try_add(offset, size, Protection::read_write(), None)
    }

    /// Maps `size` bytes from the start of the given `fd` at `offset` bytes from
    /// the start of the arena. `offset` must be page aligned.
    ///
    /// # Arguments
    /// * `offset` - Page aligned offset into the arena in bytes.
    /// * `size` - Size of memory region in bytes.
    /// * `fd` - File descriptor to mmap from.
    pub fn add_fd(&mut self, offset: usize, size: usize, fd: &dyn AsRawFd) -> Result<()> {
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
        fd: &dyn AsRawFd,
        fd_offset: usize,
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
        fd: &dyn AsRawFd,
        fd_offset: usize,
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
        fd: Option<(&AsRawFd, usize)>,
    ) -> Result<()> {
        self.validate_range(offset, size)?;

        // This is safe since the range has been validated.
        let mmap = unsafe {
            match fd {
                Some((fd, fd_offset)) => MemoryMapping::from_fd_offset_protection_fixed(
                    (self.addr as usize + offset) as *mut u8,
                    fd,
                    size,
                    fd_offset,
                    prot,
                )?,
                None => MemoryMapping::new_protection_fixed(
                    (self.addr as usize + offset) as *mut u8,
                    size,
                    prot,
                )?,
            }
        };

        self.maps.insert(offset, ManuallyDrop::new(mmap));
        Ok(())
    }

    /// Removes a mapping at `offset` from the start of the arena.
    /// Returns a boolean indicating if there was a mapping present at `offset`.
    /// If none was present, this method is a noop.
    pub fn remove(&mut self, offset: usize) -> Result<bool> {
        if let Some(mmap) = self.maps.remove(&offset) {
            // Instead of munmapping the memory map, leaving an unprotected hole
            // in the arena, swap this mmap with an anonymous protection.
            // This is safe since the memory mapping perfectly overlaps with an
            // existing, known good memory mapping.
            let mmap = unsafe {
                MemoryMapping::new_protection_fixed(
                    mmap.as_ptr(),
                    mmap.size(),
                    Protection::none().set_read(),
                )?
            };
            self.maps.insert(offset, ManuallyDrop::new(mmap));
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Calls msync with MS_SYNC on the mapping at `offset` from the start of
    /// the arena.
    /// Returns a boolean indicating if there was a mapping present at `offset`.
    /// If none was present, this method is a noop.
    pub fn msync(&self, offset: usize) -> Result<bool> {
        if let Some(mmap) = self.maps.get(&offset) {
            mmap.msync()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Returns a pointer to the beginning of the memory region.  Should only be
    /// used for passing this region to ioctls for setting guest memory.
    pub fn as_ptr(&self) -> *mut u8 {
        self.addr
    }

    /// Returns the size of the memory region in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Validates `offset` and `size`.
    /// Checks that offset..offset+size doesn't overlap with existing mappings.
    /// Also ensures correct alignment, and checks for any overflow.
    /// Note: offset..offset+size is considered valid if it _perfectly_ overlaps
    /// with single other region.
    fn validate_range(&self, offset: usize, size: usize) -> Result<()> {
        // Ensure offset is page-aligned
        if offset % pagesize() != 0 {
            return Err(Error::NotPageAligned);
        }
        // Ensure offset + size doesn't overflow
        let end_offset = offset.checked_add(size).ok_or(Error::InvalidAddress)?;
        // Ensure offset + size are within the arena bounds
        if end_offset > self.size {
            return Err(Error::InvalidAddress);
        }
        // Ensure offset..offset+size doesn't overlap with existing regions
        // Find the offset + size of the first mapping before the desired offset
        let (prev_offset, prev_size) = match self.maps.range(..offset).rev().next() {
            Some((offset, mmap)) => (*offset, mmap.size()),
            None => {
                // Empty map
                return Ok(());
            }
        };
        if offset == prev_offset {
            // Perfectly overlapping regions are allowed
            if size != prev_size {
                return Err(Error::Overlapping(offset, size));
            }
        } else if offset < (prev_offset + prev_size) {
            return Err(Error::Overlapping(offset, size));
        }

        Ok(())
    }
}

impl Drop for MemoryMappingArena {
    fn drop(&mut self) {
        // This is safe because we mmap the area at addr ourselves, and nobody
        // else is holding a reference to it.
        unsafe {
            libc::munmap(self.addr as *mut libc::c_void, self.size);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_model::{VolatileMemory, VolatileMemoryError};
    use std::os::unix::io::FromRawFd;

    #[test]
    fn basic_map() {
        let m = MemoryMapping::new(1024).unwrap();
        assert_eq!(1024, m.size());
    }

    #[test]
    fn map_invalid_size() {
        let res = MemoryMapping::new(0).unwrap_err();
        if let Error::SystemCallFailed(e) = res {
            assert_eq!(e.errno(), libc::EINVAL);
        } else {
            panic!("unexpected error: {}", res);
        }
    }

    #[test]
    fn map_invalid_fd() {
        let fd = unsafe { std::fs::File::from_raw_fd(-1) };
        let res = MemoryMapping::from_fd(&fd, 1024).unwrap_err();
        if let Error::SystemCallFailed(e) = res {
            assert_eq!(e.errno(), libc::EBADF);
        } else {
            panic!("unexpected error: {}", res);
        }
    }

    #[test]
    fn test_write_past_end() {
        let m = MemoryMapping::new(5).unwrap();
        let res = m.write_slice(&[1, 2, 3, 4, 5, 6], 0);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 5);
    }

    #[test]
    fn slice_size() {
        let m = MemoryMapping::new(5).unwrap();
        let s = m.get_slice(2, 3).unwrap();
        assert_eq!(s.size(), 3);
    }

    #[test]
    fn slice_addr() {
        let m = MemoryMapping::new(5).unwrap();
        let s = m.get_slice(2, 3).unwrap();
        assert_eq!(s.as_ptr(), unsafe { m.as_ptr().offset(2) });
    }

    #[test]
    fn slice_store() {
        let m = MemoryMapping::new(5).unwrap();
        let r = m.get_ref(2).unwrap();
        r.store(9u16);
        assert_eq!(m.read_obj::<u16>(2).unwrap(), 9);
    }

    #[test]
    fn slice_overflow_error() {
        let m = MemoryMapping::new(5).unwrap();
        let res = m.get_slice(std::u64::MAX, 3).unwrap_err();
        assert_eq!(
            res,
            VolatileMemoryError::Overflow {
                base: std::u64::MAX,
                offset: 3,
            }
        );
    }
    #[test]
    fn slice_oob_error() {
        let m = MemoryMapping::new(5).unwrap();
        let res = m.get_slice(3, 3).unwrap_err();
        assert_eq!(res, VolatileMemoryError::OutOfBounds { addr: 6 });
    }

    #[test]
    fn from_fd_offset_invalid() {
        let fd = unsafe { std::fs::File::from_raw_fd(-1) };
        let res = MemoryMapping::from_fd_offset(&fd, 4096, (libc::off_t::max_value() as usize) + 1)
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
        assert!(m.remove(0).unwrap(), true);
        assert!(m.remove(0).unwrap(), false);
    }

    #[test]
    fn arena_add_overlap_error() {
        let page = pagesize();
        let mut m = MemoryMappingArena::new(page * 4).unwrap();
        assert!(m.add_anon(0, page * 4).is_ok());
        let res = m.add_anon(page, page).unwrap_err();
        match res {
            Error::Overlapping(a, o) => {
                assert_eq!((a, o), (page, page));
            }
            e => panic!("unexpected error: {}", e),
        }
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
}

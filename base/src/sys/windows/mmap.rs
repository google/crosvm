// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use remain::sorted;
use std::{
    cmp::min,
    io,
    mem::size_of,
    ptr::{copy_nonoverlapping, read_unaligned, write_unaligned},
};

use data_model::{volatile_memory::*, DataInit};

use libc::{c_int, c_uint, c_void};

use super::RawDescriptor;
use crate::descriptor::{AsRawDescriptor, Descriptor};
use crate::external_mapping::ExternalMapping;

#[path = "win/mmap.rs"]
mod mmap_platform;
pub use mmap_platform::MemoryMappingArena;

#[sorted]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("`add_fd_mapping` is unsupported")]
    AddFdMappingIsUnsupported,
    #[error("requested memory out of range")]
    InvalidAddress,
    #[error("invalid argument provided when creating mapping")]
    InvalidArgument,
    #[error("requested offset is out of range of off_t")]
    InvalidOffset,
    #[error("requested memory range spans past the end of the region: offset={0} count={1} region_size={2}")]
    InvalidRange(usize, usize, usize),
    #[error("requested memory is not page aligned")]
    NotPageAligned,
    #[error("failed to read from file to memory: {0}")]
    ReadToMemory(#[source] io::Error),
    #[error("`remove_mapping` is unsupported")]
    RemoveMappingIsUnsupported,
    #[error("system call failed while creating the mapping: {0}")]
    StdSyscallFailed(io::Error),
    #[error("mmap related system call failed: {0}")]
    SystemCallFailed(#[source] super::Error),
    #[error("failed to write from memory to file: {0}")]
    WriteFromMemory(#[source] io::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

/// Memory access type for anonymous shared memory mapping.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Protection(c_uint);

impl Protection {
    /// Returns Protection allowing no access. Note that on Windows this is not a
    /// viable state and will return an error if used for mapping. It exists only
    /// to serve as a base protection to set READ or WRITE on.
    #[inline(always)]
    pub fn none() -> Protection {
        Protection(mmap_platform::PROT_NONE)
    }

    /// Returns Protection allowing read/write access.
    #[inline(always)]
    pub fn read_write() -> Protection {
        Protection(mmap_platform::PROT_READ | mmap_platform::PROT_WRITE)
    }

    /// Returns Protection allowing read access.
    #[inline(always)]
    pub fn read() -> Protection {
        Protection(mmap_platform::PROT_READ)
    }

    /// Set read events.
    #[inline(always)]
    pub fn set_read(self) -> Protection {
        Protection(self.0 | mmap_platform::PROT_READ)
    }

    /// Set write events.
    #[inline(always)]
    pub fn set_write(self) -> Protection {
        Protection(self.0 | mmap_platform::PROT_WRITE)
    }
}

impl From<c_uint> for Protection {
    fn from(f: c_uint) -> Self {
        Protection(f)
    }
}

impl From<Protection> for c_uint {
    fn from(p: Protection) -> c_uint {
        p.0 as c_uint
    }
}

impl From<c_int> for Protection {
    fn from(f: c_int) -> Self {
        Protection(f as c_uint)
    }
}

impl From<Protection> for c_int {
    fn from(p: Protection) -> c_int {
        p.0 as c_int
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

/// A range of memory that can be msynced, for abstracting over different types of memory mappings.
///
/// Safe when implementers guarantee `ptr`..`ptr+size` is an mmaped region owned by this object that
/// can't be unmapped during the `MappedRegion`'s lifetime.
pub unsafe trait MappedRegion: Send + Sync {
    /// Returns a pointer to the beginning of the memory region. Should only be
    /// used for passing this region to ioctls for setting guest memory.
    fn as_ptr(&self) -> *mut u8;

    /// Returns the size of the memory region in bytes.
    fn size(&self) -> usize;

    /// Maps `size` bytes starting at `fd_offset` bytes from within the given `fd`
    /// at `offset` bytes from the start of the region with `prot` protections.
    /// `offset` must be page aligned.
    ///
    /// # Arguments
    /// * `offset` - Page aligned offset into the arena in bytes.
    /// * `size` - Size of memory region in bytes.
    /// * `fd` - File descriptor to mmap from.
    /// * `fd_offset` - Offset in bytes from the beginning of `fd` to start the mmap.
    /// * `prot` - Protection (e.g. readable/writable) of the memory region.
    fn add_fd_mapping(
        &mut self,
        _offset: usize,
        _size: usize,
        _fd: &dyn AsRawDescriptor,
        _fd_offset: u64,
        _prot: Protection,
    ) -> Result<()> {
        Err(Error::AddFdMappingIsUnsupported)
    }

    /// Remove `size`-byte mapping starting at `offset`.
    fn remove_mapping(&mut self, _offset: usize, _size: usize) -> Result<()> {
        Err(Error::RemoveMappingIsUnsupported)
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
            use winapi::um::memoryapi::FlushViewOfFile;
            if FlushViewOfFile((self.as_ptr() as usize + offset) as *mut libc::c_void, size) == 0 {
                -1
            } else {
                0
            }
        };
        if ret != -1 {
            Ok(())
        } else {
            Err(Error::SystemCallFailed(super::Error::last()))
        }
    }
}

/// Wraps an anonymous shared memory mapping in the current process. Provides
/// RAII semantics including munmap when no longer needed.
#[derive(Debug)]
pub struct MemoryMapping {
    addr: *mut c_void,
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

    /// Maps the first `size` bytes of the given `descriptor` as read/write.
    ///
    /// # Arguments
    /// * `file_handle` - File handle to map from.
    /// * `size` - Size of memory region in bytes.
    pub fn from_descriptor(
        file_handle: &dyn AsRawDescriptor,
        size: usize,
    ) -> Result<MemoryMapping> {
        MemoryMapping::from_descriptor_offset(file_handle, size, 0)
    }

    pub fn from_raw_descriptor(file_handle: RawDescriptor, size: usize) -> Result<MemoryMapping> {
        MemoryMapping::from_descriptor_offset(&Descriptor(file_handle), size, 0)
    }

    pub fn from_descriptor_offset(
        file_handle: &dyn AsRawDescriptor,
        size: usize,
        offset: u64,
    ) -> Result<MemoryMapping> {
        MemoryMapping::from_descriptor_offset_protection(
            file_handle,
            size,
            offset,
            Protection::read_write(),
        )
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
    ///     use crate::platform::MemoryMapping;
    ///     use crate::platform::SharedMemory;
    ///     let mut mem_map = MemoryMapping::from_descriptor(
    ///         &SharedMemory::anon(1024).unwrap(), 1024).unwrap();
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
    ///     use crate::platform::MemoryMapping;
    ///     use crate::platform::SharedMemory;
    ///     let mut mem_map = MemoryMapping::from_descriptor(
    ///         &SharedMemory::anon(1024).unwrap(), 1024).unwrap();
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
    ///     use crate::platform::MemoryMapping;
    ///     use crate::platform::SharedMemory;
    ///     let mut mem_map = MemoryMapping::from_descriptor(
    ///         &SharedMemory::anon(1024).unwrap(), 1024).unwrap();
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
    ///     use crate::platform::MemoryMapping;
    ///     use crate::platform::SharedMemory;
    ///     let mut mem_map = MemoryMapping::from_descriptor(
    ///         &SharedMemory::anon(1024).unwrap(), 1024).unwrap();
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

    // Check that offset+count is valid and return the sum.
    fn range_end(&self, offset: usize, count: usize) -> Result<usize> {
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
        self.addr as *mut u8
    }

    fn size(&self) -> usize {
        self.size
    }
}

unsafe impl MappedRegion for ExternalMapping {
    /// used for passing this region to ioctls for setting guest memory.
    fn as_ptr(&self) -> *mut u8 {
        self.as_ptr()
    }

    /// Returns the size of the memory region in bytes.
    fn size(&self) -> usize {
        self.size()
    }
}

impl VolatileMemory for MemoryMapping {
    fn get_slice(&self, offset: usize, count: usize) -> VolatileMemoryResult<VolatileSlice> {
        let mem_end = calc_offset(offset, count)?;
        if mem_end > self.size {
            return Err(VolatileMemoryError::OutOfBounds { addr: mem_end });
        }

        let new_addr =
            (self.as_ptr() as usize)
                .checked_add(offset)
                .ok_or(VolatileMemoryError::Overflow {
                    base: self.as_ptr() as usize,
                    offset,
                })?;

        // Safe because we checked that offset + count was within our range and we only ever hand
        // out volatile accessors.
        Ok(unsafe { VolatileSlice::from_raw_parts(new_addr as *mut u8, count) })
    }
}

#[cfg(test)]
mod tests {
    use super::{super::shm::SharedMemory, *};
    use data_model::{VolatileMemory, VolatileMemoryError};

    #[test]
    fn basic_map() {
        let shm = SharedMemory::anon(1028).unwrap();
        let m = MemoryMapping::from_descriptor(&shm, 1024).unwrap();
        assert_eq!(1024, m.size());
    }

    #[test]
    fn test_write_past_end() {
        let shm = SharedMemory::anon(1028).unwrap();
        let m = MemoryMapping::from_descriptor(&shm, 5).unwrap();
        let res = m.write_slice(&[1, 2, 3, 4, 5, 6], 0);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 5);
    }

    #[test]
    fn slice_size() {
        let shm = SharedMemory::anon(1028).unwrap();
        let m = MemoryMapping::from_descriptor(&shm, 5).unwrap();
        let s = m.get_slice(2, 3).unwrap();
        assert_eq!(s.size(), 3);
    }

    #[test]
    fn slice_addr() {
        let shm = SharedMemory::anon(1028).unwrap();
        let m = MemoryMapping::from_descriptor(&shm, 5).unwrap();
        let s = m.get_slice(2, 3).unwrap();
        assert_eq!(s.as_ptr(), unsafe { m.as_ptr().offset(2) });
    }

    #[test]
    fn slice_store() {
        let shm = SharedMemory::anon(1028).unwrap();
        let m = MemoryMapping::from_descriptor(&shm, 5).unwrap();
        let r = m.get_ref(2).unwrap();
        r.store(9u16);
        assert_eq!(m.read_obj::<u16>(2).unwrap(), 9);
    }

    #[test]
    fn slice_overflow_error() {
        let shm = SharedMemory::anon(1028).unwrap();
        let m = MemoryMapping::from_descriptor(&shm, 5).unwrap();
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
        let shm = SharedMemory::anon(1028).unwrap();
        let m = MemoryMapping::from_descriptor(&shm, 5).unwrap();
        let res = m.get_slice(3, 3).unwrap_err();
        assert_eq!(res, VolatileMemoryError::OutOfBounds { addr: 6 });
    }
}

// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The mmap module provides a safe interface to map memory and ensures UnmapViewOfFile is called when the
//! mmap object leaves scope.

use std::{
    io,
    slice::{from_raw_parts, from_raw_parts_mut},
};

use libc::{
    c_uint, c_void, {self},
};

use win_util::{allocation_granularity, get_high_order, get_low_order};
use winapi::um::memoryapi::{
    FlushViewOfFile, MapViewOfFile, MapViewOfFileEx, UnmapViewOfFile, FILE_MAP_READ, FILE_MAP_WRITE,
};

use super::{super::RawDescriptor, Error, MappedRegion, MemoryMapping, Protection, Result};
use crate::descriptor::AsRawDescriptor;
use crate::warn;

pub(super) const PROT_NONE: c_uint = 0;
pub(super) const PROT_READ: c_uint = FILE_MAP_READ;
pub(super) const PROT_WRITE: c_uint = FILE_MAP_WRITE;

impl MemoryMapping {
    /// Creates an anonymous shared mapping of `size` bytes with `prot` protection.
    ///
    /// # Arguments
    /// * `size` - Size of memory region in bytes.
    /// * `prot` - Protection (e.g. readable/writable) of the memory region.
    pub fn new_protection(size: usize, prot: Protection) -> Result<MemoryMapping> {
        // This is safe because we are creating an anonymous mapping in a place not already used by
        // any other area in this process.
        unsafe { MemoryMapping::try_mmap(None, size, prot.into(), None) }
    }

    /// Create a Memory mapping from a raw address returned by
    /// the kernel.
    /// # Arguments
    /// * `addr` - Raw pointer to memory region.
    /// * `size` - Size of memory region in bytes.
    pub fn from_raw_ptr(addr: *mut c_void, size: usize) -> Result<MemoryMapping> {
        Ok(MemoryMapping { addr, size })
    }

    pub fn from_raw_handle_offset(
        file_handle: RawDescriptor,
        size: usize,
    ) -> Result<MemoryMapping> {
        // This is safe because we are creating an anonymous mapping in a place not already used by
        // any other area in this process.
        unsafe {
            MemoryMapping::try_mmap(
                None,
                size,
                Protection::read_write().into(),
                Some((file_handle, 0)),
            )
        }
    }

    /// Maps the `size` bytes starting at `offset` bytes of the given `descriptor` as read/write.
    ///
    /// # Arguments
    /// * `file_handle` - File handle to map from.
    /// * `size` - Size of memory region in bytes.
    /// * `offset` - Offset in bytes from the beginning of `descriptor` to start the mmap.
    /// * `prot` - Protection (e.g. readable/writable) of the memory region.
    pub fn from_descriptor_offset_protection(
        file_handle: &dyn AsRawDescriptor,
        size: usize,
        offset: u64,
        prot: Protection,
    ) -> Result<MemoryMapping> {
        // This is safe because we are creating an anonymous mapping in a place not already used by
        // any other area in this process.
        unsafe {
            MemoryMapping::try_mmap(
                None,
                size,
                prot.into(),
                Some((file_handle.as_raw_descriptor(), offset)),
            )
        }
    }

    /// Creates an anonymous shared mapping of `size` bytes with `prot` protection.
    ///
    /// # Safety
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
        MemoryMapping::try_mmap(Some(addr), size, prot.into(), None)
    }

    /// Maps the `size` bytes starting at `offset` bytes of the given `descriptor` with
    /// `prot` protections.
    ///
    /// # Safety
    /// Unsafe: unmaps any mmap'd regions already present at (addr..addr+size).
    ///
    /// # Arguments
    /// * `addr` - Memory address to mmap at.
    /// * `descriptor` - File descriptor to mmap from.
    /// * `size` - Size of memory region in bytes.
    /// * `offset` - Offset in bytes from the beginning of `descriptor` to start the mmap.
    /// * `prot` - Protection (e.g. readable/writable) of the memory region.
    pub unsafe fn from_descriptor_offset_protection_fixed(
        addr: *mut u8,
        descriptor: &dyn AsRawDescriptor,
        size: usize,
        offset: u64,
        prot: Protection,
    ) -> Result<MemoryMapping> {
        MemoryMapping::try_mmap(
            Some(addr),
            size,
            prot.into(),
            Some((descriptor.as_raw_descriptor(), offset)),
        )
    }

    /// Calls MapViewOfFile/MapViewOfFileEx with the parameters given
    unsafe fn try_mmap(
        addr: Option<*mut u8>,
        size: usize,
        access_flags: c_uint,
        file_handle: Option<(RawDescriptor, u64)>,
    ) -> Result<MemoryMapping> {
        if file_handle.is_none() {
            // TODO(mikehoyle): For now, do not allow the no-handle scenario. As per comments
            // in guest_memory, the no-handle case is for legacy support and shouldn't have
            // significant usage.
            return Err(Error::InvalidAddress);
        }
        let file_handle = file_handle.unwrap();

        // on windows, pages needed to be of fixed granular size, and the
        // maximum valid value is an i64.
        if file_handle.1 % allocation_granularity() != 0 || file_handle.1 > i64::max_value() as u64
        {
            return Err(Error::InvalidOffset);
        }

        let created_address = match addr {
            Some(addr) => MapViewOfFileEx(
                file_handle.0,
                access_flags,
                get_high_order(file_handle.1),
                get_low_order(file_handle.1),
                size,
                addr as *mut c_void,
            ),
            None => MapViewOfFile(
                file_handle.0,
                access_flags,
                get_high_order(file_handle.1),
                get_low_order(file_handle.1),
                size,
            ),
        };

        if created_address.is_null() {
            return Err(Error::SystemCallFailed(super::super::Error::last()));
        }

        Ok(MemoryMapping {
            addr: created_address,
            size,
        })
    }

    /// Calls FlushViewOfFile on the mapped memory range, ensuring all changes that would
    /// be written to disk are written immediately
    pub fn msync(&self) -> Result<()> {
        // Safe because self can only be created as a successful memory mapping
        unsafe {
            if FlushViewOfFile(self.addr, self.size) == 0 {
                return Err(Error::SystemCallFailed(super::super::Error::last()));
            }
        };
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
    ///   use crate::platform::MemoryMapping;
    ///   use crate::platform::SharedMemory;
    ///   use std::fs::File;
    ///   use std::path::Path;
    ///   fn test_read_random() -> Result<u32, ()> {
    ///       let mut mem_map = MemoryMapping::from_descriptor(
    ///         &SharedMemory::anon(1024).unwrap(), 1024).unwrap();
    ///       let mut file = File::open(Path::new("/dev/urandom")).map_err(|_| ())?;
    ///       mem_map.read_to_memory(32, &mut file, 128).map_err(|_| ())?;
    ///       let rand_val: u32 =  mem_map.read_obj(40).map_err(|_| ())?;
    ///       Ok(rand_val)
    ///   }
    /// ```
    pub fn read_to_memory<F: io::Read>(
        &self,
        mem_offset: usize,
        src: &mut F,
        count: usize,
    ) -> Result<()> {
        self.range_end(mem_offset, count)
            .map_err(|_| Error::InvalidRange(mem_offset, count, self.size()))?;
        // Safe because the check above ensures that no memory outside this slice will get accessed
        // by this read call.
        let buf: &mut [u8] = unsafe { from_raw_parts_mut(self.as_ptr().add(mem_offset), count) };
        match src.read_exact(buf) {
            Err(e) => Err(Error::ReadToMemory(e)),
            Ok(()) => Ok(()),
        }
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
    ///   use crate::platform::MemoryMapping;
    ///   use crate::platform::SharedMemory;
    ///   use std::fs::File;
    ///   use std::path::Path;
    ///   fn test_write_null() -> Result<(), ()> {
    ///       let mut mem_map = MemoryMapping::from_descriptor(
    ///           &SharedMemory::anon(1024).unwrap(), 1024).unwrap();
    ///       let mut file = File::open(Path::new("/dev/null")).map_err(|_| ())?;
    ///       mem_map.write_from_memory(32, &mut file, 128).map_err(|_| ())?;
    ///       Ok(())
    ///   }
    /// ```
    pub fn write_from_memory<F: io::Write>(
        &self,
        mem_offset: usize,
        dst: &mut F,
        count: usize,
    ) -> Result<()> {
        self.range_end(mem_offset, count)
            .map_err(|_| Error::InvalidRange(mem_offset, count, self.size()))?;
        // Safe because the check above ensures that no memory outside this slice will get accessed
        // by this write call.
        let buf: &[u8] = unsafe { from_raw_parts(self.as_ptr().add(mem_offset), count) };
        match dst.write_all(buf) {
            Err(e) => Err(Error::WriteFromMemory(e)),
            Ok(()) => Ok(()),
        }
    }
}

impl Drop for MemoryMapping {
    fn drop(&mut self) {
        // This is safe because we MapViewOfFile the area at addr ourselves, and nobody
        // else is holding a reference to it.
        unsafe {
            if UnmapViewOfFile(self.addr) == 0 {
                warn!(
                    "Unsuccessful unmap of file: {}",
                    super::super::Error::last()
                );
            }
        }
    }
}

/// TODO(b/150415526): This is currently an empty implementation to allow simple usages in
/// shared structs. Any attempts to use it will result in compiler errors. It will need
/// to be ported to actually be used on Windows.
pub struct MemoryMappingArena();

#[cfg(test)]
mod tests {
    use super::{
        super::super::{pagesize, SharedMemory},
        *,
    };
    use crate::descriptor::FromRawDescriptor;
    use data_model::{VolatileMemory, VolatileMemoryError};
    use std::ptr;
    use winapi::shared::winerror;

    #[test]
    fn basic_map() {
        let shm = SharedMemory::anon(1028).unwrap();
        let m = MemoryMapping::from_descriptor(&shm, 1024).unwrap();
        assert_eq!(1024, m.size());
    }

    #[test]
    fn map_invalid_fd() {
        let descriptor = unsafe { std::fs::File::from_raw_descriptor(ptr::null_mut()) };
        let res = MemoryMapping::from_descriptor(&descriptor, 1024).unwrap_err();
        if let Error::SystemCallFailed(e) = res {
            assert_eq!(e.errno(), winerror::ERROR_INVALID_HANDLE as i32);
        } else {
            panic!("unexpected error: {}", res);
        }
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

    #[test]
    fn from_descriptor_offset_invalid() {
        let shm = SharedMemory::anon(1028).unwrap();
        let res = MemoryMapping::from_descriptor_offset(&shm, 4096, (i64::max_value() as u64) + 1)
            .unwrap_err();
        match res {
            Error::InvalidOffset => {}
            e => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn arena_msync() {
        let size: usize = 0x40000;
        let shm = SharedMemory::anon(size as u64).unwrap();
        let m = MemoryMapping::from_descriptor(&shm, size).unwrap();
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

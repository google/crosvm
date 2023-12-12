// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The mmap module provides a safe interface to map memory and ensures UnmapViewOfFile is called when the
//! mmap object leaves scope.

use libc::c_void;
use win_util::get_high_order;
use win_util::get_low_order;
use winapi::shared::minwindef::DWORD;
use winapi::um::memoryapi::FlushViewOfFile;
use winapi::um::memoryapi::MapViewOfFile;
use winapi::um::memoryapi::MapViewOfFileEx;
use winapi::um::memoryapi::UnmapViewOfFile;
use winapi::um::memoryapi::FILE_MAP_READ;
use winapi::um::memoryapi::FILE_MAP_WRITE;

use super::allocation_granularity;
use super::mmap::MemoryMapping;
use crate::descriptor::AsRawDescriptor;
use crate::warn;
use crate::MmapError as Error;
use crate::MmapResult as Result;
use crate::Protection;
use crate::RawDescriptor;

impl From<Protection> for DWORD {
    #[inline(always)]
    fn from(p: Protection) -> Self {
        let mut value = 0;
        if p.read {
            value |= FILE_MAP_READ;
        }
        if p.write {
            value |= FILE_MAP_WRITE;
        }
        value
    }
}

impl MemoryMapping {
    /// Creates an anonymous shared mapping of `size` bytes with `prot` protection.
    ///
    /// # Arguments
    /// * `size` - Size of memory region in bytes.
    /// * `prot` - Protection (e.g. readable/writable) of the memory region.
    pub fn new_protection(size: usize, prot: Protection) -> Result<MemoryMapping> {
        // SAFETY:
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
        // SAFETY:
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
        // SAFETY:
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
        access_flags: DWORD,
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
            return Err(Error::SystemCallFailed(super::Error::last()));
        }

        Ok(MemoryMapping {
            addr: created_address,
            size,
        })
    }

    /// Calls FlushViewOfFile on the mapped memory range, ensuring all changes that would
    /// be written to disk are written immediately
    pub fn msync(&self) -> Result<()> {
        // SAFETY:
        // Safe because self can only be created as a successful memory mapping
        unsafe {
            if FlushViewOfFile(self.addr, self.size) == 0 {
                return Err(Error::SystemCallFailed(super::Error::last()));
            }
        };
        Ok(())
    }
}

impl Drop for MemoryMapping {
    fn drop(&mut self) {
        // SAFETY:
        // This is safe because we MapViewOfFile the area at addr ourselves, and nobody
        // else is holding a reference to it.
        unsafe {
            if UnmapViewOfFile(self.addr) == 0 {
                warn!("Unsuccessful unmap of file: {}", super::Error::last());
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
    use std::ptr;

    use winapi::shared::winerror;

    use super::super::pagesize;
    use super::Error;
    use crate::descriptor::FromRawDescriptor;
    use crate::MappedRegion;
    use crate::MemoryMappingBuilder;
    use crate::SharedMemory;

    #[test]
    fn map_invalid_fd() {
        // SAFETY: trivially safe to create an invalid File.
        let descriptor = unsafe { std::fs::File::from_raw_descriptor(ptr::null_mut()) };
        let res = MemoryMappingBuilder::new(1024)
            .from_file(&descriptor)
            .build()
            .unwrap_err();
        if let Error::StdSyscallFailed(e) = res {
            assert_eq!(
                e.raw_os_error(),
                Some(winerror::ERROR_INVALID_HANDLE as i32)
            );
        } else {
            panic!("unexpected error: {}", res);
        }
    }

    #[test]
    fn from_descriptor_offset_invalid() {
        let shm = SharedMemory::new("test", 1028).unwrap();
        let res = MemoryMappingBuilder::new(4096)
            .from_shared_memory(&shm)
            .offset((i64::max_value() as u64) + 1)
            .build()
            .unwrap_err();
        match res {
            Error::InvalidOffset => {}
            e => panic!("unexpected error: {}", e),
        }
    }

    #[test]
    fn arena_msync() {
        let size: usize = 0x40000;
        let shm = SharedMemory::new("test", size as u64).unwrap();
        let m = MemoryMappingBuilder::new(size)
            .from_shared_memory(&shm)
            .build()
            .unwrap();
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

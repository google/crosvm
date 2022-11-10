// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::min;
use std::fs::File;
use std::intrinsics::copy_nonoverlapping;
use std::mem::size_of;
use std::ptr::read_unaligned;
use std::ptr::read_volatile;
use std::ptr::write_unaligned;
use std::ptr::write_volatile;
use std::sync::atomic::fence;
use std::sync::atomic::Ordering;

use data_model::volatile_memory::*;
use data_model::DataInit;
use libc::c_int;
use serde::Deserialize;
use serde::Serialize;

use crate::descriptor::AsRawDescriptor;
use crate::descriptor::SafeDescriptor;
use crate::platform::MemoryMapping as PlatformMmap;
use crate::platform::MmapError as Error;
use crate::platform::PROT_READ;
use crate::platform::PROT_WRITE;
use crate::SharedMemory;

pub type Result<T> = std::result::Result<T, Error>;

/// Memory access type for anonymous shared memory mapping.
#[derive(Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct Protection(c_int);
impl Protection {
    /// Returns Protection allowing read/write access.
    #[inline(always)]
    pub fn read_write() -> Protection {
        Protection(PROT_READ | PROT_WRITE)
    }

    /// Returns Protection allowing read access.
    #[inline(always)]
    pub fn read() -> Protection {
        Protection(PROT_READ)
    }

    /// Returns Protection allowing write access.
    #[inline(always)]
    pub fn write() -> Protection {
        Protection(PROT_WRITE)
    }

    /// Set read events.
    #[inline(always)]
    pub fn set_read(self) -> Protection {
        Protection(self.0 | PROT_READ)
    }

    /// Set write events.
    #[inline(always)]
    pub fn set_write(self) -> Protection {
        Protection(self.0 | PROT_WRITE)
    }

    /// Returns true if all access allowed by |other| is also allowed by |self|.
    #[inline(always)]
    pub fn allows(&self, other: &Protection) -> bool {
        (self.0 & PROT_READ) >= (other.0 & PROT_READ)
            && (self.0 & PROT_WRITE) >= (other.0 & PROT_WRITE)
    }
}

impl From<c_int> for Protection {
    fn from(f: c_int) -> Self {
        Protection(f)
    }
}

impl From<Protection> for c_int {
    fn from(p: Protection) -> c_int {
        p.0
    }
}

/// See [MemoryMapping](crate::platform::MemoryMapping) for struct- and method-level
/// documentation.
#[derive(Debug)]
pub struct MemoryMapping {
    pub(crate) mapping: PlatformMmap,

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
        match self.mapping.size().checked_sub(offset) {
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

    pub fn read_slice(&self, buf: &mut [u8], offset: usize) -> Result<usize> {
        match self.size().checked_sub(offset) {
            Some(size_past_offset) => {
                let bytes_copied = min(size_past_offset, buf.len());
                // The bytes_copied equation above ensures we don't copy bytes out of range of
                // either buf or this slice. We also know that the buffers do not overlap because
                // slices can never occupy the same memory as a volatile slice.
                unsafe {
                    copy_nonoverlapping(self.as_ptr().add(offset), buf.as_mut_ptr(), bytes_copied);
                }
                Ok(bytes_copied)
            }
            None => Err(Error::InvalidAddress),
        }
    }

    /// Writes an object to the memory region at the specified offset.
    /// Returns Ok(()) if the object fits, or Err if it extends past the end.
    ///
    /// This method is for writing to regular memory. If writing to a mapped
    /// I/O region, use [`MemoryMapping::write_obj_volatile`].
    ///
    /// # Examples
    /// * Write a u64 at offset 16.
    ///
    /// ```
    /// #   use base::MemoryMappingBuilder;
    /// #   let mut mem_map = MemoryMappingBuilder::new(1024).build().unwrap();
    ///     let res = mem_map.write_obj(55u64, 16);
    ///     assert!(res.is_ok());
    /// ```
    pub fn write_obj<T: DataInit>(&self, val: T, offset: usize) -> Result<()> {
        self.mapping.range_end(offset, size_of::<T>())?;
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
    /// This method is for reading from regular memory. If reading from a
    /// mapped I/O region, use [`MemoryMapping::read_obj_volatile`].
    ///
    /// # Examples
    /// * Read a u64 written to offset 32.
    ///
    /// ```
    /// #   use base::MemoryMappingBuilder;
    /// #   let mut mem_map = MemoryMappingBuilder::new(1024).build().unwrap();
    ///     let res = mem_map.write_obj(55u64, 32);
    ///     assert!(res.is_ok());
    ///     let num: u64 = mem_map.read_obj(32).unwrap();
    ///     assert_eq!(55, num);
    /// ```
    pub fn read_obj<T: DataInit>(&self, offset: usize) -> Result<T> {
        self.mapping.range_end(offset, size_of::<T>())?;
        // This is safe because by definition Copy types can have their bits set arbitrarily and
        // still be valid.
        unsafe {
            Ok(read_unaligned(
                self.as_ptr().add(offset) as *const u8 as *const T
            ))
        }
    }

    /// Writes an object to the memory region at the specified offset.
    /// Returns Ok(()) if the object fits, or Err if it extends past the end.
    ///
    /// The write operation will be volatile, i.e. it will not be reordered by
    /// the compiler and is suitable for I/O, but must be aligned. When writing
    /// to regular memory, prefer [`MemoryMapping::write_obj`].
    ///
    /// # Examples
    /// * Write a u32 at offset 16.
    ///
    /// ```
    /// #   use base::MemoryMappingBuilder;
    /// #   let mut mem_map = MemoryMappingBuilder::new(1024).build().unwrap();
    ///     let res = mem_map.write_obj_volatile(0xf00u32, 16);
    ///     assert!(res.is_ok());
    /// ```
    pub fn write_obj_volatile<T: DataInit>(&self, val: T, offset: usize) -> Result<()> {
        self.mapping.range_end(offset, size_of::<T>())?;
        // Make sure writes to memory have been committed before performing I/O that could
        // potentially depend on them.
        fence(Ordering::SeqCst);
        // This is safe because we checked the bounds above.
        unsafe {
            write_volatile(self.as_ptr().add(offset) as *mut T, val);
        }
        Ok(())
    }

    /// Reads on object from the memory region at the given offset.
    /// Reading from a volatile area isn't strictly safe as it could change
    /// mid-read.  However, as long as the type T is plain old data and can
    /// handle random initialization, everything will be OK.
    ///
    /// The read operation will be volatile, i.e. it will not be reordered by
    /// the compiler and is suitable for I/O, but must be aligned. When reading
    /// from regular memory, prefer [`MemoryMapping::read_obj`].
    ///
    /// # Examples
    /// * Read a u32 written to offset 16.
    ///
    /// ```
    /// #   use base::MemoryMappingBuilder;
    /// #   let mut mem_map = MemoryMappingBuilder::new(1024).build().unwrap();
    ///     let res = mem_map.write_obj(0xf00u32, 16);
    ///     assert!(res.is_ok());
    ///     let num: u32 = mem_map.read_obj(16).unwrap();
    ///     assert_eq!(0xf00, num);
    /// ```
    pub fn read_obj_volatile<T: DataInit>(&self, offset: usize) -> Result<T> {
        self.mapping.range_end(offset, size_of::<T>())?;
        // This is safe because by definition Copy types can have their bits set arbitrarily and
        // still be valid.
        unsafe {
            Ok(read_volatile(
                self.as_ptr().add(offset) as *const u8 as *const T
            ))
        }
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
            return Err(Error::InvalidArgument);
        }
        match self.descriptor {
            None => MemoryMappingBuilder::wrap(
                PlatformMmap::new_protection_fixed(
                    addr,
                    self.size,
                    self.protection.unwrap_or_else(Protection::read_write),
                )?,
                None,
            ),
            Some(descriptor) => MemoryMappingBuilder::wrap(
                PlatformMmap::from_descriptor_offset_protection_fixed(
                    addr,
                    descriptor,
                    self.size,
                    self.offset.unwrap_or(0),
                    self.protection.unwrap_or_else(Protection::read_write),
                )?,
                None,
            ),
        }
    }
}

impl VolatileMemory for MemoryMapping {
    fn get_slice(&self, offset: usize, count: usize) -> VolatileMemoryResult<VolatileSlice> {
        let mem_end = calc_offset(offset, count)?;
        if mem_end > self.size() {
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

/// A range of memory that can be msynced, for abstracting over different types of memory mappings.
///
/// # Safety
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

// Safe because it exclusively forwards calls to a safe implementation.
unsafe impl MappedRegion for MemoryMapping {
    fn as_ptr(&self) -> *mut u8 {
        self.mapping.as_ptr()
    }

    fn size(&self) -> usize {
        self.mapping.size()
    }
}

#[derive(Debug, PartialEq)]
pub struct ExternalMapping {
    pub ptr: u64,
    pub size: usize,
}

unsafe impl MappedRegion for ExternalMapping {
    /// used for passing this region to ioctls for setting guest memory.
    fn as_ptr(&self) -> *mut u8 {
        self.ptr as *mut u8
    }

    /// Returns the size of the memory region in bytes.
    fn size(&self) -> usize {
        self.size
    }
}

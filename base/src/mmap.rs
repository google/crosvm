// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::min;
use std::fs::File;
use std::intrinsics::copy_nonoverlapping;
use std::io;
use std::mem::size_of;
use std::ptr::read_unaligned;
use std::ptr::read_volatile;
use std::ptr::write_unaligned;
use std::ptr::write_volatile;
use std::sync::atomic::fence;
use std::sync::atomic::Ordering;
use std::sync::OnceLock;

use remain::sorted;
use serde::Deserialize;
use serde::Serialize;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use crate::descriptor::AsRawDescriptor;
use crate::descriptor::SafeDescriptor;
use crate::platform::MemoryMapping as PlatformMmap;
use crate::SharedMemory;
use crate::VolatileMemory;
use crate::VolatileMemoryError;
use crate::VolatileMemoryResult;
use crate::VolatileSlice;

static CACHELINE_SIZE: OnceLock<usize> = OnceLock::new();

#[allow(unused_assignments)]
fn get_cacheline_size_once() -> usize {
    let mut assume_reason: &str = "unknown";
    cfg_if::cfg_if! {
        if #[cfg(any(target_os = "android", target_os = "linux"))] {
            // SAFETY:
            // Safe because we check the return value for errors or unsupported requests
            let linesize = unsafe { libc::sysconf(libc::_SC_LEVEL1_DCACHE_LINESIZE) };
            if linesize > 0 {
                return linesize as usize;
            } else {
                assume_reason = "sysconf cacheline size query failed";
            }
        } else {
            assume_reason = "cacheline size query not implemented for platform/arch";
        }
    }

    let assumed_size = 64;
    log::debug!(
        "assuming cacheline_size={}; reason: {}.",
        assumed_size,
        assume_reason
    );
    assumed_size
}

/// Returns the system's effective cacheline size (e.g. the granularity at which arch-specific
/// cacheline management, such as with the clflush instruction, is expected to occur).
#[inline(always)]
fn get_cacheline_size() -> usize {
    let size = *CACHELINE_SIZE.get_or_init(get_cacheline_size_once);
    assert!(size > 0);
    size
}

#[sorted]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("`add_fd_mapping` is unsupported")]
    AddFdMappingIsUnsupported,
    #[error("requested memory out of range")]
    InvalidAddress,
    #[error("requested alignment is incompatible")]
    InvalidAlignment,
    #[error("invalid argument provided when creating mapping")]
    InvalidArgument,
    #[error("requested offset is out of range of off_t")]
    InvalidOffset,
    #[error("requested memory range spans past the end of the region: offset={0} count={1} region_size={2}")]
    InvalidRange(usize, usize, usize),
    #[error("operation is not implemented on platform/architecture: {0}")]
    NotImplemented(&'static str),
    #[error("requested memory is not page aligned")]
    NotPageAligned,
    #[error("failed to read from file to memory: {0}")]
    ReadToMemory(#[source] io::Error),
    #[error("`remove_mapping` is unsupported")]
    RemoveMappingIsUnsupported,
    #[error("system call failed while creating the mapping: {0}")]
    StdSyscallFailed(io::Error),
    #[error("mmap related system call failed: {0}")]
    SystemCallFailed(#[source] crate::Error),
    #[error("failed to write from memory to file: {0}")]
    WriteFromMemory(#[source] io::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

/// Memory access type for anonymous shared memory mapping.
#[derive(Copy, Clone, Default, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct Protection {
    pub(crate) read: bool,
    pub(crate) write: bool,
}

impl Protection {
    /// Returns Protection allowing read/write access.
    #[inline(always)]
    pub fn read_write() -> Protection {
        Protection {
            read: true,
            write: true,
        }
    }

    /// Returns Protection allowing read access.
    #[inline(always)]
    pub fn read() -> Protection {
        Protection {
            read: true,
            ..Default::default()
        }
    }

    /// Returns Protection allowing write access.
    #[inline(always)]
    pub fn write() -> Protection {
        Protection {
            write: true,
            ..Default::default()
        }
    }

    /// Set read events.
    #[inline(always)]
    pub fn set_read(self) -> Protection {
        Protection { read: true, ..self }
    }

    /// Set write events.
    #[inline(always)]
    pub fn set_write(self) -> Protection {
        Protection {
            write: true,
            ..self
        }
    }

    /// Returns true if all access allowed by |other| is also allowed by |self|.
    #[inline(always)]
    pub fn allows(&self, other: &Protection) -> bool {
        self.read >= other.read && self.write >= other.write
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

#[inline(always)]
unsafe fn flush_one(_addr: *const u8) -> Result<()> {
    cfg_if::cfg_if! {
        if #[cfg(target_arch = "x86_64")] {
            // As per table 11-7 of the SDM, processors are not required to
            // snoop UC mappings, so flush the target to memory.
            // SAFETY: assumes that the caller has supplied a valid address.
            unsafe { core::arch::x86_64::_mm_clflush(_addr) };
            Ok(())
        } else if #[cfg(target_arch = "aarch64")] {
            // Data cache clean by VA to PoC.
            std::arch::asm!("DC CVAC, {x}", x = in(reg) _addr);
            Ok(())
        } else if #[cfg(target_arch = "arm")] {
            Err(Error::NotImplemented("Userspace cannot flush to PoC"))
        } else {
            Err(Error::NotImplemented("Cache flush not implemented"))
        }
    }
}

impl MemoryMapping {
    pub fn write_slice(&self, buf: &[u8], offset: usize) -> Result<usize> {
        match self.mapping.size().checked_sub(offset) {
            Some(size_past_offset) => {
                let bytes_copied = min(size_past_offset, buf.len());
                // SAFETY:
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
                // SAFETY:
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
    /// #   use base::SharedMemory;
    /// #   let shm = SharedMemory::new("test", 1024).unwrap();
    /// #   let mut mem_map = MemoryMappingBuilder::new(1024).from_shared_memory(&shm).build().unwrap();
    ///     let res = mem_map.write_obj(55u64, 16);
    ///     assert!(res.is_ok());
    /// ```
    pub fn write_obj<T: AsBytes>(&self, val: T, offset: usize) -> Result<()> {
        self.mapping.range_end(offset, size_of::<T>())?;
        // SAFETY:
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
    pub fn read_obj<T: FromBytes>(&self, offset: usize) -> Result<T> {
        self.mapping.range_end(offset, size_of::<T>())?;
        // SAFETY:
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
    /// #   use base::SharedMemory;
    /// #   let shm = SharedMemory::new("test", 1024).unwrap();
    /// #   let mut mem_map = MemoryMappingBuilder::new(1024).from_shared_memory(&shm).build().unwrap();
    ///     let res = mem_map.write_obj_volatile(0xf00u32, 16);
    ///     assert!(res.is_ok());
    /// ```
    pub fn write_obj_volatile<T: AsBytes>(&self, val: T, offset: usize) -> Result<()> {
        self.mapping.range_end(offset, size_of::<T>())?;
        // Make sure writes to memory have been committed before performing I/O that could
        // potentially depend on them.
        fence(Ordering::SeqCst);
        // SAFETY:
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
    /// #   use base::SharedMemory;
    /// #   let shm = SharedMemory::new("test", 1024).unwrap();
    /// #   let mut mem_map = MemoryMappingBuilder::new(1024).from_shared_memory(&shm).build().unwrap();
    ///     let res = mem_map.write_obj(0xf00u32, 16);
    ///     assert!(res.is_ok());
    ///     let num: u32 = mem_map.read_obj_volatile(16).unwrap();
    ///     assert_eq!(0xf00, num);
    /// ```
    pub fn read_obj_volatile<T: FromBytes>(&self, offset: usize) -> Result<T> {
        self.mapping.range_end(offset, size_of::<T>())?;
        // SAFETY:
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

    /// Flush a region of the MemoryMapping from the system's caching hierarchy.
    /// There are several uses for flushing:
    ///
    /// * Cached memory which the guest may be reading through an uncached mapping:
    ///
    ///     Guest reads via an uncached mapping can bypass the cache and directly access main
    ///     memory. This is outside the memory model of Rust, which means that even with proper
    ///     synchronization, guest reads via an uncached mapping might not see updates from the
    ///     host. As such, it is necessary to perform architectural cache maintainance to flush the
    ///     host writes to main memory.
    ///
    ///     Note that this does not support writable uncached guest mappings, as doing so
    ///     requires invalidating the cache, not flushing the cache.
    ///
    /// * Uncached memory which the guest may be writing through a cached mapping:
    ///
    ///     Guest writes via a cached mapping of a host's uncached memory may never make it to
    ///     system/device memory prior to being read. In such cases, explicit flushing of the cached
    ///     writes is necessary, since other managers of the host's uncached mapping (e.g. DRM) see
    ///     no need to flush, as they believe all writes would explicitly bypass the caches.
    ///
    /// Currently only supported on x86_64 and aarch64. Cannot be supported on 32-bit arm.
    pub fn flush_region(&self, offset: usize, len: usize) -> Result<()> {
        let addr: *const u8 = self.as_ptr();
        let size = self.size();

        // disallow overflow/wrapping ranges and subregion extending beyond mapped range
        if usize::MAX - size < addr as usize || offset >= size || size - offset < len {
            return Err(Error::InvalidRange(offset, len, size));
        }

        // SAFETY:
        // Safe because already validated that `next` will be an address in the mapping:
        //     * mapped region is non-wrapping
        //     * subregion is bounded within the mapped region
        let mut next: *const u8 = unsafe { addr.add(offset) };

        let cacheline_size = get_cacheline_size();
        let cacheline_count = len / cacheline_size;

        for _ in 0..cacheline_count {
            // SAFETY:
            // Safe because `next` is guaranteed to be within the mapped region (see earlier
            // validations), and flushing the cache doesn't affect any rust safety properties.
            unsafe { flush_one(next)? };

            // SAFETY:
            // Safe because we never use next if it goes out of the mapped region or overflows its
            // storage type (based on earlier validations and the loop bounds).
            next = unsafe { next.add(cacheline_size) };
        }
        Ok(())
    }

    /// Flush all backing memory for a mapping in an arch-specific manner (see `flush_region()`).
    pub fn flush_all(&self) -> Result<()> {
        self.flush_region(0, self.size())
    }
}

pub struct MemoryMappingBuilder<'a> {
    pub(crate) descriptor: Option<&'a dyn AsRawDescriptor>,
    pub(crate) is_file_descriptor: bool,
    #[cfg_attr(target_os = "macos", allow(unused))]
    pub(crate) size: usize,
    pub(crate) offset: Option<u64>,
    pub(crate) align: Option<u64>,
    pub(crate) protection: Option<Protection>,
    #[cfg_attr(target_os = "macos", allow(unused))]
    #[cfg_attr(windows, allow(unused))]
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
            align: None,
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

    /// Alignment of the memory region mapping in bytes.
    ///
    /// Default: No alignment
    pub fn align(mut self, alignment: u64) -> MemoryMappingBuilder<'a> {
        self.align = Some(alignment);
        self
    }
}

impl VolatileMemory for MemoryMapping {
    fn get_slice(&self, offset: usize, count: usize) -> VolatileMemoryResult<VolatileSlice> {
        let mem_end = offset
            .checked_add(count)
            .ok_or(VolatileMemoryError::Overflow {
                base: offset,
                offset: count,
            })?;

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

        // SAFETY:
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
    // SAFETY:
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

// SAFETY:
// Safe because it exclusively forwards calls to a safe implementation.
unsafe impl MappedRegion for MemoryMapping {
    fn as_ptr(&self) -> *mut u8 {
        self.mapping.as_ptr()
    }

    fn size(&self) -> usize {
        self.mapping.size()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ExternalMapping {
    pub ptr: u64,
    pub size: usize,
}

// SAFETY:
// `ptr`..`ptr+size` is an mmaped region and is owned by this object. Caller
// needs to ensure that the region is not unmapped during the `MappedRegion`'s
// lifetime.
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

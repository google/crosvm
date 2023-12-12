// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libc::c_void;
use win_util::create_file_mapping;
use win_util::duplicate_handle;
use winapi::um::winnt::PAGE_READWRITE;

pub use super::mmap_platform::MemoryMappingArena;
use crate::AsRawDescriptor;
use crate::Descriptor;
use crate::FromRawDescriptor;
use crate::MappedRegion;
use crate::MemoryMapping as CrateMemoryMapping;
use crate::MemoryMappingBuilder;
use crate::MmapError as Error;
use crate::MmapResult as Result;
use crate::Protection;
use crate::RawDescriptor;
use crate::SafeDescriptor;

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
    pub(crate) addr: *mut c_void,
    pub(crate) size: usize,
}

// SAFETY:
// Send and Sync aren't automatically inherited for the raw address pointer.
// Accessing that pointer is only done through the stateless interface which
// allows the object to be shared by multiple threads without a decrease in
// safety.
unsafe impl Send for MemoryMapping {}
// SAFETY: See comments for impl Send
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
        self.addr as *mut u8
    }

    fn size(&self) -> usize {
        self.size
    }
}

impl CrateMemoryMapping {
    pub fn from_raw_ptr(addr: RawDescriptor, size: usize) -> Result<CrateMemoryMapping> {
        MemoryMapping::from_raw_ptr(addr, size).map(|mapping| CrateMemoryMapping {
            mapping,
            _file_descriptor: None,
        })
    }
}

pub trait MemoryMappingBuilderWindows<'a> {
    /// Build the memory mapping given the specified descriptor to mapped memory
    ///
    /// Default: Create a new memory mapping.
    ///
    /// descriptor MUST be a mapping handle. Files MUST use `MemoryMappingBuilder::from_file`
    /// instead.
    #[allow(clippy::wrong_self_convention)]
    fn from_descriptor(self, descriptor: &'a dyn AsRawDescriptor) -> MemoryMappingBuilder;
}

impl<'a> MemoryMappingBuilderWindows<'a> for MemoryMappingBuilder<'a> {
    /// See MemoryMappingBuilderWindows.
    fn from_descriptor(mut self, descriptor: &'a dyn AsRawDescriptor) -> MemoryMappingBuilder {
        self.descriptor = Some(descriptor);
        self
    }
}

impl<'a> MemoryMappingBuilder<'a> {
    /// Build a MemoryMapping from the provided options.
    pub fn build(self) -> Result<CrateMemoryMapping> {
        match self.descriptor {
            Some(descriptor) => {
                let mapping_descriptor = if self.is_file_descriptor {
                    // On Windows, a file cannot be mmapped directly. We have to create a mapping
                    // handle for it first. That handle is then provided to Self::wrap, which
                    // performs the actual mmap (creating a mapped view).
                    //
                    // SAFETY:
                    // Safe because self.descriptor is guaranteed to be a valid handle.
                    let mapping_handle = unsafe {
                        create_file_mapping(
                            Some(descriptor.as_raw_descriptor()),
                            self.size as u64,
                            PAGE_READWRITE,
                            None,
                        )
                    }
                    .map_err(Error::StdSyscallFailed)?;

                    // SAFETY:
                    // The above comment block is why the SafeDescriptor wrap is safe.
                    Some(unsafe { SafeDescriptor::from_raw_descriptor(mapping_handle) })
                } else {
                    None
                };

                MemoryMappingBuilder::wrap(
                    MemoryMapping::from_descriptor_offset_protection(
                        match mapping_descriptor.as_ref() {
                            Some(descriptor) => descriptor as &dyn AsRawDescriptor,
                            None => descriptor,
                        },
                        self.size,
                        self.offset.unwrap_or(0),
                        self.protection.unwrap_or_else(Protection::read_write),
                    )?,
                    if self.is_file_descriptor {
                        self.descriptor
                    } else {
                        None
                    },
                )
            }
            None => MemoryMappingBuilder::wrap(
                MemoryMapping::new_protection(
                    self.size,
                    self.protection.unwrap_or_else(Protection::read_write),
                )?,
                None,
            ),
        }
    }
    pub fn wrap(
        mapping: MemoryMapping,
        file_descriptor: Option<&'a dyn AsRawDescriptor>,
    ) -> Result<CrateMemoryMapping> {
        let file_descriptor = match file_descriptor {
            // SAFETY:
            // Safe because `duplicate_handle` will return a handle or at least error out.
            Some(descriptor) => unsafe {
                Some(SafeDescriptor::from_raw_descriptor(
                    duplicate_handle(descriptor.as_raw_descriptor())
                        .map_err(Error::StdSyscallFailed)?,
                ))
            },
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
    use super::*;
    use crate::SharedMemory;
    use crate::VolatileMemory;
    use crate::VolatileMemoryError;

    // get_slice() and other methods are only available on crate::MemoryMapping.
    fn to_crate_mmap(mapping: MemoryMapping) -> crate::MemoryMapping {
        crate::MemoryMapping {
            mapping,
            _file_descriptor: None,
        }
    }

    #[test]
    fn basic_map() {
        let shm = SharedMemory::new("test", 1028).unwrap();
        let m = to_crate_mmap(MemoryMapping::from_descriptor(&shm, 1024).unwrap());
        assert_eq!(1024, m.size());
    }

    #[test]
    fn test_write_past_end() {
        let shm = SharedMemory::new("test", 1028).unwrap();
        let m = to_crate_mmap(MemoryMapping::from_descriptor(&shm, 5).unwrap());
        let res = m.write_slice(&[1, 2, 3, 4, 5, 6], 0);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), 5);
    }

    #[test]
    fn slice_size() {
        let shm = SharedMemory::new("test", 1028).unwrap();
        let m = to_crate_mmap(MemoryMapping::from_descriptor(&shm, 5).unwrap());
        let s = m.get_slice(2, 3).unwrap();
        assert_eq!(s.size(), 3);
    }

    #[test]
    fn slice_addr() {
        let shm = SharedMemory::new("test", 1028).unwrap();
        let m = to_crate_mmap(MemoryMapping::from_descriptor(&shm, 5).unwrap());
        let s = m.get_slice(2, 3).unwrap();
        // SAFETY: trivially safe
        assert_eq!(s.as_ptr(), unsafe { m.as_ptr().offset(2) });
    }

    #[test]
    fn slice_overflow_error() {
        let shm = SharedMemory::new("test", 1028).unwrap();
        let m = to_crate_mmap(MemoryMapping::from_descriptor(&shm, 5).unwrap());
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
        let shm = SharedMemory::new("test", 1028).unwrap();
        let m = to_crate_mmap(MemoryMapping::from_descriptor(&shm, 5).unwrap());
        let res = m.get_slice(3, 3).unwrap_err();
        assert_eq!(res, VolatileMemoryError::OutOfBounds { addr: 6 });
    }
}

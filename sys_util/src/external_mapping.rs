// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::MappedRegion;
use std::fmt::{self, Display};

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    // A null address is typically bad.  mmap allows it, but not external libraries
    NullAddress,
    // For external mappings that have weird sizes
    InvalidSize,
    // External library failed to map
    LibraryError(i32),
    // If external mapping is unsupported.
    Unsupported,
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            NullAddress => write!(f, "null address returned"),
            InvalidSize => write!(f, "invalid size returned"),
            LibraryError(ret) => write!(f, "library failed to map with {}", ret),
            Unsupported => write!(f, "external mapping unsupported"),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

// Maps a external library resource given an id, returning address and size upon success
pub type Map = fn(u32) -> Result<(u64, usize)>;
// Unmaps the resource given a resource id.
pub type Unmap = fn(u32);

/// ExternalMapping wraps an external library mapping.  This is useful in cases where where the
/// device memory is not compatible with the mmap interface, such as Vulkan VkDeviceMemory in the
/// non-exportable case or when exported as an opaque fd.
#[derive(Debug, PartialEq)]
pub struct ExternalMapping {
    resource_id: u32,
    ptr: u64,
    size: usize,
    unmap: Unmap,
}

unsafe impl Send for ExternalMapping {}
unsafe impl Sync for ExternalMapping {}
impl ExternalMapping {
    /// Creates an ExternalMapping given a library-specific resource id and map/unmap functions.
    ///
    /// # Safety
    ///
    /// The map function must return a valid host memory region.  In addition, callers of the
    /// function must guarantee that the map and unmap functions are thread-safe, never return a
    /// region overlapping already Rust referenced-data, and the backing store of the resource
    /// doesn't disappear before the unmap function is called.
    pub unsafe fn new(resource_id: u32, map: Map, unmap: Unmap) -> Result<ExternalMapping> {
        let (ptr, size) = map(resource_id)?;

        if (ptr as *mut u8).is_null() {
            return Err(Error::NullAddress);
        }
        if size == 0 {
            return Err(Error::InvalidSize);
        }

        Ok(ExternalMapping {
            resource_id,
            ptr,
            size,
            unmap,
        })
    }
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

impl Drop for ExternalMapping {
    fn drop(&mut self) {
        // This is safe because we own this memory range, and nobody else is holding a reference to
        // it.
        (self.unmap)(self.resource_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_valid_external_map() {
        let map1: Map = |_resource_id| Ok((0xAAAABBBB, 500));
        let map2: Map = |_resource_id| Ok((0xBBBBAAAA, 1000));
        let unmap: Unmap = |_resource_id| {};
        let external_map1 = unsafe { ExternalMapping::new(0, map1, unmap).unwrap() };
        let external_map2 = unsafe { ExternalMapping::new(0, map2, unmap).unwrap() };

        assert_eq!(external_map1.as_ptr(), 0xAAAABBBB as *mut u8);
        assert_eq!(external_map1.size(), 500);
        assert_eq!(external_map2.as_ptr(), 0xBBBBAAAA as *mut u8);
        assert_eq!(external_map2.size(), 1000);
    }

    #[test]
    fn check_invalid_external_map() {
        let map1: Map = |_resource_id| Ok((0xAAAABBBB, 0));
        let map2: Map = |_resource_id| Ok((0, 500));
        let unmap: Unmap = |_resource_id| {};

        assert_eq!(
            unsafe { ExternalMapping::new(0, map1, unmap) },
            Err(Error::InvalidSize)
        );

        assert_eq!(
            unsafe { ExternalMapping::new(0, map2, unmap) },
            Err(Error::NullAddress)
        );
    }

    #[test]
    #[should_panic]
    fn check_external_map_drop() {
        let map = |_resource_id| Ok((0xAAAABBBB, 500));
        let unmap = |_resource_id| panic!();
        let _external_map = unsafe { ExternalMapping::new(0, map, unmap) };
    }
}

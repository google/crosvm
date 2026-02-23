// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Common mmap support shared between Linux and macOS.

use libc::c_int;
use libc::PROT_READ;
use libc::PROT_WRITE;

use crate::MappedRegion;
use crate::MmapError as Error;
use crate::MmapResult as Result;
use crate::Protection;

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
pub fn validate_includes_range(mmap_size: usize, offset: usize, range_size: usize) -> Result<()> {
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
            Err(Error::SystemCallFailed(crate::errno::Error::last()))
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
            Err(Error::SystemCallFailed(crate::errno::Error::last()))
        }
    }
}

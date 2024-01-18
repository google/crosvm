// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::MappedRegion;
use base::SharedMemory;
use base::VolatileMemory;
use bitflags::bitflags;

use crate::GuestMemory;
use crate::MemoryRegion;
use crate::Result;

bitflags! {
    #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    #[repr(transparent)]
    pub struct MemoryPolicy: u32 {
    }
}

pub(crate) fn finalize_shm(_shm: &mut SharedMemory) -> Result<()> {
    // Seals are only a concept on Unix systems. On Windows, SharedMemory allocation cannot be
    // updated after creation regardless, so the same operation is done implicitly.
    Ok(())
}

impl GuestMemory {
    /// Handles guest memory policy hints/advices.
    pub fn set_memory_policy(&self, _mem_policy: MemoryPolicy) {
        // Hints aren't supported on Windows.
    }
}

impl MemoryRegion {
    /// Finds ranges of memory that might have non-zero data (i.e. not unallocated memory). The
    /// ranges are offsets into the region's mmap, not offsets into the backing file.
    ///
    /// For example, if there were three bytes and the second byte was a hole, the return would be
    /// `[1..2]` (in practice these are probably always at least page sized).
    pub(crate) fn find_data_ranges(&self) -> anyhow::Result<Vec<std::ops::Range<usize>>> {
        Ok(vec![0..self.mapping.size()])
    }

    pub(crate) fn zero_range(&self, offset: usize, size: usize) -> anyhow::Result<()> {
        self.mapping.get_slice(offset, size)?.write_bytes(0);
        Ok(())
    }
}

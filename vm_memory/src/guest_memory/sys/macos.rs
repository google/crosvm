// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::MappedRegion;
use base::SharedMemory;
use base::VolatileMemory;
use bitflags::bitflags;

use crate::FileBackedMappingParameters;
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
    // macOS does not support memfd seals. SharedMemory on macOS is backed by
    // shm_open or mach_make_memory_entry which cannot be resized after creation,
    // providing equivalent guarantees implicitly.
    Ok(())
}

impl GuestMemory {
    /// Handles guest memory policy hints.
    pub fn set_memory_policy(&self, _mem_policy: MemoryPolicy) {
        // Memory policy hints (hugepages, locking) are not supported on macOS.
    }
}

impl FileBackedMappingParameters {
    pub fn open(&self) -> std::io::Result<std::fs::File> {
        use std::os::unix::fs::OpenOptionsExt;
        Ok(base::open_file_or_duplicate(
            &self.path,
            std::fs::OpenOptions::new()
                .read(true)
                .write(self.writable)
                .custom_flags(if self.sync { libc::O_SYNC } else { 0 }),
        )?)
    }
}

impl MemoryRegion {
    /// Finds ranges of memory that might have non-zero data (i.e. not unallocated memory). The
    /// ranges are offsets into the region's mmap, not offsets into the backing file.
    ///
    /// On macOS we cannot efficiently detect holes in shared memory, so we conservatively
    /// report the entire region as containing data (same approach as Windows).
    pub(crate) fn find_data_ranges(&self) -> anyhow::Result<Vec<std::ops::Range<usize>>> {
        Ok(vec![0..self.mapping.size()])
    }

    pub(crate) fn zero_range(&self, offset: usize, size: usize) -> anyhow::Result<()> {
        self.mapping.get_slice(offset, size)?.write_bytes(0);
        Ok(())
    }
}

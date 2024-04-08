// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::linux::FileDataIterator;
use base::linux::MemfdSeals;
use base::linux::MemoryMappingUnix;
use base::linux::SharedMemoryLinux;
use base::MappedRegion;
use base::SharedMemory;
use bitflags::bitflags;

use crate::Error;
use crate::GuestAddress;
use crate::GuestMemory;
use crate::MemoryRegion;
use crate::Result;

bitflags! {
    #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    #[repr(transparent)]
    pub struct MemoryPolicy: u32 {
        const USE_HUGEPAGES = 1;
        const LOCK_GUEST_MEMORY = (1 << 1);
    }
}

pub(crate) fn finalize_shm(shm: &mut SharedMemory) -> Result<()> {
    // Seals are only a concept on Unix systems, so we must add them in conditional
    // compilation. On Windows, SharedMemory allocation cannot be updated after creation
    // regardless, so the same operation is done implicitly.
    let mut seals = MemfdSeals::new();

    seals.set_shrink_seal();
    seals.set_grow_seal();
    seals.set_seal_seal();

    shm.add_seals(seals).map_err(Error::MemoryAddSealsFailed)
}

impl GuestMemory {
    /// Madvise away the address range in the host that is associated with the given guest range.
    ///
    /// This feature is only available on Unix, where a MemoryMapping can remove a mapped range.
    pub fn remove_range(&self, addr: GuestAddress, count: u64) -> Result<()> {
        let (mapping, offset, _) = self.find_region(addr)?;
        mapping
            .remove_range(offset, count as usize)
            .map_err(|e| Error::MemoryAccess(addr, e))
    }

    /// Handles guest memory policy hints/advices.
    pub fn set_memory_policy(&self, mem_policy: MemoryPolicy) {
        if mem_policy.is_empty() {
            return;
        }

        for region in self.regions.iter() {
            if mem_policy.contains(MemoryPolicy::USE_HUGEPAGES) {
                let ret = region.mapping.use_hugepages();

                if let Err(err) = ret {
                    println!("Failed to enable HUGEPAGE for mapping {}", err);
                }
            }

            if mem_policy.contains(MemoryPolicy::LOCK_GUEST_MEMORY) {
                // This is done in coordination with remove_range() calls, which are
                // performed by the virtio-balloon process (they must be performed by
                // a different process from the one that issues the locks).
                // We also prevent this from happening in single-process configurations,
                // when we compute configuration flags.
                let ret = region.mapping.lock_all();

                if let Err(err) = ret {
                    println!("Failed to lock memory for mapping {}", err);
                }
            }
        }
    }

    pub fn use_dontfork(&self) -> anyhow::Result<()> {
        for region in self.regions.iter() {
            region.mapping.use_dontfork()?;
        }
        Ok(())
    }
}

impl MemoryRegion {
    /// Finds ranges of memory that might have non-zero data (i.e. not unallocated memory). The
    /// ranges are offsets into the region's mmap, not offsets into the backing file.
    ///
    /// For example, if there were three bytes and the second byte was a hole, the return would be
    /// `[1..2]` (in practice these are probably always at least page sized).
    pub(crate) fn find_data_ranges(&self) -> anyhow::Result<Vec<std::ops::Range<usize>>> {
        FileDataIterator::new(
            &self.shared_obj,
            self.obj_offset,
            u64::try_from(self.mapping.size()).unwrap(),
        )
        .map(|range| {
            let range = range?;
            // Convert from file offsets to mmap offsets.
            Ok(usize::try_from(range.start - self.obj_offset).unwrap()
                ..usize::try_from(range.end - self.obj_offset).unwrap())
        })
        .collect()
    }

    pub(crate) fn zero_range(&self, offset: usize, size: usize) -> anyhow::Result<()> {
        self.mapping.remove_range(offset, size)?;
        Ok(())
    }
}

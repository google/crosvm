// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::MemfdSeals;
use base::MemoryMappingUnix;
use base::SharedMemory;
use base::SharedMemoryUnix;
use bitflags::bitflags;

use crate::Error;
use crate::GuestAddress;
use crate::GuestMemory;
use crate::Result;

bitflags! {
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

        for (_, region) in self.regions.iter().enumerate() {
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

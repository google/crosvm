// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use bitflags::bitflags;

use base::{MemfdSeals, MemoryMappingUnix, SharedMemory, SharedMemoryUnix};

use crate::{Error, GuestAddress, GuestMemory, Result};

bitflags! {
    pub struct MemoryPolicy: u32 {
        const USE_HUGEPAGES = 1;
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
        self.do_in_region(addr, move |mapping, offset, _| {
            mapping
                .remove_range(offset, count as usize)
                .map_err(|e| Error::MemoryAccess(addr, e))
        })
    }

    /// Handles guest memory policy hints/advices.
    pub fn set_memory_policy(&self, mem_policy: MemoryPolicy) {
        if mem_policy.contains(MemoryPolicy::USE_HUGEPAGES) {
            for (_, region) in self.regions.iter().enumerate() {
                let ret = region.mapping.use_hugepages();

                if let Err(err) = ret {
                    println!("Failed to enable HUGEPAGE for mapping {}", err);
                }
            }
        }
    }
}

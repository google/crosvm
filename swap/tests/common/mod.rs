// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::MappedRegion;
use base::MemoryMapping;
use base::MemoryMappingBuilder;
use base::SharedMemory;
use swap::userfaultfd::Userfaultfd;
use userfaultfd::UffdBuilder;

pub fn create_uffd_for_test() -> Userfaultfd {
    UffdBuilder::new()
        .non_blocking(false)
        .create()
        .unwrap()
        .into()
}

pub struct SharedMemoryMapping {
    pub shm: SharedMemory,
    pub mmap: MemoryMapping,
}

impl SharedMemoryMapping {
    pub fn base_addr(&self) -> usize {
        self.mmap.as_ptr() as usize
    }
}

pub fn create_shared_memory(name: &str, size: usize) -> SharedMemoryMapping {
    let shm = SharedMemory::new(name, size as u64).unwrap();
    let mmap = MemoryMappingBuilder::new(size)
        .from_shared_memory(&shm)
        .build()
        .unwrap();
    SharedMemoryMapping { shm, mmap }
}

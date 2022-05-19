// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use bitflags::bitflags;

use base::SharedMemory;

use crate::{GuestMemory, Result};

bitflags! {
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

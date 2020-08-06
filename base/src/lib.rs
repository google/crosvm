// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub use sys_util::*;

mod mmap;
mod shm;

pub use mmap::MemoryMapping;
pub use shm::{SharedMemory, Unix as SharedMemoryUnix};

/// Wraps an AsRawDescriptor in the simple Descriptor struct, which
/// has AsRawFd methods for interfacing with sys_util
fn wrap_descriptor(descriptor: &dyn AsRawDescriptor) -> Descriptor {
    Descriptor(descriptor.as_raw_descriptor())
}

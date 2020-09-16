// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub use sys_util::*;

mod event;
mod mmap;
mod shm;
mod timer;

pub use event::{Event, EventReadResult, ScopedEvent};
pub use mmap::MemoryMapping;
pub use shm::{SharedMemory, Unix as SharedMemoryUnix};
pub use sys_util::ioctl::*;
pub use sys_util::sched::*;
pub use sys_util::{
    volatile_at_impl, volatile_impl, FileAllocate, FileGetLen, FileReadWriteAtVolatile,
    FileReadWriteVolatile, FileSetLen, FileSync,
};
pub use sys_util::{SeekHole, WriteZeroesAt};
pub use timer::{FakeTimer, Timer};

/// Wraps an AsRawDescriptor in the simple Descriptor struct, which
/// has AsRawFd methods for interfacing with sys_util
fn wrap_descriptor(descriptor: &dyn AsRawDescriptor) -> Descriptor {
    Descriptor(descriptor.as_raw_descriptor())
}

/// A trait similar to `AsRawDescriptor` but supports an arbitrary number of descriptors.
pub trait AsRawDescriptors {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor>;
}

impl<T> AsRawDescriptors for T
where
    T: AsRawDescriptor,
{
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        vec![self.as_raw_descriptor()]
    }
}

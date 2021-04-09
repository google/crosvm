// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub use sys_util::*;

mod async_types;
mod event;
mod ioctl;
mod mmap;
mod shm;
mod timer;
mod tube;
mod wait_context;

pub use async_types::*;
pub use event::{Event, EventReadResult, ScopedEvent};
pub use ioctl::{
    ioctl, ioctl_with_mut_ptr, ioctl_with_mut_ref, ioctl_with_ptr, ioctl_with_ref, ioctl_with_val,
};
pub use mmap::Unix as MemoryMappingUnix;
pub use mmap::{MemoryMapping, MemoryMappingBuilder, MemoryMappingBuilderUnix};
pub use shm::{SharedMemory, Unix as SharedMemoryUnix};
pub use sys_util::ioctl::*;
pub use sys_util::sched::*;
pub use sys_util::{
    volatile_at_impl, volatile_impl, FileAllocate, FileGetLen, FileReadWriteAtVolatile,
    FileReadWriteVolatile, FileSetLen, FileSync,
};
pub use sys_util::{SeekHole, WriteZeroesAt};
pub use timer::{FakeTimer, Timer};
pub use tube::{AsyncTube, Error as TubeError, Result as TubeResult, Tube};
pub use wait_context::{EventToken, EventType, TriggeredEvent, WaitContext};

/// Wraps an AsRawDescriptor in the simple Descriptor struct, which
/// has AsRawFd methods for interfacing with sys_util
pub fn wrap_descriptor(descriptor: &dyn AsRawDescriptor) -> Descriptor {
    Descriptor(descriptor.as_raw_descriptor())
}

/// Verifies that |raw_descriptor| is actually owned by this process and duplicates it
/// to ensure that we have a unique handle to it.
pub fn validate_raw_descriptor(raw_descriptor: RawDescriptor) -> Result<RawDescriptor> {
    validate_raw_fd(raw_descriptor)
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

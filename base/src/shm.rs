// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CString;

use libc::EINVAL;
use serde::Deserialize;
use serde::Serialize;

use crate::descriptor::AsRawDescriptor;
use crate::descriptor::FromRawDescriptor;
use crate::descriptor::IntoRawDescriptor;
use crate::descriptor::SafeDescriptor;
use crate::platform::SharedMemory as SysUtilSharedMemory;
use crate::Error;
use crate::RawDescriptor;
use crate::Result;

/// See [SharedMemory](crate::platform::SharedMemory) for struct- and method-level
/// documentation.
#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SharedMemory(pub(crate) SysUtilSharedMemory);
impl SharedMemory {
    /// Creates a new shared memory object of the given size.
    ///
    /// |name| is purely for debugging purposes. It does not need to be unique, and it does
    /// not affect any non-debugging related properties of the constructed shared memory.
    pub fn new<T: Into<Vec<u8>>>(debug_name: T, size: u64) -> Result<SharedMemory> {
        let debug_name = CString::new(debug_name).map_err(|_| super::Error::new(EINVAL))?;
        SysUtilSharedMemory::new(&debug_name, size).map(SharedMemory)
    }

    pub fn size(&self) -> u64 {
        self.0.size()
    }

    /// Creates a SharedMemory instance from a SafeDescriptor owning a reference to a
    /// shared memory descriptor. Ownership of the underlying descriptor is transferred to the
    /// new SharedMemory object.
    pub fn from_safe_descriptor(descriptor: SafeDescriptor, size: u64) -> Result<SharedMemory> {
        SysUtilSharedMemory::from_safe_descriptor(descriptor, size).map(SharedMemory)
    }
}

impl AsRawDescriptor for SharedMemory {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.0.as_raw_descriptor()
    }
}

impl IntoRawDescriptor for SharedMemory {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self.0.into_raw_descriptor()
    }
}

impl From<SharedMemory> for SafeDescriptor {
    fn from(sm: SharedMemory) -> SafeDescriptor {
        // Safe because we own the SharedMemory at this point.
        unsafe { SafeDescriptor::from_raw_descriptor(sm.into_raw_descriptor()) }
    }
}

impl audio_streams::shm_streams::SharedMemory for SharedMemory {
    type Error = Error;

    fn anon(size: u64) -> Result<Self> {
        SharedMemory::new("shm_streams", size)
    }

    fn size(&self) -> u64 {
        self.size()
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    fn as_raw_fd(&self) -> RawDescriptor {
        self.as_raw_descriptor()
    }
}

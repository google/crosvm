// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CStr;
use std::ffi::CString;

use libc::EINVAL;
use serde::Deserialize;
use serde::Serialize;

use crate::descriptor::AsRawDescriptor;
use crate::descriptor::IntoRawDescriptor;
use crate::descriptor::SafeDescriptor;
use crate::Error;
use crate::RawDescriptor;
use crate::Result;

/// A shared memory file descriptor and its size.
#[derive(Debug, Deserialize, Serialize)]
pub struct SharedMemory {
    #[serde(with = "crate::with_as_descriptor")]
    pub descriptor: SafeDescriptor,
    pub size: u64,
}

pub(crate) trait PlatformSharedMemory {
    fn new(debug_name: &CStr, size: u64) -> Result<SharedMemory>;
    fn from_safe_descriptor(descriptor: SafeDescriptor, size: u64) -> Result<SharedMemory>;
}

impl SharedMemory {
    /// Creates a new shared memory object of the given size.
    ///
    /// |name| is purely for debugging purposes. It does not need to be unique, and it does
    /// not affect any non-debugging related properties of the constructed shared memory.
    pub fn new<T: Into<Vec<u8>>>(debug_name: T, size: u64) -> Result<SharedMemory> {
        let debug_name = CString::new(debug_name).map_err(|_| super::Error::new(EINVAL))?;
        <SharedMemory as PlatformSharedMemory>::new(&debug_name, size)
    }

    /// Gets the size in bytes of the shared memory.
    ///
    /// The size returned here does not reflect changes by other interfaces or users of the shared
    /// memory file descriptor.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Creates a SharedMemory instance from a SafeDescriptor owning a reference to a
    /// shared memory descriptor. Ownership of the underlying descriptor is transferred to the
    /// new SharedMemory object.
    pub fn from_safe_descriptor(descriptor: SafeDescriptor, size: u64) -> Result<SharedMemory> {
        <SharedMemory as PlatformSharedMemory>::from_safe_descriptor(descriptor, size)
    }
}

/// USE THIS CAUTIOUSLY. On Windows, the returned handle is not a file handle and cannot be used as
/// if it were one. It is a handle to a the associated file mapping object and should only be used
/// for memory-mapping the file view.
impl AsRawDescriptor for SharedMemory {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.descriptor.as_raw_descriptor()
    }
}

impl IntoRawDescriptor for SharedMemory {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self.descriptor.into_raw_descriptor()
    }
}

impl From<SharedMemory> for SafeDescriptor {
    fn from(sm: SharedMemory) -> SafeDescriptor {
        sm.descriptor
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_1024() {
        let shm = SharedMemory::new("test", 1024).expect("failed to create shared memory");
        assert_eq!(shm.size(), 1024);
    }

    #[test]
    fn new_1028() {
        let shm = SharedMemory::new("name", 1028).expect("failed to create shared memory");
        assert_eq!(shm.size(), 1028);
    }

    #[test]
    fn new_too_huge() {
        SharedMemory::new("test", 0x8000_0000_0000_0000)
            .expect_err("8 exabyte shared memory creation should fail");
    }
}

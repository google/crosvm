// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::descriptor::{AsRawDescriptor, FromRawDescriptor, IntoRawDescriptor, SafeDescriptor};
use crate::{Error, RawDescriptor, Result};
#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::{ffi::CStr, os::unix::io::IntoRawFd};

use crate::platform::SharedMemory as SysUtilSharedMemory;
use serde::{Deserialize, Serialize};

/// See [SharedMemory](crate::platform::SharedMemory) for struct- and method-level
/// documentation.
#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SharedMemory(pub(crate) SysUtilSharedMemory);
impl SharedMemory {
    pub fn named<T: Into<Vec<u8>>>(name: T, size: u64) -> Result<SharedMemory> {
        SysUtilSharedMemory::named(name)
            .and_then(|mut shm| shm.set_size(size).map(|_| shm))
            .map(SharedMemory)
    }

    pub fn anon(size: u64) -> Result<SharedMemory> {
        Self::new(None, size)
    }

    pub fn new(name: Option<&CStr>, size: u64) -> Result<SharedMemory> {
        SysUtilSharedMemory::new(name)
            .and_then(|mut shm| shm.set_size(size).map(|_| shm))
            .map(SharedMemory)
    }

    pub fn size(&self) -> u64 {
        self.0.size()
    }

    /// Creates a SharedMemory instance from a SafeDescriptor owning a reference to a
    /// shared memory descriptor. Ownership of the underlying descriptor is transferred to the
    /// new SharedMemory object.
    /// `size` needs to be Some() on windows.
    /// On unix, when `size` is Some(value), the mapping size is set to `value`.
    // TODO(b:231319974): Make size non-optional arg.
    pub fn from_safe_descriptor(
        descriptor: SafeDescriptor,
        size: Option<u64>,
    ) -> Result<SharedMemory> {
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
        self.0.into_raw_fd()
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
        SharedMemory::anon(size)
    }

    fn size(&self) -> u64 {
        self.size()
    }

    #[cfg(unix)]
    fn as_raw_fd(&self) -> RawFd {
        self.as_raw_descriptor()
    }
}

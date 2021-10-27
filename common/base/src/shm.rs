// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::{
    AsRawDescriptor, FromRawDescriptor, IntoRawDescriptor, MemfdSeals, RawDescriptor, Result,
    SafeDescriptor,
};
use std::ffi::CStr;
use std::fs::File;
use std::os::unix::io::{AsRawFd, IntoRawFd};

use serde::{Deserialize, Serialize};
use sys_util::SharedMemory as SysUtilSharedMemory;

/// See [SharedMemory](sys_util::SharedMemory) for struct- and method-level
/// documentation.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct SharedMemory(SysUtilSharedMemory);
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

    /// Unwraps the sys_util::SharedMemory stored within this type.
    /// This should be used only when necessary for interacting with
    /// external libraries.
    pub fn inner(&self) -> &SysUtilSharedMemory {
        &self.0
    }
}

pub trait Unix {
    /// Creates a SharedMemory instance from a SafeDescriptor owning a reference to a
    /// shared memory descriptor. Ownership of the underlying descriptor is transferred to the
    /// new SharedMemory object.
    fn from_safe_descriptor(descriptor: SafeDescriptor) -> Result<SharedMemory> {
        let file = unsafe { File::from_raw_descriptor(descriptor.into_raw_descriptor()) };
        SysUtilSharedMemory::from_file(file).map(SharedMemory)
    }

    fn from_file(file: File) -> Result<SharedMemory> {
        SysUtilSharedMemory::from_file(file).map(SharedMemory)
    }

    fn get_seals(&self) -> Result<MemfdSeals>;

    fn add_seals(&mut self, seals: MemfdSeals) -> Result<()>;
}

impl Unix for SharedMemory {
    fn get_seals(&self) -> Result<MemfdSeals> {
        self.0.get_seals()
    }

    fn add_seals(&mut self, seals: MemfdSeals) -> Result<()> {
        self.0.add_seals(seals)
    }
}

impl AsRawDescriptor for SharedMemory {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.0.as_raw_fd()
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

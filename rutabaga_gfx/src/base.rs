// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(target_os = "fuchsia")]

use std::fmt;

use serde::Deserialize;
use serde::Serialize;

pub type RawDescriptor = u64;

#[derive(Serialize, Deserialize, Debug)]
pub struct Error(i32);
pub type Result<T> = std::result::Result<T, Error>;

/// Wraps a RawDescriptor and safely closes it when self falls out of scope.
#[derive(Serialize, Deserialize, Debug)]
#[serde(transparent)]
pub struct SafeDescriptor {
    pub(crate) descriptor: RawDescriptor,
}

impl SafeDescriptor {
    pub fn try_clone(&self) -> Result<Self> {
        Err(Error(0))
    }
}

impl FromRawDescriptor for SafeDescriptor {
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
        SafeDescriptor { descriptor }
    }
}

/// Trait for forfeiting ownership of the current raw descriptor, and returning the raw descriptor
pub trait IntoRawDescriptor {
    fn into_raw_descriptor(self) -> RawDescriptor;
}

/// Trait for returning the underlying raw descriptor, without giving up ownership of the
/// descriptor.
pub trait AsRawDescriptor {
    /// Returns the underlying raw descriptor.
    ///
    /// Since the descriptor is still owned by the provider, callers should not assume that it will
    /// remain open for longer than the immediate call of this method. In particular, it is a
    /// dangerous practice to store the result of this method for future use: instead, it should be
    /// used to e.g. obtain a raw descriptor that is immediately passed to a system call.
    ///
    /// If you need to use the descriptor for a longer time (and particularly if you cannot reliably
    /// track the lifetime of the providing object), you should probably consider using
    /// [`SafeDescriptor`] (possibly along with [`trait@IntoRawDescriptor`]) to get full ownership
    /// over a descriptor pointing to the same resource.
    fn as_raw_descriptor(&self) -> RawDescriptor;
}

/// A trait similar to `AsRawDescriptor` but supports an arbitrary number of descriptors.
pub trait AsRawDescriptors {
    /// Returns the underlying raw descriptors.
    ///
    /// Please refer to the documentation of [`AsRawDescriptor::as_raw_descriptor`] for limitations
    /// and recommended use.
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor>;
}

pub trait FromRawDescriptor {
    /// # Safety
    /// Safe only if the caller ensures nothing has access to the descriptor after passing it to
    /// `from_raw_descriptor`
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self;
}

impl AsRawDescriptor for SafeDescriptor {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.descriptor
    }
}

pub struct SharedMemory {
    handle: u64,
    size: u64,
}

impl SharedMemory {
    /// Creates a new shared memory object of the given size.
    ///
    /// |name| is purely for debugging purposes. It does not need to be unique, and it does
    /// not affect any non-debugging related properties of the constructed shared memory.
    pub fn new<T: Into<Vec<u8>>>(debug_name: T, size: u64) -> Result<SharedMemory> {
        Err(Error(0))
    }

    pub fn size(&self) -> u64 {
        self.size
    }
}

impl IntoRawDescriptor for SharedMemory {
    fn into_raw_descriptor(self) -> RawDescriptor {
        0
    }
}

impl From<SharedMemory> for SafeDescriptor {
    fn from(sm: SharedMemory) -> SafeDescriptor {
        // Safe because we own the SharedMemory at this point.
        unsafe { SafeDescriptor::from_raw_descriptor(sm.into_raw_descriptor()) }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error recieved")
    }
}

pub fn round_up_to_page_size(v: usize) -> usize {
    v
}

pub unsafe trait MappedRegion: Send + Sync {
    /// Returns a pointer to the beginning of the memory region. Should only be
    /// used for passing this region to ioctls for setting guest memory.
    fn as_ptr(&self) -> *mut u8;

    /// Returns the size of the memory region in bytes.
    fn size(&self) -> usize;
}

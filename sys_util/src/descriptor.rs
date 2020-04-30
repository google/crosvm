// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::unix::io::RawFd;

use crate::{errno_result, Result};
use std::mem;
use std::ops::Drop;

pub type RawDescriptor = RawFd;

/// Trait for forfeiting ownership of the current raw descriptor, and returning the raw descriptor
pub trait IntoRawDescriptor {
    fn into_raw_descriptor(self) -> RawDescriptor;
}

/// Trait for returning the underlying raw descriptor, without giving up ownership of the
/// descriptor.
pub trait AsRawDescriptor {
    fn as_raw_descriptor(&self) -> RawDescriptor;
}

pub trait FromRawDescriptor {
    /// # Safety
    /// Safe only if the caller ensures nothing has access to the descriptor after passing it to
    /// `from_raw_descriptor`
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self;
}

/// Wraps a RawDescriptor and safely closes it when self falls out of scope.
#[derive(Debug, PartialEq)]
pub struct SafeDescriptor {
    descriptor: RawDescriptor,
}

impl Drop for SafeDescriptor {
    fn drop(&mut self) {
        let _ = unsafe { libc::close(self.descriptor) };
    }
}

impl AsRawDescriptor for SafeDescriptor {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.descriptor
    }
}

impl IntoRawDescriptor for SafeDescriptor {
    fn into_raw_descriptor(self) -> RawDescriptor {
        let descriptor = self.descriptor;
        mem::forget(self);
        descriptor
    }
}

impl FromRawDescriptor for SafeDescriptor {
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
        SafeDescriptor { descriptor }
    }
}

impl SafeDescriptor {
    /// Clones this descriptor, internally creating a new descriptor. The new SafeDescriptor will
    /// share the same underlying count within the kernel.
    pub fn try_clone(&self) -> Result<SafeDescriptor> {
        // Safe because self.as_raw_descriptor() returns a valid value
        let copy_fd = unsafe { libc::dup(self.as_raw_descriptor()) };
        if copy_fd < 0 {
            return errno_result();
        }
        // Safe becuase we just successfully duplicated and this object will uniquely
        // own the raw descriptor.
        Ok(unsafe { SafeDescriptor::from_raw_descriptor(copy_fd) })
    }
}

/// For use cases where a simple wrapper around a RawDescriptor is needed.
/// This is a simply a wrapper and does not manage the lifetime of the descriptor.
/// Most usages should prefer SafeDescriptor or using a RawDescriptor directly
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Descriptor(pub RawDescriptor);
impl AsRawDescriptor for Descriptor {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.0
    }
}

// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::{PollToken, RawDescriptor};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    mem::{self, ManuallyDrop},
};

/// Wraps a RawDescriptor and safely closes it when self falls out of scope.
#[derive(Serialize, Deserialize, Debug, Eq)]
#[serde(transparent)]
pub struct SafeDescriptor {
    #[serde(with = "super::with_raw_descriptor")]
    pub(crate) descriptor: RawDescriptor,
}

/// Trait for forfeiting ownership of the current raw descriptor, and returning the raw descriptor
pub trait IntoRawDescriptor {
    fn into_raw_descriptor(self) -> RawDescriptor;
}

/// Trait for returning the underlying raw descriptor, without giving up ownership of the
/// descriptor.
pub trait AsRawDescriptor {
    fn as_raw_descriptor(&self) -> RawDescriptor;
}

/// A trait similar to `AsRawDescriptor` but supports an arbitrary number of descriptors.
pub trait AsRawDescriptors {
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

impl<T> AsRawDescriptors for T
where
    T: AsRawDescriptor,
{
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        vec![self.as_raw_descriptor()]
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

impl TryFrom<&dyn AsRawDescriptor> for SafeDescriptor {
    type Error = std::io::Error;

    /// Clones the underlying descriptor (handle), internally creating a new descriptor.
    ///
    /// WARNING: Windows does NOT support cloning/duplicating all types of handles. DO NOT use this
    /// function on IO completion ports, sockets, or pseudo-handles (except those from
    /// GetCurrentProcess or GetCurrentThread). See
    /// https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle
    /// for further details.
    ///
    /// TODO(b/191800567): this API has sharp edges on Windows. We should evaluate making some
    /// adjustments to smooth those edges.
    fn try_from(rd: &dyn AsRawDescriptor) -> std::result::Result<Self, Self::Error> {
        // Safe because the underlying raw descriptor is guaranteed valid by rd's existence.
        //
        // Note that we are cloning the underlying raw descriptor since we have no guarantee of
        // its existence after this function returns.
        let rd_as_safe_desc = ManuallyDrop::new(unsafe {
            SafeDescriptor::from_raw_descriptor(rd.as_raw_descriptor())
        });

        // We have to clone rd because we have no guarantee ownership was transferred (rd is
        // borrowed).
        rd_as_safe_desc
            .try_clone()
            .map_err(|e| Self::Error::from_raw_os_error(e.errno()))
    }
}

impl From<File> for SafeDescriptor {
    fn from(f: File) -> SafeDescriptor {
        // Safe because we own the File at this point.
        unsafe { SafeDescriptor::from_raw_descriptor(f.into_raw_descriptor()) }
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

/// Implement token for implementations that wish to use this struct as such
impl PollToken for Descriptor {
    fn as_raw_token(&self) -> u64 {
        self.0 as u64
    }

    fn from_raw_token(data: u64) -> Self {
        Descriptor(data as RawDescriptor)
    }
}

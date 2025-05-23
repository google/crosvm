// Copyright 2025 Google
// SPDX-License-Identifier: MIT

use crate::OwnedDescriptor;
use crate::RawDescriptor;

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
    /// `OwnedDescriptor` (possibly along with `IntoRawDescriptor`) to get full ownership
    /// over a descriptor pointing to the same resource.
    fn as_raw_descriptor(&self) -> RawDescriptor;
}

pub trait FromRawDescriptor {
    /// # Safety
    /// Safe only if the caller ensures nothing has access to the descriptor after passing it to
    /// `from_raw_descriptor`
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self;
}

impl IntoRawDescriptor for i64 {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self as RawDescriptor
    }
}

pub trait AsBorrowedDescriptor {
    fn as_borrowed_descriptor(&self) -> &OwnedDescriptor;
}

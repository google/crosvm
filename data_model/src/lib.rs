// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem::size_of;
use std::slice::{from_raw_parts, from_raw_parts_mut};

/// Types for which it is safe to initialize from raw data.
///
/// A type `T` is `DataInit` if and only if it can be initialized by reading its contents from a
/// byte array.  This is generally true for all plain-old-data structs.  It is notably not true for
/// any type that includes a reference.
///
/// Implementing this trait guarantees that it is safe to instantiate the struct with random data.
pub unsafe trait DataInit: Copy + Send + Sync {
    /// Converts a slice of raw data into a reference of `Self`.
    ///
    /// The value of `data` is not copied. Instead a reference is made from the given slice. The
    /// value of `Self` will depend on the representation of the type in memory, and may change in
    /// an unstable fashion.
    ///
    /// This will return `None` if the length of data does not match the size of `Self`.
    fn from_slice(data: &[u8]) -> Option<&Self> {
        if data.len() == size_of::<Self>() {
            // Safe because the DataInit trait asserts any data is valid for this type, and we
            // ensured the size of the pointer's buffer is the correct size. This aliases a pointer,
            // but because the pointer is from a const slice reference, there are no mutable
            // aliases. Finally, the reference returned can not outlive data because they have equal
            // implicit lifetime constraints.
            Some(unsafe { &*(data.as_ptr() as *const Self) })
        } else {
            None
        }
    }

    /// Converts a mutable slice of raw data into a mutable reference of `Self`.
    ///
    /// Because `Self` is made from a reference to the mutable slice`, mutations to the returned
    /// reference are immediately reflected in `data`. The value of the returned `Self` will depend
    /// on the representation of the type in memory, and may change in an unstable fashion.
    ///
    /// This will return `None` if the length of data does not match the size of `Self`.
    fn from_mut_slice(data: &mut [u8]) -> Option<&mut Self> {
        if data.len() == size_of::<Self>() {
            // Safe because the DataInit trait asserts any data is valid for this type, and we
            // ensured the size of the pointer's buffer is the correct size. This aliases a pointer,
            // but because the pointer is from a const slice reference, there are no mutable
            // aliases. Finally, the reference returned can not outlive data because they have equal
            // implicit lifetime constraints.
            Some(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
        } else {
            None
        }
    }

    /// Converts a reference to `self` into a slice of bytes.
    ///
    /// The value of `self` is not copied. Instead, the slice is made from a reference to `self`.
    /// The value of bytes in the returned slice will depend on the representation of the type in
    /// memory, and may change in an unstable fashion.
    fn as_slice(&self) -> &[u8] {
        // Safe because the entire size of self is accessible as bytes because the trait guarantees
        // it. The lifetime of the returned slice is the same as the passed reference, so that no
        // dangling pointers will result from this pointer alias.
        unsafe { from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }

    /// Converts a mutable reference to `self` into a mutable slice of bytes.
    ///
    /// Because the slice is made from a reference to `self`, mutations to the returned slice are
    /// immediately reflected in `self`. The value of bytes in the returned slice will depend on
    /// the representation of the type in memory, and may change in an unstable fashion.
    fn as_mut_slice(&mut self) -> &mut [u8] {
        // Safe because the entire size of self is accessible as bytes because the trait guarantees
        // it. The trait also guarantees that any combination of bytes is valid for this type, so
        // modifying them in the form of a byte slice is valid. The lifetime of the returned slice
        // is the same as the passed reference, so that no dangling pointers will result from this
        // pointer alias. Although this does alias a mutable pointer, we do so by exclusively
        // borrowing the given mutable reference.
        unsafe { from_raw_parts_mut(self as *mut Self as *mut u8, size_of::<Self>()) }
    }
}

// All intrinsic types and arays of intrinsic types are DataInit.  They are just numbers.
macro_rules! array_data_init {
    ($T:ty, $($N:expr)+) => {
        $(
            unsafe impl DataInit for [$T; $N] {}
        )+
    }
}
macro_rules! data_init_type {
    ($T:ty) => {
        unsafe impl DataInit for $T {}
        array_data_init! {
            $T,
            0  1  2  3  4  5  6  7  8  9
            10 11 12 13 14 15 16 17 18 19
            20 21 22 23 24 25 26 27 28 29
            30 31 32
        }
    }
}
data_init_type!(u8);
data_init_type!(u16);
data_init_type!(u32);
data_init_type!(u64);
data_init_type!(usize);
data_init_type!(i8);
data_init_type!(i16);
data_init_type!(i32);
data_init_type!(i64);
data_init_type!(isize);

pub mod endian;
pub use endian::*;

pub mod volatile_memory;
pub use volatile_memory::*;

// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(deprecated)]

use std::io;
use std::mem::size_of;
use std::mem::MaybeUninit;
use std::slice::from_raw_parts;
use std::slice::from_raw_parts_mut;

use zerocopy::AsBytes;
use zerocopy::FromBytes;

use zerocopy::Ref;

pub fn zerocopy_from_reader<R: io::Read, T: FromBytes>(mut read: R) -> io::Result<T> {
    // Allocate on the stack via `MaybeUninit` to ensure proper alignment.
    let mut out = MaybeUninit::zeroed();

    // Safe because the pointer is valid and points to `size_of::<T>()` bytes of zeroes,
    // which is a properly initialized value for `u8`.
    let buf = unsafe { from_raw_parts_mut(out.as_mut_ptr() as *mut u8, size_of::<T>()) };
    read.read_exact(buf)?;

    // Safe because any bit pattern is considered a valid value for `T`.
    Ok(unsafe { out.assume_init() })
}

pub fn zerocopy_from_mut_slice<T: FromBytes + AsBytes>(data: &mut [u8]) -> Option<&mut T> {
    let lv: Ref<&mut [u8], T> = Ref::new(data)?;
    Some(lv.into_mut())
}

pub fn zerocopy_from_slice<T: FromBytes>(data: &[u8]) -> Option<&T> {
    let lv: Ref<&[u8], T> = Ref::new(data)?;
    Some(lv.into_ref())
}

/// Types for which it is safe to initialize from raw data.
///
///
/// Implementing this trait guarantees that it is safe to instantiate the struct with random data.
///
/// # Safety
/// A type `T` is `DataInit` if it can be initialized by reading its contents from a byte array.
/// This is generally true for all plain-old-data structs.  It is notably not true for any type
/// that includes a reference.
///
/// It is unsafe for `T` to be `DataInit` if `T` contains implicit padding. (LLVM considers access
/// to implicit padding to be undefined behavior, which can cause UB when working with `T`.
/// For details on structure padding in Rust, see
/// <https://doc.rust-lang.org/reference/type-layout.html#the-c-representation>.
#[deprecated(
    note = "This type was created when there's no suitable POD (plain-old-data) types in the rust
     ecosystem. It does not verify the safety of treating a data structure as POD and multiple
     incorrect and unsound usage have occured previously. Users should use `zerocopy` crate as
     alternative."
)]
pub unsafe trait DataInit: Copy + Send + Sync {
    /// Converts a slice of raw data into a reference of `Self`.
    ///
    /// The value of `data` is not copied. Instead a reference is made from the given slice. The
    /// value of `Self` will depend on the representation of the type in memory, and may change in
    /// an unstable fashion.
    ///
    /// This will return `None` if the length of data does not match the size of `Self`, or if the
    /// data is not aligned for the type of `Self`.
    fn from_slice(data: &[u8]) -> Option<&Self> {
        // Early out to avoid an unneeded `align_to` call.
        if data.len() != size_of::<Self>() {
            return None;
        }

        // Safe because the DataInit trait asserts any data is valid for this type, and we ensured
        // the size of the pointer's buffer is the correct size. The `align_to` method ensures that
        // we don't have any unaligned references. This aliases a pointer, but because the pointer
        // is from a const slice reference, there are no mutable aliases. Finally, the reference
        // returned can not outlive data because they have equal implicit lifetime constraints.
        match unsafe { data.align_to::<Self>() } {
            ([], [mid], []) => Some(mid),
            _ => None,
        }
    }

    /// Copies the value of `Self` from the beginning of a slice of raw data.
    ///
    /// This will return `None` if the length of data is less than the size of `Self`, or if the
    /// data is not aligned for the type of `Self`.
    fn read_from_prefix(data: &[u8]) -> Option<Self> {
        data.get(0..size_of::<Self>())
            .and_then(|slice| Self::from_slice(slice))
            .copied()
    }

    /// Converts a mutable slice of raw data into a mutable reference of `Self`.
    ///
    /// Because `Self` is made from a reference to the mutable slice`, mutations to the returned
    /// reference are immediately reflected in `data`. The value of the returned `Self` will depend
    /// on the representation of the type in memory, and may change in an unstable fashion.
    ///
    /// This will return `None` if the length of data does not match the size of `Self`, or if the
    /// data is not aligned for the type of `Self`.
    fn from_mut_slice(data: &mut [u8]) -> Option<&mut Self> {
        // Early out to avoid an unneeded `align_to_mut` call.
        if data.len() != size_of::<Self>() {
            return None;
        }

        // Safe because the DataInit trait asserts any data is valid for this type, and we ensured
        // the size of the pointer's buffer is the correct size. The `align_to` method ensures that
        // we don't have any unaligned references. This aliases a pointer, but because the pointer
        // is from a mut slice reference, we borrow the passed in mutable reference. Finally, the
        // reference returned can not outlive data because they have equal implicit lifetime
        // constraints.
        match unsafe { data.align_to_mut::<Self>() } {
            ([], [mid], []) => Some(mid),
            _ => None,
        }
    }

    /// Creates an instance of `Self` by copying raw data from an io::Read stream.
    fn from_reader<R: io::Read>(mut read: R) -> io::Result<Self> {
        // Allocate on the stack via `MaybeUninit` to ensure proper alignment.
        let mut out = MaybeUninit::zeroed();

        // Safe because the pointer is valid and points to `size_of::<Self>()` bytes of zeroes,
        // which is a properly initialized value for `u8`.
        let buf = unsafe { from_raw_parts_mut(out.as_mut_ptr() as *mut u8, size_of::<Self>()) };
        read.read_exact(buf)?;

        // Safe because any bit pattern is considered a valid value for `Self`.
        Ok(unsafe { out.assume_init() })
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
    ($($T:ident),*) => {
        $(
            unsafe impl DataInit for $T {}
            array_data_init! {
                $T,
                0  1  2  3  4  5  6  7  8  9
                10 11 12 13 14 15 16 17 18 19
                20 21 22 23 24 25 26 27 28 29
                30 31 32
            }
        )*
        #[cfg(test)]
        mod data_init_tests {
            use std::mem::{size_of, align_of};
            use crate::DataInit;

            #[test]
            fn from_slice_alignment() {
                let mut v = [0u8; 32];
                $(
                    let (pre, _, _) = unsafe { v.align_to::<$T>() };
                    let pre_len = pre.len();

                    let aligned_v = &mut v[pre_len..pre_len + size_of::<$T>()];

                    let from_aligned = $T::from_slice(aligned_v);
                    assert_eq!(from_aligned, Some(&0));

                    let from_aligned_mut = $T::from_mut_slice(aligned_v);
                    assert_eq!(from_aligned_mut, Some(&mut 0));

                    for i in 1..size_of::<$T>() {
                        let begin = pre_len + i;
                        let end = begin + size_of::<$T>();
                        let unaligned_v = &mut v[begin..end];

                        let from_unaligned = $T::from_slice(unaligned_v);
                        if align_of::<$T>() != 1 {
                            assert_eq!(from_unaligned, None);
                        }

                        let from_unaligned_mut = $T::from_mut_slice(unaligned_v);
                        if align_of::<$T>() != 1 {
                            assert_eq!(from_unaligned_mut, None);
                        }
                    }
                )*

            }
        }
    };
}
data_init_type!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);

pub mod endian;
pub use crate::endian::*;

pub mod volatile_memory;
pub use crate::volatile_memory::*;

mod flexible_array;
pub use flexible_array::vec_with_array_field;
pub use flexible_array::FlexibleArray;
pub use flexible_array::FlexibleArrayWrapper;

mod iobuf;
pub use iobuf::create_iobuf;
pub use iobuf::IoBuf;
pub use iobuf::IoBufMut;

mod sys;

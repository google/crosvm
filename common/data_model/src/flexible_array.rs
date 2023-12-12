// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A wrapper for structures that contain flexible arrays.

use std::marker::PhantomData;
use std::mem::size_of;

// Returns a `Vec<T>` with a size in bytes at least as large as `size_in_bytes`.
fn vec_with_size_in_bytes<T: Default>(size_in_bytes: usize) -> Vec<T> {
    let rounded_size = (size_in_bytes + size_of::<T>() - 1) / size_of::<T>();
    let mut v = Vec::with_capacity(rounded_size);
    v.resize_with(rounded_size, T::default);
    v
}

/// The kernel API has many structs that resemble the following `Foo` structure:
///
/// ```ignore
/// #[repr(C)]
/// struct Foo {
///    some_data: u32,
///    entries: __IncompleteArrayField<__u32>,
/// }
/// ```
///
/// In order to allocate such a structure, `size_of::<Foo>()` would be too small because it would
/// not include any space for `entries`. To make the allocation large enough while still being
/// aligned for `Foo`, a `Vec<Foo>` is created. Only the first element of `Vec<Foo>` would actually
/// be used as a `Foo`. The remaining memory in the `Vec<Foo>` is for `entries`, which must be
/// contiguous with `Foo`. This function is used to make the `Vec<Foo>` with enough space for
/// `count` entries.
pub fn vec_with_array_field<T: Default, F>(count: usize) -> Vec<T> {
    let element_space = count * size_of::<F>();
    let vec_size_bytes = size_of::<T>() + element_space;
    vec_with_size_in_bytes(vec_size_bytes)
}

/// The following code provides generic helpers for creating and accessing flexible array structs.
/// A complete definition of flexible array structs is found in the ISO 9899 specification
/// <http://www.iso-9899.info/n1570.html>. A flexible array struct is of the form:
///
/// ```ignore
/// #[repr(C)]
/// struct T {
///    some_data: u32,
///    nents: u32,
///    entries: __IncompleteArrayField<S>,
/// }
/// ```
/// where:
///
/// - `T` is the flexible array struct type
/// - `S` is the flexible array type
/// - `nents` is the flexible array length
/// - `entries` is the flexible array member
///
/// These structures are used by the kernel API.

/// A collection of methods that are required by the FlexibleArrayWrapper type.
///
/// When implemented for `T`, this trait allows the caller to set number of `S` entries and
/// retrieve a slice of `S` entries.  Trait methods must only be called by the FlexibleArrayWrapper
/// type.  Don't implement this trait directly, use the flexible_array! macro to avoid duplication.
pub trait FlexibleArray<S> {
    /// Implementations must set flexible array length in the flexible array struct to the value
    /// specified by `len`. Appropriate conversions (i.e, usize to u32) are allowed so long as
    /// they don't overflow or underflow.
    fn set_len(&mut self, len: usize);
    /// Implementations must return the length of the flexible array member.  Appropriate
    /// conversions (i.e, usize to u32) are allowed so long as they don't overflow or underflow.
    fn get_len(&self) -> usize;
    /// Implementations must return a slice of flexible array member of length `len`.
    /// # Safety
    /// Do not use this function directly, as the FlexibleArrayWrapper will guarantee safety.
    unsafe fn get_slice(&self, len: usize) -> &[S];
    /// Implementations must return a mutable slice of flexible array member of length `len`.
    /// # Safety
    /// Do not use this function directly, as the FlexibleArrayWrapper will guarantee safety.
    unsafe fn get_mut_slice(&mut self, len: usize) -> &mut [S];
}

/// Always use this macro for implementing the FlexibleArray<`S`> trait for a given `T`.  There
/// exists an 1:1 mapping of macro identifiers to the definitions in the FlexibleArray<`S`>
/// documentation, so refer to that for more information.
#[macro_export]
macro_rules! flexible_array_impl {
    ($T:ident, $S:ident, $nents:ident, $entries:ident) => {
        impl $crate::FlexibleArray<$S> for $T {
            fn set_len(&mut self, len: usize) {
                self.$nents = ::std::convert::TryInto::try_into(len).unwrap();
            }

            fn get_len(&self) -> usize {
                self.$nents as usize
            }

            unsafe fn get_slice(&self, len: usize) -> &[$S] {
                self.$entries.as_slice(len)
            }

            unsafe fn get_mut_slice(&mut self, len: usize) -> &mut [$S] {
                self.$entries.as_mut_slice(len)
            }
        }
    };
}

pub struct FlexibleArrayWrapper<T, S> {
    entries: Vec<T>,
    phantom: PhantomData<S>,
    allocated_len: usize,
}

/// Convenience wrapper for flexible array structs.
///
/// The FlexibleArray trait must be implemented for the flexible array struct before using this
/// wrapper.
impl<T, S> FlexibleArrayWrapper<T, S>
where
    T: FlexibleArray<S> + Default,
{
    /// Creates a new FlexibleArrayWrapper for the given flexible array struct type and flexible
    /// array type. The flexible array length is set to `array_len`. vec_with_array_field is used
    /// to make sure the resultant wrapper is appropriately sized.
    pub fn new(array_len: usize) -> FlexibleArrayWrapper<T, S> {
        let mut entries = vec_with_array_field::<T, S>(array_len);
        entries[0].set_len(array_len);

        FlexibleArrayWrapper {
            entries,
            phantom: PhantomData,
            allocated_len: array_len,
        }
    }

    /// Mapping the unsized array to a slice is unsafe because the length isn't known.  Using
    /// the length we originally allocated with eliminates the possibility of overflow.
    fn get_valid_len(&self) -> usize {
        if self.entries[0].get_len() > self.allocated_len {
            self.allocated_len
        } else {
            self.entries[0].get_len()
        }
    }

    /// Returns a slice of the flexible array member, for inspecting. To modify, use
    /// mut_entries_slice instead.
    pub fn entries_slice(&self) -> &[S] {
        let valid_length = self.get_valid_len();
        // SAFETY:
        // Safe because the length has been validated.
        unsafe { self.entries[0].get_slice(valid_length) }
    }

    /// Returns a mutable slice of the flexible array member, for modifying.
    pub fn mut_entries_slice(&mut self) -> &mut [S] {
        let valid_length = self.get_valid_len();
        self.entries[0].set_len(valid_length);
        // SAFETY:
        // Safe because the length has been validated.
        unsafe { self.entries[0].get_mut_slice(valid_length) }
    }

    /// Get a pointer so it can be passed to the kernel. Callers must not access the flexible
    /// array member.  Using this pointer is unsafe.
    pub fn as_ptr(&self) -> *const T {
        &self.entries[0]
    }

    /// Get a mutable pointer so it can be passed to the kernel. Callers must not access the
    /// flexible array member.  Using this pointer is unsafe.
    pub fn as_mut_ptr(&mut self) -> *mut T {
        &mut self.entries[0]
    }
}

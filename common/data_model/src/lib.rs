// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::mem::size_of;
use std::mem::MaybeUninit;
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

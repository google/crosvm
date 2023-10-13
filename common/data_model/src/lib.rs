// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;

use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;
use zerocopy::Ref;

pub fn zerocopy_from_reader<R: io::Read, T: AsBytes + FromBytes + FromZeroes>(
    mut read: R,
) -> io::Result<T> {
    let mut out = T::new_zeroed();
    read.read_exact(out.as_bytes_mut())?;
    Ok(out)
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

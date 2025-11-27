// Copyright 2025 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Integer types.

/// A positive integer in the range `0..=i32::MAX`.
pub struct U31(u32);

impl U31 {
    pub const fn new(value: u32) -> Option<Self> {
        if value > i32::MAX as _ {
            None
        } else {
            Some(Self(value))
        }
    }
}

impl From<U31> for i32 {
    fn from(value: U31) -> Self {
        value.0 as _
    }
}

/// A strictly negative integer in the range `i32::MIN..0`.
pub struct NegativeI32(i32);

impl NegativeI32 {
    pub const fn new(value: i32) -> Option<Self> {
        if value < 0 {
            Some(Self(value))
        } else {
            None
        }
    }
}

impl From<NegativeI32> for i32 {
    fn from(value: NegativeI32) -> Self {
        value.0
    }
}

/// Represent a `Result` as a single integer where negative values are errors.
pub fn fold_into_i32<T, E>(result: Result<T, E>) -> i32
where
    T: Into<U31>,
    E: Into<NegativeI32>,
{
    match result {
        Ok(t) => i32::from(t.into()),
        Err(e) => i32::from(e.into()),
    }
}

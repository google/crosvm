// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ops::Deref;

use winapi::um::winnt::LARGE_INTEGER;

pub struct LargeInteger {
    large_integer: LARGE_INTEGER,
}

impl LargeInteger {
    pub fn new(value: i64) -> LargeInteger {
        // SAFETY: We are zero-initializing a struct with only primitive member fields.
        let mut large_integer_val: LARGE_INTEGER = unsafe { std::mem::zeroed() };
        // SAFETY: We uniquely own this variable
        let large_integer_val_mut: &mut i64 = unsafe { large_integer_val.QuadPart_mut() };
        *large_integer_val_mut = value;

        LargeInteger {
            large_integer: large_integer_val,
        }
    }
}

impl Deref for LargeInteger {
    type Target = LARGE_INTEGER;

    fn deref(&self) -> &Self::Target {
        &self.large_integer
    }
}

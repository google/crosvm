// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Macros for rutabaga_gfx.

#[macro_export]
macro_rules! checked_range {
    ($x:expr; <= $y:expr) => {
        if $x <= $y {
            Ok(())
        } else {
            Err($crate::RutabagaError::from($crate::RutabagaErrorKind::CheckedRange {
                field1: (stringify!($x), $x as usize),
                field2: (stringify!($y), $y as usize),
            }))
        }
    };
    ($x:ident <= $y:ident) => {
        check_range!($x; <= $y)
    };
}

#[macro_export]
macro_rules! checked_arithmetic {
    ($x:ident $op:ident $y:ident $op_name:expr) => {
        $x.$op($y).ok_or_else(|| $crate::RutabagaErrorKind::CheckedArithmetic {
            field1: (stringify!($x), $x as usize),
            field2: (stringify!($y), $y as usize),
            op: $op_name,
        }).map_err($crate::RutabagaError::from)
    };
    ($x:ident + $y:ident) => {
        checked_arithmetic!($x checked_add $y "+")
    };
    ($x:ident - $y:ident) => {
        checked_arithmetic!($x checked_sub $y "-")
    };
    ($x:ident * $y:ident) => {
        checked_arithmetic!($x checked_mul $y "*")
    };
    ($x:ident / $y:ident) => {
        checked_arithmetic!($x checked_div $y "/")
    };
}

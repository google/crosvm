// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Macros that helps virtio video implementation.

/// Implements TryFrom<data_model::Le32> for an enum that implements `enumn::N`.
#[macro_export]
macro_rules! impl_try_from_le32_for_enumn {
    ($ty:ty, $name:literal) => {
        impl TryFrom<Le32> for $ty {
            type Error = ReadCmdError;

            fn try_from(x: Le32) -> Result<Self, Self::Error> {
                let v: u32 = x.into();
                Self::n(v).ok_or_else(|| {
                    error!(concat!("invalid ", $name, ": {}"), v);
                    ReadCmdError::InvalidArgument
                })
            }
        }
    };
}

/// Implements `From` between two structs whose each field implements `From` each other.
#[macro_export]
macro_rules! impl_from_for_interconvertible_structs {
    ($t1:ident, $t2:ident, $($v:ident),+) => {
        impl_from_for_interconvertible_structs_core!($t1, $t2, $( $v ),+ );
        impl_from_for_interconvertible_structs_core!($t2, $t1, $( $v ),+ );
    };
}

macro_rules! impl_from_for_interconvertible_structs_core {
    ($t1:ident, $t2:ident, $($v:ident),+) => {
        impl From<$t1> for $t2 {
            #[allow(clippy::needless_update)]
            fn from(x :$t1) -> Self {
                $t2 {
                    $( $v: x.$v.into(), )+
                    ..Default::default() // for paddings
                }
            }
        }
    };
}

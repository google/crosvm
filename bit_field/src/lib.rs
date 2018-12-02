// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[allow(unused_imports)]
#[macro_use]
extern crate bit_field_derive;

pub use bit_field_derive::*;

// This functions calculate max possible number represented by `width` bits. If one day this can be
// done in other ways, remove this function. For now, stop worrying and trust constant
// propagation. (checked assembly code, it's a constant when opt-leve >= 2)
fn max_number_of_width(width: u8) -> u64 {
    if width < 64 {
        (1 << width) - 1
    } else {
        u64::max_value()
    }
}

/// BitFieldSpecifier is a group of structs help defining bitfield. It should only
/// be used with the #[bitfield] attribute macro.
/// Example:
/// #[bitfield]
/// pub struct MyBitFieldSchema {
///     field_a : BitField1,
///     field_b : BitField3,
///     field_c : BitField5,
///     field_d : BitField32,
/// }
///
/// bit_field_derive implementation will use the static informations associated
/// with those tyes to generate a struct named MyBitField and getter/setter for
/// all fields.
/// An example getter/setter is:
///     fn get_field_a(&self) -> u8
///     fn set_field_a(&self, val: u8)
/// For larger fields:
///     fn get_field_d(&self) -> u32
///     fn set_field_d(&self, val: u32)
///
/// You can also pass attributes to the defined bitfield structs. Simply do this:
/// #[derive(Clone)]
/// For more details, refer to bit_field_derive.
pub trait BitFieldSpecifier {
    /// Width of this field in bits.
    const FIELD_WIDTH: u8;
    /// Default data type of this field.
    /// For any field, we use the closest u* type. e.g. FIELD_WIDTH <= 8 will
    /// have defulat type of u8.
    /// It's possible to write a custom specifier and use i8.
    type DefaultFieldType;

    /// Max value of this field.
    fn field_max() -> u64 {
        max_number_of_width(Self::FIELD_WIDTH)
    }
    fn from_u64(val: u64) -> Self::DefaultFieldType;
    fn into_u64(val: Self::DefaultFieldType) -> u64;
}

pub struct BitFieldBool;
impl BitFieldSpecifier for BitFieldBool {
    const FIELD_WIDTH: u8 = 1;
    type DefaultFieldType = bool;
    fn from_u64(val: u64) -> Self::DefaultFieldType {
        val > 0
    }
    fn into_u64(val: Self::DefaultFieldType) -> u64 {
        val as u64
    }
}
macro_rules! bitfield_structs {
    ($t:ty, $min_width:expr, $bt:ident $($bts:ident)*)
    => {
        pub struct $bt;
        impl BitFieldSpecifier for $bt {
            const FIELD_WIDTH: u8 = $min_width;
            type DefaultFieldType = $t;
            fn from_u64(val: u64) -> Self::DefaultFieldType {
                val as Self::DefaultFieldType
            }
            fn into_u64(val: Self::DefaultFieldType) -> u64 {
                val as u64
            }
        }
        bitfield_structs!($t, $min_width + 1, $($bts)*);
    };
    ($t:ty, $min_width:expr,) => {};
}

bitfield_structs! {
    u8, 0, BitField0 BitField1 BitField2 BitField3 BitField4 BitField5 BitField6 BitField7 BitField8
}

bitfield_structs! {
    u16, 9, BitField9 BitField10 BitField11 BitField12 BitField13 BitField14 BitField15 BitField16
}

bitfield_structs! {
    u32, 17, BitField17 BitField18 BitField19 BitField20 BitField21 BitField22 BitField23 BitField24
        BitField25 BitField26 BitField27 BitField28 BitField29 BitField30 BitField31 BitField32
}

bitfield_structs! {
    u64, 33, BitField33 BitField34 BitField35 BitField36 BitField37 BitField38 BitField39 BitField40 BitField41
        BitField42 BitField43 BitField44 BitField45 BitField46 BitField47 BitField48 BitField49 BitField50
        BitField51 BitField52 BitField53 BitField54 BitField55 BitField56 BitField57 BitField58
        BitField59 BitField60 BitField61 BitField62 BitField63 BitField64
}

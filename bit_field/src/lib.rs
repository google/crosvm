// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[allow(unused_imports)]
#[macro_use]
extern crate bit_field_derive;

pub use bit_field_derive::*;

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
    /// Max value of this field.
    const FIELD_MAX: u64;
    /// Default data type of this field.
    /// For any field, we use the closest u* type. e.g. FIELD_WIDTH <= 8 will
    /// have defulat type of u8.
    /// It's possible to write a custom specifier and use i8.
    type DefaultFieldType;
}

pub struct BitField0;
impl BitFieldSpecifier for BitField0 {
    const FIELD_WIDTH: u8 = 0;
    const FIELD_MAX: u64 = 0x0;
    type DefaultFieldType = u8;
}

pub struct BitField1;
impl BitFieldSpecifier for BitField1 {
    const FIELD_WIDTH: u8 = 1;
    const FIELD_MAX: u64 = 0x1;
    type DefaultFieldType = u8;
}

pub struct BitField2;
impl BitFieldSpecifier for BitField2 {
    const FIELD_WIDTH: u8 = 2;
    const FIELD_MAX: u64 = 0x3;
    type DefaultFieldType = u8;
}

pub struct BitField3;
impl BitFieldSpecifier for BitField3 {
    const FIELD_WIDTH: u8 = 3;
    const FIELD_MAX: u64 = 0x7;
    type DefaultFieldType = u8;
}

pub struct BitField4;
impl BitFieldSpecifier for BitField4 {
    const FIELD_WIDTH: u8 = 4;
    const FIELD_MAX: u64 = 0xf;
    type DefaultFieldType = u8;
}

pub struct BitField5;
impl BitFieldSpecifier for BitField5 {
    const FIELD_WIDTH: u8 = 5;
    const FIELD_MAX: u64 = 0x1f;
    type DefaultFieldType = u8;
}

pub struct BitField6;
impl BitFieldSpecifier for BitField6 {
    const FIELD_WIDTH: u8 = 6;
    const FIELD_MAX: u64 = 0x3f;
    type DefaultFieldType = u8;
}

pub struct BitField7;
impl BitFieldSpecifier for BitField7 {
    const FIELD_WIDTH: u8 = 7;
    const FIELD_MAX: u64 = 0x7f;
    type DefaultFieldType = u8;
}

pub struct BitField8;
impl BitFieldSpecifier for BitField8 {
    const FIELD_WIDTH: u8 = 8;
    const FIELD_MAX: u64 = 0xff;
    type DefaultFieldType = u8;
}

pub struct BitField9;
impl BitFieldSpecifier for BitField9 {
    const FIELD_WIDTH: u8 = 9;
    const FIELD_MAX: u64 = 0x1ff;
    type DefaultFieldType = u16;
}

pub struct BitField10;
impl BitFieldSpecifier for BitField10 {
    const FIELD_WIDTH: u8 = 10;
    const FIELD_MAX: u64 = 0x3ff;
    type DefaultFieldType = u16;
}

pub struct BitField11;
impl BitFieldSpecifier for BitField11 {
    const FIELD_WIDTH: u8 = 11;
    const FIELD_MAX: u64 = 0x7ff;
    type DefaultFieldType = u16;
}

pub struct BitField12;
impl BitFieldSpecifier for BitField12 {
    const FIELD_WIDTH: u8 = 12;
    const FIELD_MAX: u64 = 0xfff;
    type DefaultFieldType = u16;
}

pub struct BitField13;
impl BitFieldSpecifier for BitField13 {
    const FIELD_WIDTH: u8 = 13;
    const FIELD_MAX: u64 = 0x1fff;
    type DefaultFieldType = u16;
}

pub struct BitField14;
impl BitFieldSpecifier for BitField14 {
    const FIELD_WIDTH: u8 = 14;
    const FIELD_MAX: u64 = 0x3fff;
    type DefaultFieldType = u16;
}

pub struct BitField15;
impl BitFieldSpecifier for BitField15 {
    const FIELD_WIDTH: u8 = 15;
    const FIELD_MAX: u64 = 0x7fff;
    type DefaultFieldType = u16;
}

pub struct BitField16;
impl BitFieldSpecifier for BitField16 {
    const FIELD_WIDTH: u8 = 16;
    const FIELD_MAX: u64 = 0xffff;
    type DefaultFieldType = u16;
}

pub struct BitField17;
impl BitFieldSpecifier for BitField17 {
    const FIELD_WIDTH: u8 = 17;
    const FIELD_MAX: u64 = 0x1ffff;
    type DefaultFieldType = u32;
}

pub struct BitField18;
impl BitFieldSpecifier for BitField18 {
    const FIELD_WIDTH: u8 = 18;
    const FIELD_MAX: u64 = 0x3ffff;
    type DefaultFieldType = u32;
}

pub struct BitField19;
impl BitFieldSpecifier for BitField19 {
    const FIELD_WIDTH: u8 = 19;
    const FIELD_MAX: u64 = 0x7ffff;
    type DefaultFieldType = u32;
}

pub struct BitField20;
impl BitFieldSpecifier for BitField20 {
    const FIELD_WIDTH: u8 = 20;
    const FIELD_MAX: u64 = 0xfffff;
    type DefaultFieldType = u32;
}

pub struct BitField21;
impl BitFieldSpecifier for BitField21 {
    const FIELD_WIDTH: u8 = 21;
    const FIELD_MAX: u64 = 0x1fffff;
    type DefaultFieldType = u32;
}

pub struct BitField22;
impl BitFieldSpecifier for BitField22 {
    const FIELD_WIDTH: u8 = 22;
    const FIELD_MAX: u64 = 0x3fffff;
    type DefaultFieldType = u32;
}

pub struct BitField23;
impl BitFieldSpecifier for BitField23 {
    const FIELD_WIDTH: u8 = 23;
    const FIELD_MAX: u64 = 0x7fffff;
    type DefaultFieldType = u32;
}

pub struct BitField24;
impl BitFieldSpecifier for BitField24 {
    const FIELD_WIDTH: u8 = 24;
    const FIELD_MAX: u64 = 0xffffff;
    type DefaultFieldType = u32;
}

pub struct BitField25;
impl BitFieldSpecifier for BitField25 {
    const FIELD_WIDTH: u8 = 25;
    const FIELD_MAX: u64 = 0x1ffffff;
    type DefaultFieldType = u32;
}

pub struct BitField26;
impl BitFieldSpecifier for BitField26 {
    const FIELD_WIDTH: u8 = 26;
    const FIELD_MAX: u64 = 0x3ffffff;
    type DefaultFieldType = u32;
}

pub struct BitField27;
impl BitFieldSpecifier for BitField27 {
    const FIELD_WIDTH: u8 = 27;
    const FIELD_MAX: u64 = 0x7ffffff;
    type DefaultFieldType = u32;
}

pub struct BitField28;
impl BitFieldSpecifier for BitField28 {
    const FIELD_WIDTH: u8 = 28;
    const FIELD_MAX: u64 = 0xfffffff;
    type DefaultFieldType = u32;
}

pub struct BitField29;
impl BitFieldSpecifier for BitField29 {
    const FIELD_WIDTH: u8 = 29;
    const FIELD_MAX: u64 = 0x1fffffff;
    type DefaultFieldType = u32;
}

pub struct BitField30;
impl BitFieldSpecifier for BitField30 {
    const FIELD_WIDTH: u8 = 30;
    const FIELD_MAX: u64 = 0x3fffffff;
    type DefaultFieldType = u32;
}

pub struct BitField31;
impl BitFieldSpecifier for BitField31 {
    const FIELD_WIDTH: u8 = 31;
    const FIELD_MAX: u64 = 0x7fffffff;
    type DefaultFieldType = u32;
}

pub struct BitField32;
impl BitFieldSpecifier for BitField32 {
    const FIELD_WIDTH: u8 = 32;
    const FIELD_MAX: u64 = 0xffffffff;
    type DefaultFieldType = u32;
}

pub struct BitField33;
impl BitFieldSpecifier for BitField33 {
    const FIELD_WIDTH: u8 = 33;
    const FIELD_MAX: u64 = 0x1ffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField34;
impl BitFieldSpecifier for BitField34 {
    const FIELD_WIDTH: u8 = 34;
    const FIELD_MAX: u64 = 0x3ffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField35;
impl BitFieldSpecifier for BitField35 {
    const FIELD_WIDTH: u8 = 35;
    const FIELD_MAX: u64 = 0x7ffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField36;
impl BitFieldSpecifier for BitField36 {
    const FIELD_WIDTH: u8 = 36;
    const FIELD_MAX: u64 = 0xfffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField37;
impl BitFieldSpecifier for BitField37 {
    const FIELD_WIDTH: u8 = 37;
    const FIELD_MAX: u64 = 0x1fffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField38;
impl BitFieldSpecifier for BitField38 {
    const FIELD_WIDTH: u8 = 38;
    const FIELD_MAX: u64 = 0x3fffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField39;
impl BitFieldSpecifier for BitField39 {
    const FIELD_WIDTH: u8 = 39;
    const FIELD_MAX: u64 = 0x7fffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField40;
impl BitFieldSpecifier for BitField40 {
    const FIELD_WIDTH: u8 = 40;
    const FIELD_MAX: u64 = 0xffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField41;
impl BitFieldSpecifier for BitField41 {
    const FIELD_WIDTH: u8 = 41;
    const FIELD_MAX: u64 = 0x1ffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField42;
impl BitFieldSpecifier for BitField42 {
    const FIELD_WIDTH: u8 = 42;
    const FIELD_MAX: u64 = 0x3ffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField43;
impl BitFieldSpecifier for BitField43 {
    const FIELD_WIDTH: u8 = 43;
    const FIELD_MAX: u64 = 0x7ffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField44;
impl BitFieldSpecifier for BitField44 {
    const FIELD_WIDTH: u8 = 44;
    const FIELD_MAX: u64 = 0xfffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField45;
impl BitFieldSpecifier for BitField45 {
    const FIELD_WIDTH: u8 = 45;
    const FIELD_MAX: u64 = 0x1fffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField46;
impl BitFieldSpecifier for BitField46 {
    const FIELD_WIDTH: u8 = 46;
    const FIELD_MAX: u64 = 0x3fffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField47;
impl BitFieldSpecifier for BitField47 {
    const FIELD_WIDTH: u8 = 47;
    const FIELD_MAX: u64 = 0x7fffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField48;
impl BitFieldSpecifier for BitField48 {
    const FIELD_WIDTH: u8 = 48;
    const FIELD_MAX: u64 = 0xffffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField49;
impl BitFieldSpecifier for BitField49 {
    const FIELD_WIDTH: u8 = 49;
    const FIELD_MAX: u64 = 0x1ffffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField50;
impl BitFieldSpecifier for BitField50 {
    const FIELD_WIDTH: u8 = 50;
    const FIELD_MAX: u64 = 0x3ffffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField51;
impl BitFieldSpecifier for BitField51 {
    const FIELD_WIDTH: u8 = 51;
    const FIELD_MAX: u64 = 0x7ffffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField52;
impl BitFieldSpecifier for BitField52 {
    const FIELD_WIDTH: u8 = 52;
    const FIELD_MAX: u64 = 0xfffffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField53;
impl BitFieldSpecifier for BitField53 {
    const FIELD_WIDTH: u8 = 53;
    const FIELD_MAX: u64 = 0x1fffffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField54;
impl BitFieldSpecifier for BitField54 {
    const FIELD_WIDTH: u8 = 54;
    const FIELD_MAX: u64 = 0x3fffffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField55;
impl BitFieldSpecifier for BitField55 {
    const FIELD_WIDTH: u8 = 55;
    const FIELD_MAX: u64 = 0x7fffffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField56;
impl BitFieldSpecifier for BitField56 {
    const FIELD_WIDTH: u8 = 56;
    const FIELD_MAX: u64 = 0xffffffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField57;
impl BitFieldSpecifier for BitField57 {
    const FIELD_WIDTH: u8 = 57;
    const FIELD_MAX: u64 = 0x1ffffffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField58;
impl BitFieldSpecifier for BitField58 {
    const FIELD_WIDTH: u8 = 58;
    const FIELD_MAX: u64 = 0x3ffffffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField59;
impl BitFieldSpecifier for BitField59 {
    const FIELD_WIDTH: u8 = 59;
    const FIELD_MAX: u64 = 0x7ffffffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField60;
impl BitFieldSpecifier for BitField60 {
    const FIELD_WIDTH: u8 = 60;
    const FIELD_MAX: u64 = 0xfffffffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField61;
impl BitFieldSpecifier for BitField61 {
    const FIELD_WIDTH: u8 = 61;
    const FIELD_MAX: u64 = 0x1fffffffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField62;
impl BitFieldSpecifier for BitField62 {
    const FIELD_WIDTH: u8 = 62;
    const FIELD_MAX: u64 = 0x3fffffffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField63;
impl BitFieldSpecifier for BitField63 {
    const FIELD_WIDTH: u8 = 63;
    const FIELD_MAX: u64 = 0x7fffffffffffffff;
    type DefaultFieldType = u64;
}

pub struct BitField64;
impl BitFieldSpecifier for BitField64 {
    const FIELD_WIDTH: u8 = 64;
    const FIELD_MAX: u64 = 0xffffffffffffffff;
    type DefaultFieldType = u64;
}

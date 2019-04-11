// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This crate provides a `#[bitfield]` attribute macro for defining structs in
//! a packed binary representation that supports access to ranges of bits.
//!
//! We conceptualize one of these structs as a sequence of bits 0..N. The bits
//! are grouped into fields in the order specified by a struct written by the
//! caller. The `#[bitfield]` attribute rewrites the caller's struct into a
//! private byte array representation with public getter and setter methods for
//! each field.
//!
//! Byte order: note that we consider the bit `i` to be the `i % 8`'th least
//! significant bit in the `i / 8`'th byte of the struct.
//!
//! The total number of bits N is required to be a multiple of 8 (this is
//! checked at compile time).
//!
//! # Examples
//!
//! The following invocation builds a struct with a total size of 32 bits or 4
//! bytes. It places field `a` in the least significant bit of the first byte,
//! field `b` in the next three least significant bits, field `c` in the
//! remaining four most significant bits of the first byte, and field `d`
//! spanning the next three bytes. The least significant byte of `d` will be
//! held in the second byte of our struct, adjacent to the byte holding the
//! first three fields.
//!
//! ```
//! use bit_field::*;
//!
//! #[bitfield]
//! pub struct MyFourBytes {
//!     a: B1,
//!     b: B3,
//!     c: B4,
//!     d: B24,
//! }
//! ```
//!
//! ```text
//!                                             less significant
//!                                            /             more significant
//!                                           /             /
//!      (first byte)      (second byte)     /   (third)   /   (fourth byte)
//!     0 1 2 3 4 5 6 7   0 1 2 3 4 5 6 7   0 1 2 3 4 5 6 7   0 1 2 3 4 5 6 7
//!     |  \ /   \_ _/     \_______________________ _______________________/
//!     a   b      c        less significant       d       more significant
//! ```
//!
//! The code emitted by the `#[bitfield]` macro for this struct is as follows.
//! Note that the field getters and setters use whichever of `u8`, `u16`, `u32`,
//! `u64` is the smallest while being at least as large as the number of bits in
//! the field.
//!
//! ```ignore
//! impl MyFourBytes {
//!     // Initializes all fields to 0.
//!     pub fn new() -> Self;
//!
//!     // Field getters and setters:
//!     pub fn get_a(&self) -> u8;
//!     pub fn set_a(&mut self, val: u8);
//!     pub fn get_b(&self) -> u8;
//!     pub fn set_b(&mut self, val: u8);
//!     pub fn get_c(&self) -> u8;
//!     pub fn set_c(&mut self, val: u8);
//!     pub fn get_d(&self) -> u32;
//!     pub fn set_d(&mut self, val: u32);
//!
//!     // Bit-level accessors:
//!     pub fn get_bit(&self, offset: usize) -> bool;
//!     pub fn set_bit(&mut self, offset: usize, val: bool);
//!     pub fn get(&self, offset: usize, width: u8) -> u64;
//!     pub fn set(&mut self, offset: usize, width: u8, val: u64);
//! }
//! ```
//!
//! # Bit field specifier types
//!
//! Field types may be specified as B1 through B64, or alternatively as
//! BitField1 through BitField64 in code that benefits from the clarification.
//!
//! Fields may also be specified as `bool`, which is laid out equivalently to
//! `B1` but with accessors that use `bool` rather than `u8`.
//!
//! ```
//! use bit_field::*;
//!
//! #[bitfield]
//! pub struct MyFourBytes {
//!     a: bool,
//!     b: B3,
//!     c: B4,
//!     d: B24,
//! }
//! ```
//!
//! Fields may be user-defined single element tuple struct with primitive types. Use must specify
//! the width with `#[bits = N]`. This should be used to improve type safety.
//!
//! ```
//! use bit_field::*;
//!
//! #[bitfield]
//! #[bits = 60]
//! struct AddressField(u64);
//!
//! impl AddressField {
//!     pub fn new(addr: u64) -> AddressField {
//!         AddressField(addr >> 4)
//!     }
//!
//!     pub fn get_addr(&self) -> u64 {
//!         self.0 << 4
//!     }
//! }
//!
//! ```
//!
//! Finally, fields may be of user-defined enum types. The enum must satisfy one of the following
//! requirements.
//!
//! The enum has `#[bits = N]` attributes with it. `N` will be the width of the field. The getter
//! function of this enum field will return `Result<EnumType, u64>`. Raw value that does not match
//! any variant will result in an `Err(u64)`.
//!
//! ```
//! use bit_field::*;
//!
//! #[bitfield]
//! #[bits = 2]
//! #[derive(Debug, PartialEq)]
//! enum TwoBits {
//!     Zero = 0b00,
//!     One = 0b01,
//!     Three = 0b11,
//! }
//!
//! #[bitfield]
//! struct Struct {
//!     prefix: BitField1,
//!     two_bits: TwoBits,
//!     suffix: BitField5,
//! }
//! ```
//!
//! The enum has a number of variants which is a power of 2 and the discriminant values
//! (explicit or implicit) are 0 through (2^n)-1. In this case the generated
//! getter and setter are defined in terms of the given enum type.
//!
//! ```
//! use bit_field::*;
//!
//! #[bitfield]
//! #[derive(Debug, PartialEq)]
//! enum TwoBits {
//!     Zero = 0b00,
//!     One = 0b01,
//!     Two = 0b10,
//!     Three = 0b11,
//! }
//!
//! #[bitfield]
//! struct Struct {
//!     prefix: BitField1,
//!     two_bits: TwoBits,
//!     suffix: BitField5,
//! }
//! ```
//!
//! An optional `#[bits = N]` attribute may be used to document the number of
//! bits in any field. This is intended for fields of enum type whose name does
//! not clearly indicate the number of bits. The attribute is optional but helps
//! make it possible to read off the field sizes directly from the definition of
//! a bitfield struct.
//!
//! ```
//! use bit_field::*;
//!
//! #[bitfield]
//! #[derive(Debug, PartialEq)]
//! enum WhoKnows {
//!     Zero = 0b00,
//!     One = 0b01,
//!     Two = 0b10,
//!     Three = 0b11,
//! }
//!
//! #[bitfield]
//! struct Struct {
//!     prefix: BitField1,
//!     #[bits = 2]
//!     two_bits: WhoKnows,
//!     suffix: BitField5,
//! }
//! ```
//!
//! # Derives
//!
//! Derives may be specified and are applied to the data structure post
//! rewriting by the macro.
//!
//! ```
//! use bit_field::*;
//!
//! #[bitfield]
//! #[derive(Copy, Clone)]
//! pub struct ExampleWithDerives {
//!     car: B4,
//!     cdr: B4,
//! }
//! ```
//!
//! # Compile time checks
//!
//! If the total size is not a multiple of 8 bits, you will receive an error
//! message at compile time mentioning:
//!
//! > the trait `bit_field::checks::TotalSizeIsMultipleOfEightBits` is not implemented
//!
//! ```compile_fail
//! use bit_field::*;
//!
//! #[bitfield]
//! pub struct Broken {
//!     field_a: B1,
//!     field_b: B3,
//!     field_c: B6,
//! }
//! ```
//!
//! If a bitfield enum has discriminants that are outside the range 0 through
//! (2^n)-1, it will be caught at compile time.
//!
//! ```compile_fail
//! use bit_field::*;
//!
//! #[bitfield]
//! enum Broken {
//!     Zero = 0b00,
//!     One = 0b01,
//!     Two = 0b10,
//!     Nine = 0b1001, // error
//! }
//! ```
//!
//! If the value provided in a #[bits = N] attribute does not match the real
//! number of bits in that field, it will be caught.
//!
//! ```compile_fail
//! use bit_field::*;
//!
//! #[bitfield]
//! #[derive(Debug, PartialEq)]
//! enum OneBit {
//!     No = 0,
//!     Yes = 1,
//! }
//!
//! #[bitfield]
//! struct Struct {
//!     #[bits = 4] // error
//!     two_bits: OneBit,
//!     padding: BitField7,
//! }
//! ```

use std::fmt::{self, Display};

pub use bit_field_derive::bitfield;

/// Error type for bit field get.
#[derive(Debug)]
pub struct Error {
    type_name: &'static str,
    val: u64,
}

impl Error {
    pub fn new(type_name: &'static str, val: u64) -> Error {
        Error { type_name, val }
    }

    pub fn raw_val(&self) -> u64 {
        self.val
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "enum field type {} has a bad value {}",
            self.type_name, self.val
        )
    }
}

impl std::error::Error for Error {}

#[doc(hidden)]
pub trait BitFieldSpecifier {
    // Width of this field in bits.
    const FIELD_WIDTH: u8;
    // Date type for setter of this field.
    // For any field, we use the closest u* type. e.g. FIELD_WIDTH <= 8 will
    // have defulat type of u8.
    // It's possible to write a custom specifier and use i8.
    type SetterType;
    // Data type for getter of this field. For enums, it will be Result<EnumType, SetterType>.
    // For others, it will be the same as SetterType.
    type GetterType;

    fn from_u64(val: u64) -> Self::GetterType;
    fn into_u64(val: Self::SetterType) -> u64;
}

// Largest u64 representable by this bit field specifier. Used by generated code
// in bit_field_derive.
#[doc(hidden)]
#[inline]
pub fn max<T: BitFieldSpecifier>() -> u64 {
    if T::FIELD_WIDTH < 64 {
        (1 << T::FIELD_WIDTH) - 1
    } else {
        u64::max_value()
    }
}

// Defines bit_field::BitField0 through bit_field::BitField64.
bit_field_derive::define_bit_field_specifiers!();

impl BitFieldSpecifier for bool {
    const FIELD_WIDTH: u8 = 1;
    type SetterType = bool;
    type GetterType = bool;

    #[inline]
    fn from_u64(val: u64) -> Self::GetterType {
        val > 0
    }

    #[inline]
    fn into_u64(val: Self::SetterType) -> u64 {
        val as u64
    }
}

// Instantiated by the generated code to prove that the total size of fields is
// a multiple of 8 bits.
#[doc(hidden)]
pub struct Check<T: checks::TotalSizeIsMultipleOfEightBits> {
    marker: std::marker::PhantomData<T>,
}

mod checks {
    pub trait TotalSizeIsMultipleOfEightBits {}
    impl TotalSizeIsMultipleOfEightBits for [u8; 0] {}
}

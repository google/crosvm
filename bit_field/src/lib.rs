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
//! extern crate bit_field;
//!
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
//! We also accept `bool` as a field type, which is laid out equivalently to
//! `B1` but with accessors that use `bool` rather than `u8`.
//!
//! ```
//! extern crate bit_field;
//!
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
//! Derives may be specified and are applied to the data structure post
//! rewriting by the macro.
//!
//! ```
//! extern crate bit_field;
//!
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
//! If the total size is not a multiple of 8 bits, you will receive an error
//! message at compile time mentioning:
//!
//! > the trait `bit_field::checks::TotalSizeIsMultipleOfEightBits` is not implemented
//!
//! ```compile_fail
//! extern crate bit_field;
//!
//! use bit_field::*;
//!
//! #[bitfield]
//! pub struct Broken {
//!     field_a: B1,
//!     field_b: B3,
//!     field_c: B6,
//! }
//! ```

#[allow(unused_imports)]
#[macro_use]
extern crate bit_field_derive;

pub use bit_field_derive::bitfield;

// This trait is sealed and not intended to be implemented outside of the
// bit_field crate.
#[doc(hidden)]
pub trait BitFieldSpecifier: private::Sealed {
    // Width of this field in bits.
    const FIELD_WIDTH: u8;
    // Default data type of this field.
    // For any field, we use the closest u* type. e.g. FIELD_WIDTH <= 8 will
    // have defulat type of u8.
    // It's possible to write a custom specifier and use i8.
    type DefaultFieldType;

    fn from_u64(val: u64) -> Self::DefaultFieldType;
    fn into_u64(val: Self::DefaultFieldType) -> u64;
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
    type DefaultFieldType = bool;

    #[inline]
    fn from_u64(val: u64) -> Self::DefaultFieldType {
        val > 0
    }

    #[inline]
    fn into_u64(val: Self::DefaultFieldType) -> u64 {
        val as u64
    }
}

impl private::Sealed for bool {}

mod private {
    // Seal for the BitFieldSpecifier trait. This seal trait is not nameable
    // outside of the bit_field crate, so we are guaranteed that all impls of
    // BitFieldSpecifier come from within this crate.
    pub trait Sealed {}
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

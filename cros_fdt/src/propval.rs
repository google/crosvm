// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module implements FDT property value conversions as defined by the device tree format.

use std::mem::size_of_val;

use crate::fdt::c_str_to_string;
use crate::fdt::Error;
use crate::fdt::Result;
use crate::fdt::SIZE_U32;
use crate::fdt::SIZE_U64;

/// Conversion into an FDT property value.
///
/// Implementing `ToFdtPropval` for a type defines its conversion to a raw
/// FDT property value (a byte vector).
pub trait ToFdtPropval {
    // Convert the type to its byte representation as an FDT property.
    fn to_propval(self) -> Result<Vec<u8>>;
}

#[inline]
fn u32_to_bytes(value: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(size_of_val(value));
    for val in value {
        bytes.extend_from_slice(&val.to_be_bytes())
    }
    bytes
}

#[inline]
fn u64_to_bytes(value: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(size_of_val(value));
    for val in value {
        bytes.extend_from_slice(&val.to_be_bytes())
    }
    bytes
}

impl ToFdtPropval for () {
    fn to_propval(self) -> Result<Vec<u8>> {
        Ok(vec![])
    }
}

impl ToFdtPropval for &[u8] {
    fn to_propval(self) -> Result<Vec<u8>> {
        Ok(self.into())
    }
}

impl<const N: usize> ToFdtPropval for &[u8; N] {
    fn to_propval(self) -> Result<Vec<u8>> {
        Ok(self.to_vec())
    }
}

impl ToFdtPropval for Vec<u8> {
    fn to_propval(self) -> Result<Vec<u8>> {
        Ok(self)
    }
}

impl ToFdtPropval for u32 {
    fn to_propval(self) -> Result<Vec<u8>> {
        Ok(u32_to_bytes(std::slice::from_ref(&self)))
    }
}

impl ToFdtPropval for &[u32] {
    fn to_propval(self) -> Result<Vec<u8>> {
        Ok(u32_to_bytes(self))
    }
}

impl<const N: usize> ToFdtPropval for &[u32; N] {
    fn to_propval(self) -> Result<Vec<u8>> {
        Ok(u32_to_bytes(self))
    }
}

impl ToFdtPropval for Vec<u32> {
    fn to_propval(self) -> Result<Vec<u8>> {
        Ok(u32_to_bytes(self.as_slice()))
    }
}

impl ToFdtPropval for u64 {
    fn to_propval(self) -> Result<Vec<u8>> {
        Ok(u64_to_bytes(std::slice::from_ref(&self)))
    }
}

impl ToFdtPropval for &[u64] {
    fn to_propval(self) -> Result<Vec<u8>> {
        Ok(u64_to_bytes(self))
    }
}

impl<const N: usize> ToFdtPropval for &[u64; N] {
    fn to_propval(self) -> Result<Vec<u8>> {
        Ok(u64_to_bytes(self))
    }
}

impl ToFdtPropval for Vec<u64> {
    fn to_propval(self) -> Result<Vec<u8>> {
        Ok(u64_to_bytes(self.as_slice()))
    }
}

#[inline]
fn is_valid_string_property(val: &str) -> bool {
    // Although the devicetree spec says string properties should be printable, neither libfdt nor
    // the kernel device tree API verify that, so only check for zero bytes.
    !val.contains('\0')
}

#[inline]
fn str_to_bytes<T: AsRef<str>>(value: &[T]) -> Result<Vec<u8>> {
    let total_length = value.iter().map(|s| s.as_ref().len() + 1).sum();
    let mut bytes = Vec::with_capacity(total_length);
    for s in value {
        let s = s.as_ref();
        if !is_valid_string_property(s) {
            return Err(Error::InvalidString(s.to_owned()));
        }
        bytes.extend_from_slice(s.as_bytes());
        bytes.push(0);
    }
    Ok(bytes)
}

impl ToFdtPropval for &str {
    fn to_propval(self) -> Result<Vec<u8>> {
        str_to_bytes(std::slice::from_ref(&self))
    }
}

impl ToFdtPropval for &[&str] {
    fn to_propval(self) -> Result<Vec<u8>> {
        str_to_bytes(self)
    }
}

impl<const N: usize> ToFdtPropval for &[&str; N] {
    fn to_propval(self) -> Result<Vec<u8>> {
        str_to_bytes(self)
    }
}

impl ToFdtPropval for String {
    fn to_propval(self) -> Result<Vec<u8>> {
        if !is_valid_string_property(&self) {
            Err(Error::InvalidString(self))
        } else {
            let mut bytes = self.into_bytes();
            bytes.push(0);
            Ok(bytes)
        }
    }
}

impl ToFdtPropval for Vec<String> {
    fn to_propval(self) -> Result<Vec<u8>> {
        str_to_bytes(&self)
    }
}

/// Conversion from an FDT property value.
///
/// Implementing `FromFdtPropval` for a type defines its construction from a raw
/// FDT property value (a byte slice).
pub trait FromFdtPropval {
    // Try to convert FDT property bytes to `Self`, return `None` if impossible.
    fn from_propval(propval: &[u8]) -> Option<Self>
    where
        Self: Sized;
}

impl FromFdtPropval for () {
    fn from_propval(propval: &[u8]) -> Option<Self> {
        propval.is_empty().then_some(())
    }
}

impl FromFdtPropval for Vec<u8> {
    fn from_propval(propval: &[u8]) -> Option<Self> {
        Some(propval.into())
    }
}

impl FromFdtPropval for u32 {
    fn from_propval(propval: &[u8]) -> Option<Self> {
        if propval.len() == SIZE_U32 {
            Some(u32::from_be_bytes(propval.try_into().unwrap()))
        } else {
            None
        }
    }
}

impl FromFdtPropval for Vec<u32> {
    fn from_propval(propval: &[u8]) -> Option<Self> {
        if propval.len() % SIZE_U32 != 0 {
            None
        } else {
            Some(
                propval
                    .chunks(SIZE_U32)
                    .map(|v| u32::from_be_bytes(v.try_into().unwrap()))
                    .collect(),
            )
        }
    }
}

impl FromFdtPropval for u64 {
    fn from_propval(propval: &[u8]) -> Option<Self> {
        if propval.len() == SIZE_U64 {
            Some(u64::from_be_bytes(propval.try_into().unwrap()))
        } else {
            None
        }
    }
}

impl FromFdtPropval for Vec<u64> {
    fn from_propval(propval: &[u8]) -> Option<Self> {
        if propval.len() % SIZE_U64 != 0 {
            None
        } else {
            Some(
                propval
                    .chunks(SIZE_U64)
                    .map(|v| u64::from_be_bytes(v.try_into().unwrap()))
                    .collect(),
            )
        }
    }
}

impl FromFdtPropval for String {
    fn from_propval(propval: &[u8]) -> Option<Self> {
        c_str_to_string(propval)
    }
}

impl FromFdtPropval for Vec<String> {
    fn from_propval(propval: &[u8]) -> Option<Self> {
        if Some(&0) == propval.last() {
            Some(
                propval
                    .split(|&b| b == 0u8)
                    .take_while(|s| !s.is_empty())
                    .filter_map(|b| String::from_utf8(b.into()).ok())
                    .collect(),
            )
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fdt_as_propval() {
        assert_eq!(().to_propval().unwrap(), []);
        assert_eq!([0u8, 1u8, 2u8].to_propval().unwrap(), [0u8, 1u8, 2u8]);
        assert_eq!(0x1u32.to_propval().unwrap(), [0u8, 0, 0, 1]);
        assert_eq!(
            0x12345678u32.to_propval().unwrap(),
            [0x12u8, 0x34, 0x56, 0x78]
        );
        assert_eq!(
            0x12345678ABCDu64.to_propval().unwrap(),
            [0x00u8, 0x00, 0x12, 0x34, 0x56, 0x78, 0xAB, 0xCD]
        );
        assert_eq!(
            [0x1u32, 0xABCDu32].to_propval().unwrap(),
            [0x00u8, 0x00, 0x00, 0x01, 0x00, 0x00, 0xAB, 0xCD]
        );
        assert_eq!(
            [0x1u64, 0xABCD00000000u64].to_propval().unwrap(),
            [
                0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xAB, 0xCD, 0x00,
                0x00, 0x00, 0x00,
            ]
        );
        assert_eq!(
            "abc def".to_propval().unwrap(),
            [0x61u8, 0x62, 0x63, 0x20, 0x64, 0x65, 0x66, 0x00,]
        );
        assert_eq!(
            ["abc def", "ghi jkl", "mno pqr"].to_propval().unwrap(),
            [
                0x61u8, 0x62, 0x63, 0x20, 0x64, 0x65, 0x66, 0x00, 0x67u8, 0x68, 0x69, 0x20, 0x6A,
                0x6B, 0x6C, 0x00, 0x6Du8, 0x6E, 0x6F, 0x20, 0x70, 0x71, 0x72, 0x00,
            ]
        );
        "abc\0def".to_propval().expect_err("invalid string");
    }

    #[test]
    fn fdt_from_propval() {
        assert_eq!(Vec::<u8>::from_propval(&[]).unwrap(), []);
        assert_eq!(u32::from_propval(&[0, 0, 0, 1]).unwrap(), 1u32);
        assert_eq!(
            u32::from_propval(&[0x12u8, 0x34, 0x56, 0x78]).unwrap(),
            0x12345678u32
        );
        assert_eq!(
            u64::from_propval(&[0x00u8, 0x00, 0x12, 0x34, 0x56, 0x78, 0xAB, 0xCD]).unwrap(),
            0x12345678ABCDu64
        );
        assert_eq!(
            Vec::<u32>::from_propval(&[0x00u8, 0x00, 0x00, 0x01, 0x00, 0x00, 0xAB, 0xCD]).unwrap(),
            [0x1u32, 0xABCDu32]
        );
        assert_eq!(
            Vec::<u64>::from_propval(&[
                0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xAB, 0xCD, 0x00,
                0x00, 0x00, 0x00
            ])
            .unwrap(),
            [0x1u64, 0xABCD00000000u64]
        );
        assert_eq!(
            String::from_propval(&[0x61u8, 0x62, 0x63, 0x20, 0x64, 0x65, 0x66, 0x00]).unwrap(),
            "abc def"
        );
        assert_eq!(
            Vec::<String>::from_propval(&[
                0x61u8, 0x62, 0x63, 0x20, 0x64, 0x65, 0x66, 0x00, 0x67u8, 0x68, 0x69, 0x20, 0x6A,
                0x6B, 0x6C, 0x00, 0x6Du8, 0x6E, 0x6F, 0x20, 0x70, 0x71, 0x72, 0x00,
            ])
            .unwrap(),
            ["abc def", "ghi jkl", "mno pqr"],
        );

        assert!(Vec::<String>::from_propval(&[
            0x61u8, 0x62, 0x63, 0x20, 0x64, 0x65, 0x66, 0x00, 0x67u8, 0x68,
        ])
        .is_none());
        assert!(String::from_propval(&[0x61u8, 0x62, 0x63]).is_none());
        assert!(u32::from_propval(&[0x61u8, 0x62]).is_none());
        assert!(u64::from_propval(&[0x61u8, 0x62, 0x61u8, 0x62, 0x61u8, 0x62]).is_none());
    }
}

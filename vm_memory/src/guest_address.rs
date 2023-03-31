// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Represents an address in the guest's memory space.

use std::cmp::Eq;
use std::cmp::Ord;
use std::cmp::Ordering;
use std::cmp::PartialEq;
use std::cmp::PartialOrd;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::ops::BitAnd;
use std::ops::BitOr;

use serde::Deserialize;
use serde::Serialize;

/// Represents an Address in the guest's memory.
#[derive(Clone, Copy, Deserialize, Serialize)]
pub struct GuestAddress(pub u64);

impl Debug for GuestAddress {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "GuestAddress({:#018x})", self.0)
    }
}

impl GuestAddress {
    /// Returns the offset from this address to the given base address.
    ///
    /// # Examples
    ///
    /// ```
    /// # use vm_memory::GuestAddress;
    ///   let base = GuestAddress(0x100);
    ///   let addr = GuestAddress(0x150);
    ///   assert_eq!(addr.offset_from(base), 0x50u64);
    /// ```
    pub fn offset_from(self, base: GuestAddress) -> u64 {
        self.0 - base.0
    }

    /// Returns the address as a u64 offset from 0x0.
    /// Use this when a raw number is needed to pass to the kernel.
    pub fn offset(self) -> u64 {
        self.0
    }

    /// Returns the result of the add or None if there is overflow.
    pub fn checked_add(self, other: u64) -> Option<GuestAddress> {
        self.0.checked_add(other).map(GuestAddress)
    }

    /// Returns the result of the base address + the size.
    /// Only use this when `offset` is guaranteed not to overflow.
    pub fn unchecked_add(self, offset: u64) -> GuestAddress {
        GuestAddress(self.0 + offset)
    }

    /// Returns the result of the subtraction of None if there is underflow.
    pub fn checked_sub(self, other: u64) -> Option<GuestAddress> {
        self.0.checked_sub(other).map(GuestAddress)
    }

    /// Returns the bitwise and of the address with the given mask.
    pub fn mask(self, mask: u64) -> GuestAddress {
        GuestAddress(self.0 & mask)
    }

    /// Returns the next highest address that is a multiple of `align`, or an unchanged copy of the
    /// address if it's already a multiple of `align`.  Returns None on overflow.
    ///
    /// `align` must be a power of 2.
    pub fn align(self, align: u64) -> Option<GuestAddress> {
        if align <= 1 {
            return Some(self);
        }
        self.checked_add(align - 1).map(|a| a & !(align - 1))
    }
}

impl BitAnd<u64> for GuestAddress {
    type Output = GuestAddress;

    fn bitand(self, other: u64) -> GuestAddress {
        GuestAddress(self.0 & other)
    }
}

impl BitOr<u64> for GuestAddress {
    type Output = GuestAddress;

    fn bitor(self, other: u64) -> GuestAddress {
        GuestAddress(self.0 | other)
    }
}

impl PartialEq for GuestAddress {
    fn eq(&self, other: &GuestAddress) -> bool {
        self.0 == other.0
    }
}
impl Eq for GuestAddress {}

impl Ord for GuestAddress {
    fn cmp(&self, other: &GuestAddress) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for GuestAddress {
    fn partial_cmp(&self, other: &GuestAddress) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for GuestAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equals() {
        let a = GuestAddress(0x300);
        let b = GuestAddress(0x300);
        let c = GuestAddress(0x301);
        assert_eq!(a, b);
        assert_eq!(b, a);
        assert_ne!(a, c);
        assert_ne!(c, a);
    }

    #[test]
    #[allow(clippy::eq_op)]
    #[allow(clippy::nonminimal_bool)]
    fn cmp() {
        let a = GuestAddress(0x300);
        let b = GuestAddress(0x301);
        assert!(a < b);
        assert!(b > a);
        assert!(!(a < a));
        assert!(a >= a);
    }

    #[test]
    fn mask() {
        let a = GuestAddress(0x5050);
        assert_eq!(GuestAddress(0x5000), a & 0xff00u64);
        assert_eq!(GuestAddress(0x5055), a | 0x0005u64);
    }

    #[test]
    fn add_sub() {
        let a = GuestAddress(0x50);
        let b = GuestAddress(0x60);
        assert_eq!(Some(GuestAddress(0xb0)), a.checked_add(0x60));
        assert_eq!(0x10, b.offset_from(a));
    }

    #[test]
    fn checked_add_overflow() {
        let a = GuestAddress(0xffffffffffffff55);
        assert_eq!(Some(GuestAddress(0xffffffffffffff57)), a.checked_add(2));
        assert!(a.checked_add(0xf0).is_none());
    }

    #[test]
    fn align() {
        assert_eq!(GuestAddress(12345).align(0), Some(GuestAddress(12345)));
        assert_eq!(GuestAddress(12345).align(1), Some(GuestAddress(12345)));
        assert_eq!(GuestAddress(12345).align(2), Some(GuestAddress(12346)));
        assert_eq!(GuestAddress(0).align(4096), Some(GuestAddress(0)));
        assert_eq!(GuestAddress(1).align(4096), Some(GuestAddress(4096)));
        assert_eq!(GuestAddress(4095).align(4096), Some(GuestAddress(4096)));
        assert_eq!(GuestAddress(4096).align(4096), Some(GuestAddress(4096)));
        assert_eq!(GuestAddress(4097).align(4096), Some(GuestAddress(8192)));
        assert_eq!(
            GuestAddress(u64::MAX & !4095).align(4096),
            Some(GuestAddress(u64::MAX & !4095)),
        );
        assert_eq!(GuestAddress(u64::MAX).align(2), None);
    }
}

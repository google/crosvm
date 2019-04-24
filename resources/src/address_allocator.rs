// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp;
use std::collections::HashMap;

use crate::{Alloc, Error, Result};

/// Manages allocating address ranges.
/// Use `AddressAllocator` whenever an address range needs to be allocated to different users.
/// Allocations must be uniquely tagged with an Alloc enum, which can be used for lookup.
/// An human-readable tag String must also be provided for debugging / reference.
///
/// # Examples
///
/// ```
/// // Anon is used for brevity. Don't manually instantiate Anon allocs!
/// # use resources::{Alloc, AddressAllocator};
///   AddressAllocator::new(0x1000, 0x10000, Some(0x100)).map(|mut pool| {
///       assert_eq!(pool.allocate(0x110, Alloc::Anon(0), "caps".to_string()), Ok(0x1000));
///       assert_eq!(pool.allocate(0x100, Alloc::Anon(1), "cache".to_string()), Ok(0x1200));
///       assert_eq!(pool.allocate(0x100, Alloc::Anon(2), "etc".to_string()), Ok(0x1300));
///       assert_eq!(pool.get(&Alloc::Anon(1)), Some(&(0x1200, 0x100, "cache".to_string())));
///   });
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct AddressAllocator {
    pool_base: u64,
    pool_end: u64,
    alignment: u64,
    next_addr: u64,
    allocs: HashMap<Alloc, (u64, u64, String)>,
}

impl AddressAllocator {
    /// Creates a new `AddressAllocator` for managing a range of addresses.
    /// Can return `None` if `pool_base` + `pool_size` overflows a u64 or if alignment isn't a power
    /// of two.
    ///
    /// * `pool_base` - The starting address of the range to manage.
    /// * `pool_size` - The size of the address range in bytes.
    /// * `align_size` - The minimum size of an address region to align to, defaults to four.
    pub fn new(pool_base: u64, pool_size: u64, align_size: Option<u64>) -> Result<Self> {
        if pool_size == 0 {
            return Err(Error::PoolSizeZero);
        }
        let pool_end = pool_base
            .checked_add(pool_size - 1)
            .ok_or(Error::PoolOverflow {
                base: pool_base,
                size: pool_size,
            })?;
        let alignment = align_size.unwrap_or(4);
        if !alignment.is_power_of_two() || alignment == 0 {
            return Err(Error::BadAlignment);
        }
        Ok(AddressAllocator {
            pool_base,
            pool_end,
            alignment,
            next_addr: pool_base,
            allocs: HashMap::new(),
        })
    }

    /// Allocates a range of addresses from the managed region with an optional tag
    /// and minimal alignment. Returns allocated_address. (allocated_address, size, tag)
    /// can be retrieved through the `get` method.
    pub fn allocate_with_align(
        &mut self,
        size: u64,
        alloc: Alloc,
        tag: String,
        alignment: u64,
    ) -> Result<u64> {
        let alignment = cmp::max(self.alignment, alignment);

        if self.allocs.contains_key(&alloc) {
            return Err(Error::ExistingAlloc(alloc));
        }
        if size == 0 {
            return Err(Error::AllocSizeZero);
        }
        if !alignment.is_power_of_two() {
            return Err(Error::BadAlignment);
        }
        let align_adjust = if self.next_addr % alignment != 0 {
            alignment - (self.next_addr % alignment)
        } else {
            0
        };
        let addr = self
            .next_addr
            .checked_add(align_adjust)
            .ok_or(Error::OutOfSpace)?;
        let end_addr = addr.checked_add(size - 1).ok_or(Error::OutOfSpace)?;
        if end_addr > self.pool_end {
            return Err(Error::OutOfSpace);
        }

        // TODO(dgreid): Use a smarter allocation strategy. The current strategy is just
        // bumping this pointer, meaning it will eventually exhaust available addresses.
        self.next_addr = end_addr.saturating_add(1);

        self.allocs.insert(alloc, (addr, size, tag));
        Ok(addr)
    }

    pub fn allocate(&mut self, size: u64, alloc: Alloc, tag: String) -> Result<u64> {
        self.allocate_with_align(size, alloc, tag, self.alignment)
    }

    /// Returns allocation associated with `alloc`, or None if no such allocation exists.
    pub fn get(&self, alloc: &Alloc) -> Option<&(u64, u64, String)> {
        self.allocs.get(alloc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_fails_overflow() {
        assert!(AddressAllocator::new(u64::max_value(), 0x100, None).is_err());
    }

    #[test]
    fn new_fails_size_zero() {
        assert!(AddressAllocator::new(0x1000, 0, None).is_err());
    }

    #[test]
    fn new_fails_alignment_zero() {
        assert!(AddressAllocator::new(0x1000, 0x10000, Some(0)).is_err());
    }

    #[test]
    fn new_fails_alignment_non_power_of_two() {
        assert!(AddressAllocator::new(0x1000, 0x10000, Some(200)).is_err());
    }

    #[test]
    fn allocate_fails_exising_alloc() {
        let mut pool = AddressAllocator::new(0x1000, 0x1000, Some(0x100)).unwrap();
        assert_eq!(
            pool.allocate(0x800, Alloc::Anon(0), String::from("bar0")),
            Ok(0x1000)
        );
        assert_eq!(
            pool.allocate(0x800, Alloc::Anon(0), String::from("bar0")),
            Err(Error::ExistingAlloc(Alloc::Anon(0)))
        );
    }

    #[test]
    fn allocate_fails_not_enough_space() {
        let mut pool = AddressAllocator::new(0x1000, 0x1000, Some(0x100)).unwrap();
        assert_eq!(
            pool.allocate(0x800, Alloc::Anon(0), String::from("bar0")),
            Ok(0x1000)
        );
        assert_eq!(
            pool.allocate(0x900, Alloc::Anon(1), String::from("bar1")),
            Err(Error::OutOfSpace)
        );
        assert_eq!(
            pool.allocate(0x800, Alloc::Anon(2), String::from("bar2")),
            Ok(0x1800)
        );
    }

    #[test]
    fn allocate_alignment() {
        let mut pool = AddressAllocator::new(0x1000, 0x10000, Some(0x100)).unwrap();
        assert_eq!(
            pool.allocate(0x110, Alloc::Anon(0), String::from("bar0")),
            Ok(0x1000)
        );
        assert_eq!(
            pool.allocate(0x100, Alloc::Anon(1), String::from("bar1")),
            Ok(0x1200)
        );
    }

    #[test]
    fn allocate_retrieve_alloc() {
        let mut pool = AddressAllocator::new(0x1000, 0x10000, Some(0x100)).unwrap();
        assert_eq!(
            pool.allocate(0x110, Alloc::Anon(0), String::from("bar0")),
            Ok(0x1000)
        );
        assert_eq!(
            pool.get(&Alloc::Anon(0)),
            Some(&(0x1000, 0x110, String::from("bar0")))
        );
    }

    #[test]
    fn allocate_with_alignment_allocator_alignment() {
        let mut pool = AddressAllocator::new(0x1000, 0x10000, Some(0x100)).unwrap();
        assert_eq!(
            pool.allocate_with_align(0x110, Alloc::Anon(0), String::from("bar0"), 0x1),
            Ok(0x1000)
        );
        assert_eq!(
            pool.allocate_with_align(0x100, Alloc::Anon(1), String::from("bar1"), 0x1),
            Ok(0x1200)
        );
    }

    #[test]
    fn allocate_with_alignment_custom_alignment() {
        let mut pool = AddressAllocator::new(0x1000, 0x10000, Some(0x4)).unwrap();
        assert_eq!(
            pool.allocate_with_align(0x110, Alloc::Anon(0), String::from("bar0"), 0x100),
            Ok(0x1000)
        );
        assert_eq!(
            pool.allocate_with_align(0x100, Alloc::Anon(1), String::from("bar1"), 0x100),
            Ok(0x1200)
        );
    }

    #[test]
    fn allocate_with_alignment_no_allocator_alignment() {
        let mut pool = AddressAllocator::new(0x1000, 0x10000, None).unwrap();
        assert_eq!(
            pool.allocate_with_align(0x110, Alloc::Anon(0), String::from("bar0"), 0x100),
            Ok(0x1000)
        );
        assert_eq!(
            pool.allocate_with_align(0x100, Alloc::Anon(1), String::from("bar1"), 0x100),
            Ok(0x1200)
        );
    }

    #[test]
    fn allocate_with_alignment_alignment_non_power_of_two() {
        let mut pool = AddressAllocator::new(0x1000, 0x10000, None).unwrap();
        assert!(pool
            .allocate_with_align(0x110, Alloc::Anon(0), String::from("bar0"), 200)
            .is_err());
    }
}

// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Manages allocating address ranges.
/// Use `AddressAllocator` whenever an address range needs to be allocated to different users.
///
/// # Examples
///
/// ```
/// # use resources::AddressAllocator;
///   AddressAllocator::new(0x1000, 0x10000, Some(0x100)).map(|mut pool| {
///       assert_eq!(pool.allocate(0x110), Some(0x1000));
///       assert_eq!(pool.allocate(0x100), Some(0x1200));
///   });
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct AddressAllocator {
    pool_base: u64,
    pool_end: u64,
    alignment: u64,
    next_addr: u64,
}

impl AddressAllocator {
    /// Creates a new `AddressAllocator` for managing a range of addresses.
    /// Can return `None` if `pool_base` + `pool_size` overflows a u64 or if alignment isn't a power
    /// of two.
    ///
    /// * `pool_base` - The starting address of the range to manage.
    /// * `pool_size` - The size of the address range in bytes.
    /// * `align_size` - The minimum size of an address region to align to, defaults to four.
    pub fn new(pool_base: u64, pool_size: u64, align_size: Option<u64>) -> Option<Self> {
        if pool_size == 0 {
            return None;
        }
        let pool_end = pool_base.checked_add(pool_size - 1)?;
        let alignment = align_size.unwrap_or(4);
        if !alignment.is_power_of_two() || alignment == 0 {
            return None;
        }
        Some(AddressAllocator {
            pool_base,
            pool_end,
            alignment,
            next_addr: pool_base,
        })
    }

    /// Allocates a range of addresses from the managed region. Returns `Some(allocated_address)`
    /// when successful, or `None` if an area of `size` can't be allocated.
    pub fn allocate(&mut self, size: u64) -> Option<u64> {
        if size == 0 {
            return None;
        }
        let align_adjust = if self.next_addr % self.alignment != 0 {
            self.alignment - (self.next_addr % self.alignment)
        } else {
            0
        };
        let addr = self.next_addr.checked_add(align_adjust)?;
        let end_addr = addr.checked_add(size - 1)?;
        if end_addr > self.pool_end {
            return None;
        }
        // TODO(dgreid): Use a smarter allocation strategy. The current strategy is just
        // bumping this pointer, meaning it will eventually exhaust available addresses.
        self.next_addr = end_addr.saturating_add(1);
        Some(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_fails_overflow() {
        assert_eq!(AddressAllocator::new(u64::max_value(), 0x100, None), None);
    }

    #[test]
    fn new_fails_size_zero() {
        assert_eq!(AddressAllocator::new(0x1000, 0, None), None);
    }

    #[test]
    fn new_fails_alignment_zero() {
        assert_eq!(AddressAllocator::new(0x1000, 0x10000, Some(0)), None);
    }

    #[test]
    fn new_fails_alignment_non_power_of_two() {
        assert_eq!(AddressAllocator::new(0x1000, 0x10000, Some(200)), None);
    }

    #[test]
    fn allocate_fails_not_enough_space() {
        let mut pool = AddressAllocator::new(0x1000, 0x1000, Some(0x100)).unwrap();
        assert_eq!(pool.allocate(0x800), Some(0x1000));
        assert_eq!(pool.allocate(0x900), None);
        assert_eq!(pool.allocate(0x800), Some(0x1800));
    }

    #[test]
    fn allocate_alignment() {
        let mut pool = AddressAllocator::new(0x1000, 0x10000, Some(0x100)).unwrap();
        assert_eq!(pool.allocate(0x110), Some(0x1000));
        assert_eq!(pool.allocate(0x100), Some(0x1200));
    }
}

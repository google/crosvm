// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp;
use std::collections::{BTreeSet, HashMap};

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
    alignment: u64,
    allocs: HashMap<Alloc, (u64, u64, String)>,
    regions: BTreeSet<(u64, u64)>,
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
        let mut regions = BTreeSet::new();
        regions.insert((pool_base, pool_end));
        Ok(AddressAllocator {
            alignment,
            allocs: HashMap::new(),
            regions,
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

        // finds first region matching alignment and size.
        match self
            .regions
            .iter()
            .find(|range| {
                match range.0 % alignment {
                    0 => range.0.checked_add(size - 1),
                    r => range.0.checked_add(size - 1 + alignment - r),
                }
                .map_or(false, |end| end <= range.1)
            })
            .cloned()
        {
            Some(slot) => {
                self.regions.remove(&slot);
                let start = match slot.0 % alignment {
                    0 => slot.0,
                    r => slot.0 + alignment - r,
                };
                let end = start + size - 1;
                if slot.0 < start {
                    self.regions.insert((slot.0, start - 1));
                }
                if slot.1 > end {
                    self.regions.insert((end + 1, slot.1));
                }
                self.allocs.insert(alloc, (start, size, tag));

                Ok(start)
            }
            None => Err(Error::OutOfSpace),
        }
    }

    pub fn allocate(&mut self, size: u64, alloc: Alloc, tag: String) -> Result<u64> {
        self.allocate_with_align(size, alloc, tag, self.alignment)
    }

    /// Allocates a range of addresses from the managed region with an optional tag
    /// and required location. Allocation alignment is not enforced.
    /// Returns OutOfSpace if requested range is not available (e.g. already allocated
    /// with a different alloc tag).
    pub fn allocate_at(&mut self, start: u64, size: u64, alloc: Alloc, tag: String) -> Result<()> {
        if self.allocs.contains_key(&alloc) {
            return Err(Error::ExistingAlloc(alloc));
        }
        if size == 0 {
            return Err(Error::AllocSizeZero);
        }

        let end = start.checked_add(size - 1).ok_or(Error::OutOfSpace)?;
        match self
            .regions
            .iter()
            .find(|range| range.0 <= start && range.1 >= end)
            .cloned()
        {
            Some(slot) => {
                self.regions.remove(&slot);
                if slot.0 < start {
                    self.regions.insert((slot.0, start - 1));
                }
                if slot.1 > end {
                    self.regions.insert((end + 1, slot.1));
                }
                self.allocs.insert(alloc, (start, size, tag));

                Ok(())
            }
            None => Err(Error::OutOfSpace),
        }
    }

    /// Releases exising allocation back to free pool.
    pub fn release(&mut self, alloc: Alloc) -> Result<()> {
        self.allocs
            .remove(&alloc)
            .map_or_else(|| Err(Error::BadAlloc(alloc)), |v| self.insert_at(v.0, v.1))
    }

    /// Returns allocation associated with `alloc`, or None if no such allocation exists.
    pub fn get(&self, alloc: &Alloc) -> Option<&(u64, u64, String)> {
        self.allocs.get(alloc)
    }

    /// Insert range of addresses into the pool, coalescing neighboring regions.
    fn insert_at(&mut self, start: u64, size: u64) -> Result<()> {
        if size == 0 {
            return Err(Error::AllocSizeZero);
        }

        let mut slot = (start, start.checked_add(size - 1).ok_or(Error::OutOfSpace)?);
        let mut left = None;
        let mut right = None;
        // simple coalescing with linear search over free regions.
        //
        // Calculating the distance between start and end of two regions we can
        // detect if they are disjoint (>1), adjacent (=1) or possibly
        // overlapping (<1). Saturating arithmetic is used to avoid overflow.
        // Overlapping regions are detected if both oposite ends are overlapping.
        // Algorithm assumes all existing regions are disjoined and represented
        // as pair of inclusive location point (start, end), where end >= start.
        for range in self.regions.iter() {
            match (
                slot.0.saturating_sub(range.1),
                range.0.saturating_sub(slot.1),
            ) {
                (1, 0) => {
                    left = Some(*range);
                }
                (0, 1) => {
                    right = Some(*range);
                }
                (0, 0) => {
                    return Err(Error::RegionOverlap { base: start, size });
                }
                (_, _) => (),
            }
        }
        if let Some(left) = left {
            self.regions.remove(&left);
            slot.0 = left.0;
        }
        if let Some(right) = right {
            self.regions.remove(&right);
            slot.1 = right.1;
        }
        self.regions.insert(slot);

        Ok(())
    }

    /// Returns an address from associated PCI `alloc` given an allocation offset and size.
    pub fn address_from_pci_offset(&self, alloc: Alloc, offset: u64, size: u64) -> Result<u64> {
        match alloc {
            Alloc::PciBar { .. } => (),
            _ => return Err(Error::InvalidAlloc(alloc)),
        };

        match self.allocs.get(&alloc) {
            Some((start_addr, length, _)) => {
                let address = start_addr.checked_add(offset).ok_or(Error::OutOfBounds)?;
                let range = *start_addr..*start_addr + *length;
                let end = address.checked_add(size).ok_or(Error::OutOfBounds)?;
                match (range.contains(&address), range.contains(&end)) {
                    (true, true) => Ok(address),
                    _ => Err(Error::OutOfBounds),
                }
            }
            None => Err(Error::InvalidAlloc(alloc)),
        }
    }
}

/// Contains a set of `AddressAllocator`s for allocating address ranges.
/// When attempting an allocation, each allocator will be tried in order until
/// the allocation is successful.
/// See `AddressAllocator` for function documentation.
pub struct AddressAllocatorSet<'a> {
    allocators: &'a mut [AddressAllocator],
}

impl<'a> AddressAllocatorSet<'a> {
    pub fn new(allocators: &'a mut [AddressAllocator]) -> Self {
        AddressAllocatorSet { allocators }
    }

    pub fn allocate_with_align(
        &mut self,
        size: u64,
        alloc: Alloc,
        tag: String,
        alignment: u64,
    ) -> Result<u64> {
        let mut last_res = Err(Error::OutOfSpace);
        for allocator in self.allocators.iter_mut() {
            last_res = allocator.allocate_with_align(size, alloc, tag.clone(), alignment);
            if last_res.is_ok() {
                return last_res;
            }
        }
        last_res
    }

    pub fn allocate(&mut self, size: u64, alloc: Alloc, tag: String) -> Result<u64> {
        let mut last_res = Err(Error::OutOfSpace);
        for allocator in self.allocators.iter_mut() {
            last_res = allocator.allocate(size, alloc, tag.clone());
            if last_res.is_ok() {
                return last_res;
            }
        }
        last_res
    }

    pub fn allocate_at(&mut self, start: u64, size: u64, alloc: Alloc, tag: String) -> Result<()> {
        let mut last_res = Err(Error::OutOfSpace);
        for allocator in self.allocators.iter_mut() {
            last_res = allocator.allocate_at(start, size, alloc, tag.clone());
            if last_res.is_ok() {
                return last_res;
            }
        }
        last_res
    }

    pub fn release(&mut self, alloc: Alloc) -> Result<()> {
        let mut last_res = Err(Error::OutOfSpace);
        for allocator in self.allocators.iter_mut() {
            last_res = allocator.release(alloc);
            if last_res.is_ok() {
                return last_res;
            }
        }
        last_res
    }

    pub fn get(&self, alloc: &Alloc) -> Option<&(u64, u64, String)> {
        for allocator in self.allocators.iter() {
            let opt = allocator.get(alloc);
            if opt.is_some() {
                return opt;
            }
        }
        None
    }

    pub fn address_from_pci_offset(&self, alloc: Alloc, offset: u64, size: u64) -> Result<u64> {
        let mut last_res = Err(Error::OutOfSpace);
        for allocator in self.allocators.iter() {
            last_res = allocator.address_from_pci_offset(alloc, offset, size);
            if last_res.is_ok() {
                return last_res;
            }
        }
        last_res
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
    fn allocate_with_special_alignment() {
        let mut pool = AddressAllocator::new(0x1000, 0x1000, Some(0x100)).unwrap();
        assert_eq!(
            pool.allocate(0x10, Alloc::Anon(0), String::from("bar0")),
            Ok(0x1000)
        );
        assert_eq!(
            pool.allocate_at(0x1200, 0x100, Alloc::Anon(1), String::from("bar1")),
            Ok(())
        );
        assert_eq!(
            pool.allocate_with_align(0x800, Alloc::Anon(2), String::from("bar2"), 0x800),
            Ok(0x1800)
        );
    }

    #[test]
    fn allocate_and_split_allocate_at() {
        let mut pool = AddressAllocator::new(0x1000, 0x1000, Some(0x100)).unwrap();
        assert_eq!(
            pool.allocate_at(0x1200, 0x800, Alloc::Anon(0), String::from("bar0")),
            Ok(())
        );
        assert_eq!(
            pool.allocate(0x800, Alloc::Anon(1), String::from("bar1")),
            Err(Error::OutOfSpace)
        );
        assert_eq!(
            pool.allocate(0x600, Alloc::Anon(2), String::from("bar2")),
            Ok(0x1a00)
        );
        assert_eq!(
            pool.allocate(0x200, Alloc::Anon(3), String::from("bar3")),
            Ok(0x1000)
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

    #[test]
    fn allocate_with_release() {
        let mut pool = AddressAllocator::new(0x1000, 0x1000, None).unwrap();
        assert_eq!(
            pool.allocate_with_align(0x100, Alloc::Anon(0), String::from("bar0"), 0x100),
            Ok(0x1000)
        );
        assert!(pool.release(Alloc::Anon(0)).is_ok());
        assert_eq!(
            pool.allocate_with_align(0x1000, Alloc::Anon(0), String::from("bar0"), 0x100),
            Ok(0x1000)
        );
    }

    #[test]
    fn coalescing_and_overlap() {
        let mut pool = AddressAllocator::new(0x1000, 0x1000, None).unwrap();
        assert!(pool.insert_at(0x3000, 0x1000).is_ok());
        assert!(pool.insert_at(0x1fff, 0x20).is_err());
        assert!(pool.insert_at(0x2ff1, 0x10).is_err());
        assert!(pool.insert_at(0x1800, 0x1000).is_err());
        assert!(pool.insert_at(0x2000, 0x1000).is_ok());
        assert_eq!(
            pool.allocate(0x3000, Alloc::Anon(0), String::from("bar0")),
            Ok(0x1000)
        );
    }

    #[test]
    fn coalescing_single_addresses() {
        let mut pool = AddressAllocator::new(0x1000, 0x1000, None).unwrap();
        assert!(pool.insert_at(0x2001, 1).is_ok());
        assert!(pool.insert_at(0x2003, 1).is_ok());
        assert!(pool.insert_at(0x2000, 1).is_ok());
        assert!(pool.insert_at(0x2002, 1).is_ok());
        assert_eq!(
            pool.allocate(0x1004, Alloc::Anon(0), String::from("bar0")),
            Ok(0x1000)
        );
    }

    #[test]
    fn allocate_and_verify_pci_offset() {
        let mut pool = AddressAllocator::new(0x1000, 0x10000, None).unwrap();
        let pci_bar0 = Alloc::PciBar {
            bus: 1,
            dev: 2,
            func: 0,
            bar: 0,
        };
        let pci_bar1 = Alloc::PciBar {
            bus: 1,
            dev: 2,
            func: 0,
            bar: 1,
        };
        let pci_bar2 = Alloc::PciBar {
            bus: 1,
            dev: 2,
            func: 0,
            bar: 2,
        };
        let anon = Alloc::Anon(1);

        assert_eq!(
            pool.allocate(0x800, pci_bar0, String::from("bar0")),
            Ok(0x1000)
        );
        assert_eq!(
            pool.allocate(0x800, pci_bar1, String::from("bar1")),
            Ok(0x1800)
        );
        assert_eq!(pool.allocate(0x800, anon, String::from("anon")), Ok(0x2000));

        assert_eq!(
            pool.address_from_pci_offset(pci_bar0, 0x600, 0x100),
            Ok(0x1600)
        );
        assert_eq!(
            pool.address_from_pci_offset(pci_bar1, 0x600, 0x100),
            Ok(0x1E00)
        );
        assert_eq!(
            pool.address_from_pci_offset(pci_bar0, 0x7FE, 0x001),
            Ok(0x17FE)
        );
        assert_eq!(
            pool.address_from_pci_offset(pci_bar0, 0x7FF, 0x001),
            Err(Error::OutOfBounds)
        );

        assert_eq!(
            pool.address_from_pci_offset(pci_bar2, 0x7FF, 0x001),
            Err(Error::InvalidAlloc(pci_bar2))
        );

        assert_eq!(
            pool.address_from_pci_offset(anon, 0x600, 0x100),
            Err(Error::InvalidAlloc(anon))
        );
    }
}

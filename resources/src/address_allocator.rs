// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp;
use std::collections::{BTreeSet, HashMap};
use std::ops::RangeInclusive;

use crate::{Alloc, Error, Result};

/// Manages allocating address ranges.
/// Use `AddressAllocator` whenever an address range needs to be allocated to different users.
/// Allocations must be uniquely tagged with an Alloc enum, which can be used for lookup.
/// An human-readable tag String must also be provided for debugging / reference.
#[derive(Debug, Eq, PartialEq)]
pub struct AddressAllocator {
    /// The list of pools from which address are allocated. The union
    /// of all regions from |allocs| and |regions| equals the pools.
    pools: Vec<RangeInclusive<u64>>,
    min_align: u64,
    preferred_align: u64,
    /// The region that is allocated.
    allocs: HashMap<Alloc, (u64, u64, String)>,
    /// The region that is not allocated yet.
    regions: BTreeSet<(u64, u64)>,
}

impl AddressAllocator {
    /// Creates a new `AddressAllocator` for managing a range of addresses.
    /// Can return an error if `pool` is empty or if alignment isn't a power of two.
    ///
    /// * `pool` - The address range to allocate from.
    /// * `min_align` - The minimum size of an address region to align to, defaults to four.
    /// * `preferred_align` - The preferred alignment of an address region, used if possible.
    ///
    /// If an allocation cannot be satisfied with the preferred alignment, the minimum alignment
    /// will be used instead.
    pub fn new(
        pool: RangeInclusive<u64>,
        min_align: Option<u64>,
        preferred_align: Option<u64>,
    ) -> Result<Self> {
        Self::new_from_list(vec![pool], min_align, preferred_align)
    }

    /// Creates a new `AddressAllocator` for managing a range of addresses.
    /// Can return `None` if all pools are empty alignment isn't a power of two.
    ///
    /// * `pools` - The list of pools to initialize the allocator with.
    /// * `min_align` - The minimum size of an address region to align to, defaults to four.
    /// * `preferred_align` - The preferred alignment of an address region, used if possible.
    ///
    /// If an allocation cannot be satisfied with the preferred alignment, the minimum alignment
    /// will be used instead.
    pub fn new_from_list<T>(
        pools: T,
        min_align: Option<u64>,
        preferred_align: Option<u64>,
    ) -> Result<Self>
    where
        T: IntoIterator<Item = RangeInclusive<u64>>,
    {
        let pools: Vec<RangeInclusive<u64>> = pools.into_iter().filter(|p| !p.is_empty()).collect();
        if pools.is_empty() {
            return Err(Error::PoolSizeZero);
        }

        let min_align = min_align.unwrap_or(4);
        if !min_align.is_power_of_two() || min_align == 0 {
            return Err(Error::BadAlignment);
        }

        let preferred_align = preferred_align.unwrap_or(min_align);
        if !preferred_align.is_power_of_two() || preferred_align < min_align {
            return Err(Error::BadAlignment);
        }

        let mut regions = BTreeSet::new();
        for r in pools.iter() {
            regions.insert((*r.start(), *r.end()));
        }
        Ok(AddressAllocator {
            pools,
            min_align,
            preferred_align,
            allocs: HashMap::new(),
            regions,
        })
    }

    /// Gets the regions managed by the allocator.
    ///
    /// This returns the original `pools` value provided to `AddressAllocator::new()`.
    pub fn pools(&self) -> &Vec<RangeInclusive<u64>> {
        &self.pools
    }

    fn internal_allocate_with_align(
        &mut self,
        size: u64,
        alloc: Alloc,
        tag: String,
        alignment: u64,
        reverse: bool,
    ) -> Result<u64> {
        let alignment = cmp::max(self.min_align, alignment);

        if self.allocs.contains_key(&alloc) {
            return Err(Error::ExistingAlloc(alloc));
        }
        if size == 0 {
            return Err(Error::AllocSizeZero);
        }
        if !alignment.is_power_of_two() {
            return Err(Error::BadAlignment);
        }

        let region = if !reverse {
            // finds first region matching alignment and size.
            self.regions
                .iter()
                .find(|range| {
                    match range.0 % alignment {
                        0 => range.0.checked_add(size - 1),
                        r => range.0.checked_add(size - 1 + alignment - r),
                    }
                    .map_or(false, |end| end <= range.1)
                })
                .cloned()
        } else {
            // finds last region matching alignment and size.
            self.regions
                .iter()
                .rev()
                .find(|range| {
                    range
                        .1
                        .checked_sub(size - 1)
                        .map_or(false, |start| start & !(alignment - 1) >= range.0)
                })
                .cloned()
        };

        match region {
            Some(slot) => {
                self.regions.remove(&slot);
                let start = if !reverse {
                    match slot.0 % alignment {
                        0 => slot.0,
                        r => slot.0 + alignment - r,
                    }
                } else {
                    (slot.1 - (size - 1)) & !(alignment - 1)
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

    /// Allocates a range of addresses from the reverse managed region with an optional tag
    /// and minimal alignment. Returns allocated_address. (allocated_address, size, tag)
    /// can be retrieved through the `get` method.
    pub fn reverse_allocate_with_align(
        &mut self,
        size: u64,
        alloc: Alloc,
        tag: String,
        alignment: u64,
    ) -> Result<u64> {
        self.internal_allocate_with_align(size, alloc, tag, alignment, true)
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
        self.internal_allocate_with_align(size, alloc, tag, alignment, false)
    }

    pub fn allocate(&mut self, size: u64, alloc: Alloc, tag: String) -> Result<u64> {
        if let Ok(pref_alloc) =
            self.allocate_with_align(size, alloc, tag.clone(), self.preferred_align)
        {
            return Ok(pref_alloc);
        }
        self.allocate_with_align(size, alloc, tag, self.min_align)
    }

    /// Allocates a range of addresses from the managed region with an optional tag
    /// and required location. Allocation alignment is not enforced.
    /// Returns OutOfSpace if requested range is not available or ExistingAlloc if the requested
    /// range overlaps an existing allocation.
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
            None => {
                if let Some(existing_alloc) = self.find_overlapping(start, size) {
                    Err(Error::ExistingAlloc(existing_alloc))
                } else {
                    Err(Error::OutOfSpace)
                }
            }
        }
    }

    /// Releases exising allocation back to free pool.
    pub fn release(&mut self, alloc: Alloc) -> Result<()> {
        self.allocs
            .remove(&alloc)
            .map_or_else(|| Err(Error::BadAlloc(alloc)), |v| self.insert_at(v.0, v.1))
    }

    /// Release a allocation contains the value.
    pub fn release_containing(&mut self, value: u64) -> Result<()> {
        if let Some(alloc) = self.find_overlapping(value, 1) {
            self.release(alloc)
        } else {
            Err(Error::OutOfSpace)
        }
    }

    // Find an existing allocation that overlaps the region defined by `address` and `size`. If more
    // than one allocation overlaps the given region, any of them may be returned, since the HashMap
    // iterator is not ordered in any particular way.
    fn find_overlapping(&self, start: u64, size: u64) -> Option<Alloc> {
        if size == 0 {
            return None;
        }

        let end = start.saturating_add(size - 1);
        self.allocs
            .iter()
            .find(|(_, &(alloc_start, alloc_size, _))| {
                let alloc_end = alloc_start + alloc_size;
                start < alloc_end && end >= alloc_start
            })
            .map(|(&alloc, _)| alloc)
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
    fn example() {
        // Anon is used for brevity. Don't manually instantiate Anon allocs!
        let mut pool =
            AddressAllocator::new(RangeInclusive::new(0x1000, 0xFFFF), Some(0x100), None).unwrap();
        assert_eq!(
            pool.allocate(0x110, Alloc::Anon(0), "caps".to_string()),
            Ok(0x1000)
        );
        assert_eq!(
            pool.allocate(0x100, Alloc::Anon(1), "cache".to_string()),
            Ok(0x1200)
        );
        assert_eq!(
            pool.allocate(0x100, Alloc::Anon(2), "etc".to_string()),
            Ok(0x1300)
        );
        assert_eq!(
            pool.get(&Alloc::Anon(1)),
            Some(&(0x1200, 0x100, "cache".to_string()))
        );
    }

    #[test]
    fn new_fails_size_zero() {
        assert!(AddressAllocator::new(RangeInclusive::new(0x1000, 0), None, None).is_err());
    }

    #[test]
    fn new_fails_alignment_zero() {
        assert!(AddressAllocator::new(RangeInclusive::new(0x1000, 0xFFFF), Some(0), None).is_err());
    }

    #[test]
    fn new_fails_alignment_non_power_of_two() {
        assert!(
            AddressAllocator::new(RangeInclusive::new(0x1000, 0xFFFF), Some(200), None).is_err()
        );
    }

    #[test]
    fn allocate_fails_exising_alloc() {
        let mut pool =
            AddressAllocator::new(RangeInclusive::new(0x1000, 0x1FFF), Some(0x100), None).unwrap();
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
        let mut pool =
            AddressAllocator::new(RangeInclusive::new(0x1000, 0x1FFF), Some(0x100), None).unwrap();
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
        let mut pool =
            AddressAllocator::new(RangeInclusive::new(0x1000, 0x1FFF), Some(0x100), None).unwrap();
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
        let mut pool =
            AddressAllocator::new(RangeInclusive::new(0x1000, 0x1FFF), Some(1), None).unwrap();
        // 0x1200..0x1a00
        assert_eq!(
            pool.allocate_at(0x1200, 0x800, Alloc::Anon(0), String::from("bar0")),
            Ok(())
        );
        assert_eq!(
            pool.allocate(0x800, Alloc::Anon(1), String::from("bar1")),
            Err(Error::OutOfSpace)
        );
        // 0x600..0x2000
        assert_eq!(
            pool.allocate(0x600, Alloc::Anon(2), String::from("bar2")),
            Ok(0x1a00)
        );
        // 0x1000..0x1200
        assert_eq!(
            pool.allocate(0x200, Alloc::Anon(3), String::from("bar3")),
            Ok(0x1000)
        );
        // 0x1b00..0x1c00 (overlaps with 0x600..0x2000)
        assert_eq!(
            pool.allocate_at(0x1b00, 0x100, Alloc::Anon(4), String::from("bar4")),
            Err(Error::ExistingAlloc(Alloc::Anon(2)))
        );
        // 0x1fff..0x2000 (overlaps with 0x600..0x2000)
        assert_eq!(
            pool.allocate_at(0x1fff, 1, Alloc::Anon(5), String::from("bar5")),
            Err(Error::ExistingAlloc(Alloc::Anon(2)))
        );
        // 0x1200..0x1201 (overlaps with 0x1200..0x1a00)
        assert_eq!(
            pool.allocate_at(0x1200, 1, Alloc::Anon(6), String::from("bar6")),
            Err(Error::ExistingAlloc(Alloc::Anon(0)))
        );
        // 0x11ff..0x1200 (overlaps with 0x1000..0x1200)
        assert_eq!(
            pool.allocate_at(0x11ff, 1, Alloc::Anon(7), String::from("bar7")),
            Err(Error::ExistingAlloc(Alloc::Anon(3)))
        );
        // 0x1100..0x1300 (overlaps with 0x1000..0x1200 and 0x1200..0x1a00)
        match pool.allocate_at(0x1100, 0x200, Alloc::Anon(8), String::from("bar8")) {
            Err(Error::ExistingAlloc(Alloc::Anon(0) | Alloc::Anon(3))) => {}
            x => panic!("unexpected result {:?}", x),
        }
    }

    #[test]
    fn allocate_alignment() {
        let mut pool =
            AddressAllocator::new(RangeInclusive::new(0x1000, 0xFFFF), Some(0x100), None).unwrap();
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
        let mut pool =
            AddressAllocator::new(RangeInclusive::new(0x1000, 0xFFFF), Some(0x100), None).unwrap();
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
        let mut pool =
            AddressAllocator::new(RangeInclusive::new(0x1000, 0xFFFF), Some(0x100), None).unwrap();
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
        let mut pool =
            AddressAllocator::new(RangeInclusive::new(0x1000, 0xFFFF), Some(0x4), None).unwrap();
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
        let mut pool =
            AddressAllocator::new(RangeInclusive::new(0x1000, 0xFFFF), None, None).unwrap();
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
        let mut pool =
            AddressAllocator::new(RangeInclusive::new(0x1000, 0xFFFF), None, None).unwrap();
        assert!(pool
            .allocate_with_align(0x110, Alloc::Anon(0), String::from("bar0"), 200)
            .is_err());
    }

    #[test]
    fn allocate_with_release() {
        let mut pool =
            AddressAllocator::new(RangeInclusive::new(0x1000, 0x1FFF), None, None).unwrap();
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
        let mut pool =
            AddressAllocator::new(RangeInclusive::new(0x1000, 0x1FFF), None, None).unwrap();
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
        let mut pool =
            AddressAllocator::new(RangeInclusive::new(0x1000, 0x1FFF), None, None).unwrap();
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
        let mut pool =
            AddressAllocator::new(RangeInclusive::new(0x1000, 0xFFFF), None, None).unwrap();
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

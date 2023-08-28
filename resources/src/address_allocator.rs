// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::ops::Bound;

use crate::AddressRange;
use crate::Alloc;
use crate::Error;
use crate::Result;

/// Manages allocating address ranges.
/// Use `AddressAllocator` whenever an address range needs to be allocated to different users.
/// Allocations must be uniquely tagged with an Alloc enum, which can be used for lookup.
/// An human-readable tag String must also be provided for debugging / reference.
#[derive(Debug, Eq, PartialEq)]
pub struct AddressAllocator {
    /// The list of pools from which address are allocated. The union
    /// of all regions from |allocs| and |regions| equals the pools.
    pools: Vec<AddressRange>,
    min_align: u64,
    preferred_align: u64,
    /// The region that is allocated.
    allocs: HashMap<Alloc, (AddressRange, String)>,
    /// The region that is not allocated yet.
    regions: BTreeSet<AddressRange>,
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
        pool: AddressRange,
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
        T: IntoIterator<Item = AddressRange>,
    {
        let pools: Vec<AddressRange> = pools.into_iter().filter(|p| !p.is_empty()).collect();

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
            regions.insert(*r);
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
    pub fn pools(&self) -> &[AddressRange] {
        &self.pools
    }

    fn internal_allocate_from_slot(
        &mut self,
        slot: AddressRange,
        range: AddressRange,
        alloc: Alloc,
        tag: String,
    ) -> Result<u64> {
        let slot_was_present = self.regions.remove(&slot);
        assert!(slot_was_present);

        let (before, after) = slot.non_overlapping_ranges(range);

        if !before.is_empty() {
            self.regions.insert(before);
        }
        if !after.is_empty() {
            self.regions.insert(after);
        }

        self.allocs.insert(alloc, (range, tag));
        Ok(range.start)
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
                    match range.start % alignment {
                        0 => range.start.checked_add(size - 1),
                        r => range.start.checked_add(size - 1 + alignment - r),
                    }
                    .map_or(false, |end| end <= range.end)
                })
                .cloned()
        } else {
            // finds last region matching alignment and size.
            self.regions
                .iter()
                .rev()
                .find(|range| {
                    range
                        .end
                        .checked_sub(size - 1)
                        .map_or(false, |start| start & !(alignment - 1) >= range.start)
                })
                .cloned()
        };

        match region {
            Some(slot) => {
                let start = if !reverse {
                    match slot.start % alignment {
                        0 => slot.start,
                        r => slot.start + alignment - r,
                    }
                } else {
                    (slot.end - (size - 1)) & !(alignment - 1)
                };
                let end = start + size - 1;
                let range = AddressRange { start, end };

                self.internal_allocate_from_slot(slot, range, alloc, tag)
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

    /// Allocates a range of addresses, preferring to allocate from high rather than low addresses.
    pub fn reverse_allocate(&mut self, size: u64, alloc: Alloc, tag: String) -> Result<u64> {
        if let Ok(pref_alloc) =
            self.reverse_allocate_with_align(size, alloc, tag.clone(), self.preferred_align)
        {
            return Ok(pref_alloc);
        }
        self.reverse_allocate_with_align(size, alloc, tag, self.min_align)
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
    pub fn allocate_at(&mut self, range: AddressRange, alloc: Alloc, tag: String) -> Result<()> {
        if self.allocs.contains_key(&alloc) {
            return Err(Error::ExistingAlloc(alloc));
        }

        if range.is_empty() {
            return Err(Error::AllocSizeZero);
        }

        match self
            .regions
            .iter()
            .find(|avail_range| avail_range.contains_range(range))
        {
            Some(&slot) => {
                let _address = self.internal_allocate_from_slot(slot, range, alloc, tag)?;
                Ok(())
            }
            None => {
                if let Some(existing_alloc) = self.find_overlapping(range) {
                    Err(Error::ExistingAlloc(existing_alloc))
                } else {
                    Err(Error::OutOfSpace)
                }
            }
        }
    }

    /// Releases exising allocation back to free pool and returns the range that was released.
    pub fn release(&mut self, alloc: Alloc) -> Result<AddressRange> {
        if let Some((range, _tag)) = self.allocs.remove(&alloc) {
            self.insert_at(range)?;
            Ok(range)
        } else {
            Err(Error::BadAlloc(alloc))
        }
    }

    /// Release a allocation contains the value.
    pub fn release_containing(&mut self, value: u64) -> Result<AddressRange> {
        if let Some(alloc) = self.find_overlapping(AddressRange {
            start: value,
            end: value,
        }) {
            self.release(alloc)
        } else {
            Err(Error::OutOfSpace)
        }
    }

    // Find an existing allocation that overlaps the region defined by `range`. If more
    // than one allocation overlaps the given region, any of them may be returned, since the HashMap
    // iterator is not ordered in any particular way.
    fn find_overlapping(&self, range: AddressRange) -> Option<Alloc> {
        if range.is_empty() {
            return None;
        }

        self.allocs
            .iter()
            .find(|(_, &(alloc_range, _))| alloc_range.overlaps(range))
            .map(|(&alloc, _)| alloc)
    }

    // Return the max address of the allocated address ranges.
    pub fn get_max_addr(&self) -> u64 {
        self.regions.iter().fold(0, |x, range| x.max(range.end))
    }

    /// Returns allocation associated with `alloc`, or None if no such allocation exists.
    pub fn get(&self, alloc: &Alloc) -> Option<&(AddressRange, String)> {
        self.allocs.get(alloc)
    }

    /// Insert range of addresses into the pool, coalescing neighboring regions.
    fn insert_at(&mut self, mut slot: AddressRange) -> Result<()> {
        if slot.is_empty() {
            return Err(Error::AllocSizeZero);
        }

        // Find the region with the highest starting address that is at most
        // |slot.start|. Check if it overlaps with |slot|, or if it is adjacent to
        // (and thus can be coalesced with) |slot|.
        let mut smaller_merge = None;
        if let Some(smaller) = self
            .regions
            .range((Bound::Unbounded, Bound::Included(slot)))
            .max()
        {
            // If there is overflow, then |smaller| covers up through u64::MAX
            let next_addr = smaller
                .end
                .checked_add(1)
                .ok_or(Error::RegionOverlap(slot))?;
            match next_addr.cmp(&slot.start) {
                cmp::Ordering::Less => (),
                cmp::Ordering::Equal => smaller_merge = Some(*smaller),
                cmp::Ordering::Greater => return Err(Error::RegionOverlap(slot)),
            }
        }

        // Find the region with the smallest starting address that is greater than
        // |slot.start|. Check if it overlaps with |slot|, or if it is adjacent to
        // (and thus can be coalesced with) |slot|.
        let mut larger_merge = None;
        if let Some(larger) = self
            .regions
            .range((Bound::Excluded(slot), Bound::Unbounded))
            .min()
        {
            // If there is underflow, then |larger| covers down through 0
            let prev_addr = larger
                .start
                .checked_sub(1)
                .ok_or(Error::RegionOverlap(slot))?;
            match slot.end.cmp(&prev_addr) {
                cmp::Ordering::Less => (),
                cmp::Ordering::Equal => larger_merge = Some(*larger),
                cmp::Ordering::Greater => return Err(Error::RegionOverlap(slot)),
            }
        }

        if let Some(smaller) = smaller_merge {
            self.regions.remove(&smaller);
            slot.start = smaller.start;
        }
        if let Some(larger) = larger_merge {
            self.regions.remove(&larger);
            slot.end = larger.end;
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
            Some((pci_bar_range, _)) => {
                let address = pci_bar_range
                    .start
                    .checked_add(offset)
                    .ok_or(Error::OutOfBounds)?;
                let offset_range =
                    AddressRange::from_start_and_size(address, size).ok_or(Error::OutOfBounds)?;
                if pci_bar_range.contains_range(offset_range) {
                    Ok(address)
                } else {
                    Err(Error::OutOfBounds)
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

    pub fn allocate_at(&mut self, range: AddressRange, alloc: Alloc, tag: String) -> Result<()> {
        let mut last_res = Err(Error::OutOfSpace);
        for allocator in self.allocators.iter_mut() {
            last_res = allocator.allocate_at(range, alloc, tag.clone());
            if last_res.is_ok() {
                return last_res;
            }
        }
        last_res
    }

    pub fn release(&mut self, alloc: Alloc) -> Result<AddressRange> {
        let mut last_res = Err(Error::OutOfSpace);
        for allocator in self.allocators.iter_mut() {
            last_res = allocator.release(alloc);
            if last_res.is_ok() {
                return last_res;
            }
        }
        last_res
    }

    pub fn get(&self, alloc: &Alloc) -> Option<&(AddressRange, String)> {
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
        let mut pool = AddressAllocator::new(
            AddressRange {
                start: 0x1000,
                end: 0xFFFF,
            },
            Some(0x100),
            None,
        )
        .unwrap();
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
            Some(&(
                AddressRange {
                    start: 0x1200,
                    end: 0x12FF
                },
                "cache".to_string()
            ))
        );
    }

    #[test]
    fn empty_allocator() {
        let mut pool = AddressAllocator::new_from_list(Vec::new(), None, None).unwrap();
        assert_eq!(pool.pools(), &[]);
        assert_eq!(
            pool.allocate(1, Alloc::Anon(0), "test".to_string()),
            Err(Error::OutOfSpace)
        );
    }

    #[test]
    fn new_fails_alignment_zero() {
        assert!(AddressAllocator::new(
            AddressRange {
                start: 0x1000,
                end: 0xFFFF
            },
            Some(0),
            None
        )
        .is_err());
    }

    #[test]
    fn new_fails_alignment_non_power_of_two() {
        assert!(AddressAllocator::new(
            AddressRange {
                start: 0x1000,
                end: 0xFFFF
            },
            Some(200),
            None
        )
        .is_err());
    }

    #[test]
    fn allocate_fails_exising_alloc() {
        let mut pool = AddressAllocator::new(
            AddressRange {
                start: 0x1000,
                end: 0x1FFF,
            },
            Some(0x100),
            None,
        )
        .unwrap();
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
        let mut pool = AddressAllocator::new(
            AddressRange {
                start: 0x1000,
                end: 0x1FFF,
            },
            Some(0x100),
            None,
        )
        .unwrap();
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
        let mut pool = AddressAllocator::new(
            AddressRange {
                start: 0x1000,
                end: 0x1FFF,
            },
            Some(0x100),
            None,
        )
        .unwrap();
        assert_eq!(
            pool.allocate(0x10, Alloc::Anon(0), String::from("bar0")),
            Ok(0x1000)
        );
        assert_eq!(
            pool.allocate_at(
                AddressRange {
                    start: 0x1200,
                    end: 0x13ff,
                },
                Alloc::Anon(1),
                String::from("bar1")
            ),
            Ok(())
        );
        assert_eq!(
            pool.allocate_with_align(0x800, Alloc::Anon(2), String::from("bar2"), 0x800),
            Ok(0x1800)
        );
    }

    #[test]
    fn allocate_and_split_allocate_at() {
        let mut pool = AddressAllocator::new(
            AddressRange {
                start: 0x1000,
                end: 0x1fff,
            },
            Some(1),
            None,
        )
        .unwrap();
        // 0x1200..0x1a00
        assert_eq!(
            pool.allocate_at(
                AddressRange {
                    start: 0x1200,
                    end: 0x19ff,
                },
                Alloc::Anon(0),
                String::from("bar0")
            ),
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
            pool.allocate_at(
                AddressRange {
                    start: 0x1b00,
                    end: 0x1bff,
                },
                Alloc::Anon(4),
                String::from("bar4")
            ),
            Err(Error::ExistingAlloc(Alloc::Anon(2)))
        );
        // 0x1fff..0x2000 (overlaps with 0x600..0x2000)
        assert_eq!(
            pool.allocate_at(
                AddressRange {
                    start: 0x1fff,
                    end: 0x1fff,
                },
                Alloc::Anon(5),
                String::from("bar5")
            ),
            Err(Error::ExistingAlloc(Alloc::Anon(2)))
        );
        // 0x1200..0x1201 (overlaps with 0x1200..0x1a00)
        assert_eq!(
            pool.allocate_at(
                AddressRange {
                    start: 0x1200,
                    end: 0x1200,
                },
                Alloc::Anon(6),
                String::from("bar6")
            ),
            Err(Error::ExistingAlloc(Alloc::Anon(0)))
        );
        // 0x11ff..0x1200 (overlaps with 0x1000..0x1200)
        assert_eq!(
            pool.allocate_at(
                AddressRange {
                    start: 0x11ff,
                    end: 0x11ff,
                },
                Alloc::Anon(7),
                String::from("bar7")
            ),
            Err(Error::ExistingAlloc(Alloc::Anon(3)))
        );
        // 0x1100..0x1300 (overlaps with 0x1000..0x1200 and 0x1200..0x1a00)
        match pool.allocate_at(
            AddressRange {
                start: 0x1100,
                end: 0x12ff,
            },
            Alloc::Anon(8),
            String::from("bar8"),
        ) {
            Err(Error::ExistingAlloc(Alloc::Anon(0) | Alloc::Anon(3))) => {}
            x => panic!("unexpected result {:?}", x),
        }
    }

    #[test]
    fn allocate_alignment() {
        let mut pool = AddressAllocator::new(
            AddressRange {
                start: 0x1000,
                end: 0xFFFF,
            },
            Some(0x100),
            None,
        )
        .unwrap();
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
        let mut pool = AddressAllocator::new(
            AddressRange {
                start: 0x1000,
                end: 0xFFFF,
            },
            Some(0x100),
            None,
        )
        .unwrap();
        assert_eq!(
            pool.allocate(0x110, Alloc::Anon(0), String::from("bar0")),
            Ok(0x1000)
        );
        assert_eq!(
            pool.get(&Alloc::Anon(0)),
            Some(&(
                AddressRange {
                    start: 0x1000,
                    end: 0x110f,
                },
                String::from("bar0")
            ))
        );
    }

    #[test]
    fn allocate_with_alignment_allocator_alignment() {
        let mut pool = AddressAllocator::new(
            AddressRange {
                start: 0x1000,
                end: 0xFFFF,
            },
            Some(0x100),
            None,
        )
        .unwrap();
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
        let mut pool = AddressAllocator::new(
            AddressRange {
                start: 0x1000,
                end: 0xFFFF,
            },
            Some(0x4),
            None,
        )
        .unwrap();
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
        let mut pool = AddressAllocator::new(
            AddressRange {
                start: 0x1000,
                end: 0xFFFF,
            },
            None,
            None,
        )
        .unwrap();
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
        let mut pool = AddressAllocator::new(
            AddressRange {
                start: 0x1000,
                end: 0xFFFF,
            },
            None,
            None,
        )
        .unwrap();
        assert!(pool
            .allocate_with_align(0x110, Alloc::Anon(0), String::from("bar0"), 200)
            .is_err());
    }

    #[test]
    fn allocate_with_release() {
        let mut pool = AddressAllocator::new(
            AddressRange {
                start: 0x1000,
                end: 0x1FFF,
            },
            None,
            None,
        )
        .unwrap();
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
        let mut pool = AddressAllocator::new(
            AddressRange {
                start: 0x1000,
                end: 0x1FFF,
            },
            None,
            None,
        )
        .unwrap();
        assert!(pool
            .insert_at(AddressRange {
                start: 0x3000,
                end: 0x3fff,
            })
            .is_ok());
        assert!(pool
            .insert_at(AddressRange {
                start: 0x1fff,
                end: 0x201e,
            })
            .is_err());
        assert!(pool
            .insert_at(AddressRange {
                start: 0x2ff1,
                end: 0x3000,
            })
            .is_err());
        assert!(pool
            .insert_at(AddressRange {
                start: 0x1800,
                end: 0x27ff,
            })
            .is_err());
        assert!(pool
            .insert_at(AddressRange {
                start: 0x2000,
                end: 0x2fff,
            })
            .is_ok());
        assert_eq!(
            pool.allocate(0x3000, Alloc::Anon(0), String::from("bar0")),
            Ok(0x1000)
        );
    }

    #[test]
    fn coalescing_single_addresses() {
        let mut pool = AddressAllocator::new(
            AddressRange {
                start: 0x1000,
                end: 0x1FFF,
            },
            None,
            None,
        )
        .unwrap();
        assert!(pool
            .insert_at(AddressRange {
                start: 0x2001,
                end: 0x2001,
            })
            .is_ok());
        assert!(pool
            .insert_at(AddressRange {
                start: 0x2003,
                end: 0x2003,
            })
            .is_ok());
        assert!(pool
            .insert_at(AddressRange {
                start: 0x2000,
                end: 0x2000,
            })
            .is_ok());
        assert!(pool
            .insert_at(AddressRange {
                start: 0x2002,
                end: 0x2002,
            })
            .is_ok());
        assert_eq!(
            pool.allocate(0x1004, Alloc::Anon(0), String::from("bar0")),
            Ok(0x1000)
        );
    }

    #[test]
    fn coalescing_u64_limits() {
        let mut pool = AddressAllocator::new(
            AddressRange {
                start: 0,
                end: u64::MAX - 1,
            },
            None,
            None,
        )
        .unwrap();
        assert!(pool
            .insert_at(AddressRange {
                start: u64::MAX,
                end: u64::MAX,
            })
            .is_ok());
        assert!(pool
            .insert_at(AddressRange {
                start: u64::MAX,
                end: u64::MAX,
            })
            .is_err());
        assert_eq!(
            pool.allocate(u64::MAX, Alloc::Anon(0), String::from("bar0")),
            Ok(0)
        );

        let mut pool = AddressAllocator::new(
            AddressRange {
                start: 1,
                end: u64::MAX,
            },
            None,
            None,
        )
        .unwrap();
        assert!(pool.insert_at(AddressRange { start: 0, end: 0 }).is_ok());
        assert!(pool.insert_at(AddressRange { start: 0, end: 0 }).is_err());
        assert_eq!(
            pool.allocate(u64::MAX, Alloc::Anon(0), String::from("bar0")),
            Ok(0)
        );
    }

    #[test]
    fn allocate_and_verify_pci_offset() {
        let mut pool = AddressAllocator::new(
            AddressRange {
                start: 0x1000,
                end: 0xFFFF,
            },
            None,
            None,
        )
        .unwrap();
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
            Ok(0x17FF)
        );
        assert_eq!(
            pool.address_from_pci_offset(pci_bar0, 0x800, 0x001),
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

    #[test]
    fn get_max_address_of_ranges() {
        let ranges = vec![
            AddressRange {
                start: 0x1000,
                end: 0xFFFF,
            },
            AddressRange {
                start: 0x20000,
                end: 0xFFFFF,
            },
        ];
        let pool = AddressAllocator::new_from_list(ranges, None, None).unwrap();

        assert_eq!(pool.get_max_addr(), 0xFFFFF);
    }
}

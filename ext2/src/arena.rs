// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Defines an arena allocator backed by `base::MemoryMapping`.

use std::cell::RefCell;
use std::collections::BTreeSet;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use base::MappedRegion;
use base::MemoryMapping;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Region {
    start: usize,
    len: usize,
}

/// Manages a set of regions that are not overlapping each other.
#[derive(Default)]
struct RegionManager(BTreeSet<Region>);

impl RegionManager {
    fn allocate(&mut self, start: usize, len: usize) -> Result<()> {
        // Allocation needs to fail if there exists a region that overlaps with [start, start+len).
        // A region r is overlapping with [start, start+len) if and only if:
        // r.start <= (start+len) && start <= (r.start+r.len)
        //
        // So, we first find the last region where r.start <= (start+len) holds.
        let left = self
            .0
            .range(
                ..Region {
                    start: start + len,
                    len: 0,
                },
            )
            .next_back()
            .copied();

        // New region to be added.
        let new = match left {
            None => Region { start, len },
            Some(r) => {
                if start < r.start + r.len {
                    bail!(
                        "range overlaps: existing: {:?}, new: {:?}",
                        left,
                        Region { start, len }
                    );
                }

                // if `r` and the new region is adjacent, merge them.
                // otherwise, just return the new region.
                if start == r.start + r.len {
                    let new = Region {
                        start: r.start,
                        len: r.len + len,
                    };
                    self.0.remove(&r);
                    new
                } else {
                    Region { start, len }
                }
            }
        };

        // If there exists a region that starts from `new.start + new.len`,
        // it should be merged with `new`.
        let right = self
            .0
            .range(
                Region {
                    start: new.start + new.len,
                    len: 0,
                }..,
            )
            .next()
            .copied();
        match right {
            Some(r) if r.start == new.start + new.len => {
                // merge and insert
                let merged = Region {
                    start: new.start,
                    len: new.len + r.len,
                };
                self.0.remove(&r);
                self.0.insert(merged);
            }
            Some(_) | None => {
                // just insert
                self.0.insert(new);
            }
        }

        Ok(())
    }

    #[cfg(test)]
    fn to_vec(&self) -> Vec<&Region> {
        self.0.iter().collect()
    }
}

#[test]
fn test_region_manager() {
    let mut rm: RegionManager = Default::default();

    rm.allocate(0, 5).unwrap();
    assert_eq!(rm.to_vec(), vec![&Region { start: 0, len: 5 }]);
    rm.allocate(10, 5).unwrap();
    rm.allocate(15, 5).unwrap(); // will be merged into the previous one
    assert_eq!(
        rm.to_vec(),
        vec![&Region { start: 0, len: 5 }, &Region { start: 10, len: 10 }]
    );
    rm.allocate(3, 5).unwrap_err(); // fail
    rm.allocate(8, 5).unwrap_err(); // fail

    rm.allocate(25, 5).unwrap();
    assert_eq!(
        rm.to_vec(),
        vec![
            &Region { start: 0, len: 5 },
            &Region { start: 10, len: 10 },
            &Region { start: 25, len: 5 }
        ]
    );

    rm.allocate(5, 5).unwrap(); // will be merged to the existing two regions
    assert_eq!(
        rm.to_vec(),
        vec![&Region { start: 0, len: 20 }, &Region { start: 25, len: 5 }]
    );
    rm.allocate(20, 5).unwrap();
    assert_eq!(rm.to_vec(), vec![&Region { start: 0, len: 30 },]);
}

/// Memory arena backed by `base::MemoryMapping`.
///
/// This struct takes a mutable referencet to the memory mapping so this arena won't arena the
/// region.
pub struct Arena<'a> {
    mem: &'a mut MemoryMapping,
    block_size: usize,
    /// A set of regions that are not overlapping each other.
    /// Use `RefCell` for interior mutability because the mutablity of `RegionManager` should be
    /// independent from the mutability of the memory mapping.
    regions: RefCell<RegionManager>,
}

impl<'a> Arena<'a> {
    /// Create a new arena backed by `len` bytes of `base::MemoryMapping`.
    pub fn new(block_size: usize, mem: &'a mut MemoryMapping) -> Result<Self> {
        Ok(Self {
            mem,
            block_size,
            regions: Default::default(),
        })
    }

    /// Allocate a new slice.
    pub fn allocate_slice(
        &self,
        block_id: usize,
        block_offset: usize,
        len: usize,
    ) -> Result<&'a mut [u8]> {
        let offset = block_id * self.block_size + block_offset;
        let mem_end = offset.checked_add(len).context("mem_end overflow")?;

        if mem_end > self.mem.size() {
            bail!(
                "out of memory region: {offset} + {len} > {}",
                self.mem.size()
            );
        }

        self.regions.borrow_mut().allocate(offset, len)?;

        let new_addr = (self.mem.as_ptr() as usize)
            .checked_add(offset)
            .context("address overflow")?;

        // SAFETY: the memory region [new_addr, new_addr+len) is guaranteed to be valid.
        let slice = unsafe { std::slice::from_raw_parts_mut(new_addr as *mut u8, len) };
        Ok(slice)
    }

    /// Allocate a new region for a value with type `T`.
    pub fn allocate<T: AsBytes + FromBytes + Sized>(
        &self,
        block_id: usize,
        block_offset: usize,
    ) -> Result<&'a mut T> {
        let slice = self.allocate_slice(block_id, block_offset, std::mem::size_of::<T>())?;
        T::mut_from(slice).ok_or_else(|| anyhow!("failed to interpret"))
    }
}

// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::VolatileSlice;
use remain::sorted;
use thiserror::Error as ThisError;

#[sorted]
#[derive(ThisError, Debug)]
pub enum Error {
    /// Invalid offset or length given for an iovec in backing memory.
    #[error("Invalid offset/len for getting a slice from {0} with len {1}.")]
    InvalidOffset(u64, usize),
}
pub type Result<T> = std::result::Result<T, Error>;

/// Used to index subslices of backing memory. Like an iovec, but relative to the start of the
/// backing memory instead of an absolute pointer.
/// The backing memory referenced by the region can be an array, an mmapped file, or guest memory.
/// The offset is a u64 to allow having file or guest offsets >4GB when run on a 32bit host.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MemRegion {
    pub offset: u64,
    pub len: usize,
}

/// Iterator over an ordered list of [`MemRegion`].
///
/// In addition to the usual iterator operations, `MemRegionIter` provides extra functionality that
/// allows subslicing individual memory regions without mutating the underlying list:
/// - [`skip_bytes()`](Self::skip_bytes): Advance the iterator some number of bytes, potentially
///   starting iteration in the middle of a `MemRegion`.
/// - [`take_bytes()`](Self::take_bytes): Truncate the iterator at some number of bytes, potentially
///   ending iteration in the middle of a `MemRegion`.
///
/// The order of subslicing operations matters - limiting length followed by skipping bytes is not
/// the same as skipping bytes followed by limiting length.
#[derive(Clone)]
pub struct MemRegionIter<'a> {
    regions: &'a [MemRegion],
    skip_bytes: usize,
    remaining_bytes: usize,
}

impl<'a> MemRegionIter<'a> {
    /// Create a new `MemRegion` iterator over a slice of `MemRegion`.
    ///
    /// By default, the `MemRegionIter` will iterate over each `MemRegion` in the list in its
    /// entirety. Call [`skip_bytes()`](Self::skip_bytes) and/or
    /// [`take_bytes()`](Self::take_bytes) to limit iteration to a sub-slice of the specified
    /// `regions` list.
    pub fn new(regions: &'a [MemRegion]) -> Self {
        MemRegionIter {
            regions,
            skip_bytes: 0,
            remaining_bytes: usize::MAX,
        }
    }

    /// Advance the iterator by `offset` bytes.
    ///
    /// This may place the iterator in the middle of a [`MemRegion`]; in this case, the offset and
    /// length of the next [`MemRegion`] returned by [`next()`](Self::next) will be adjusted to
    /// account for the offset.
    ///
    /// Skipping more than the remaining length of an iterator is not an error; if `offset` is
    /// greater than or equal to the total number of remaining bytes, future calls to
    /// [`next()`](Self::next) will simply return `None`.
    pub fn skip_bytes(self, offset: usize) -> Self {
        MemRegionIter {
            regions: self.regions,
            skip_bytes: self.skip_bytes.saturating_add(offset),
            remaining_bytes: self.remaining_bytes.saturating_sub(offset),
        }
    }

    /// Truncate the length of the iterator to `max` bytes at most.
    ///
    /// This may cause the final [`MemRegion`] returned by [`next()`](Self::next) to be adjusted so
    /// that its length does not cause the total number of bytes to exceed the requested `max`.
    ///
    /// If less than `max` bytes remain in the iterator already, this function will have no effect.
    ///
    /// Only truncation is supported; an iterator cannot be extended, even if it was truncated by a
    /// previous call to `take_bytes()`.
    pub fn take_bytes(self, max: usize) -> Self {
        MemRegionIter {
            regions: self.regions,
            skip_bytes: self.skip_bytes,
            remaining_bytes: self.remaining_bytes.min(max),
        }
    }
}

impl Iterator for MemRegionIter<'_> {
    type Item = MemRegion;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining_bytes == 0 {
            return None;
        }

        while let Some((first, remaining)) = self.regions.split_first() {
            // This call to `next()` will consume `first`; future calls will start with `remaining`.
            self.regions = remaining;

            // If skip_bytes encompasses this entire region, skip to the next region.
            // This also skips zero-length regions, which should not be returned by the iterator.
            if self.skip_bytes >= first.len {
                self.skip_bytes -= first.len;
                continue;
            }

            // Adjust the current region and reset `self.skip_bytes` to 0 to fully consume it.
            let mut region = MemRegion {
                offset: first.offset + self.skip_bytes as u64,
                len: first.len - self.skip_bytes,
            };
            self.skip_bytes = 0;

            // If this region is at least as large as `remaining_bytes`, truncate the region and set
            // `regions` to an empty slice to terminate iteration in future calls to `next()`.
            if region.len >= self.remaining_bytes {
                region.len = self.remaining_bytes;
                self.remaining_bytes = 0;
                self.regions = &[];
            } else {
                // Consume and return the full region.
                self.remaining_bytes -= region.len;
            }

            // This should never return a zero-length region (should be handled by the
            // `remaining_bytes == 0` early return and zero-length region skipping above).
            debug_assert_ne!(region.len, 0);
            return Some(region);
        }

        None
    }
}

/// Trait for memory that can yield both iovecs in to the backing memory.
/// # Safety
/// Must be OK to modify the backing memory without owning a mut able reference. For example,
/// this is safe for GuestMemory and VolatileSlices in crosvm as those types guarantee they are
/// dealt with as volatile.
pub unsafe trait BackingMemory {
    /// Returns VolatileSlice pointing to the backing memory. This is most commonly unsafe.
    /// To implement this safely the implementor must guarantee that the backing memory can be
    /// modified out of band without affecting safety guarantees.
    fn get_volatile_slice(&self, mem_range: MemRegion) -> Result<VolatileSlice>;
}

/// Wrapper to be used for passing a Vec in as backing memory for asynchronous operations.  The
/// wrapper owns a Vec according to the borrow checker. It is loaning this vec out to the kernel(or
/// other modifiers) through the `BackingMemory` trait. This allows multiple modifiers of the array
/// in the `Vec` while this struct is alive. The data in the Vec is loaned to the kernel not the
/// data structure itself, the length, capacity, and pointer to memory cannot be modified.
/// To ensure that those operations can be done safely, no access is allowed to the `Vec`'s memory
/// starting at the time that `VecIoWrapper` is constructed until the time it is turned back in to a
/// `Vec` using `to_inner`. The returned `Vec` is guaranteed to be valid as any combination of bits
/// in a `Vec` of `u8` is valid.
pub struct VecIoWrapper {
    inner: Box<[u8]>,
}

impl From<Vec<u8>> for VecIoWrapper {
    fn from(vec: Vec<u8>) -> Self {
        VecIoWrapper { inner: vec.into() }
    }
}

impl From<VecIoWrapper> for Vec<u8> {
    fn from(v: VecIoWrapper) -> Vec<u8> {
        v.inner.into()
    }
}

impl VecIoWrapper {
    /// Get the length of the Vec that is wrapped.
    #[cfg_attr(windows, allow(dead_code))]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    // Check that the offsets are all valid in the backing vec.
    fn check_addrs(&self, mem_range: &MemRegion) -> Result<()> {
        let end = mem_range
            .offset
            .checked_add(mem_range.len as u64)
            .ok_or(Error::InvalidOffset(mem_range.offset, mem_range.len))?;
        if end > self.inner.len() as u64 {
            return Err(Error::InvalidOffset(mem_range.offset, mem_range.len));
        }
        Ok(())
    }
}

// Safe to implement BackingMemory as the vec is only accessible inside the wrapper and these iovecs
// are the only thing allowed to modify it.  Nothing else can get a reference to the vec until all
// iovecs are dropped because they borrow Self.  Nothing can borrow the owned inner vec until self
// is consumed by `into`, which can't happen if there are outstanding mut borrows.
unsafe impl BackingMemory for VecIoWrapper {
    fn get_volatile_slice(&self, mem_range: MemRegion) -> Result<VolatileSlice<'_>> {
        self.check_addrs(&mem_range)?;
        // Safe because the mem_range range is valid in the backing memory as checked above.
        unsafe {
            Ok(VolatileSlice::from_raw_parts(
                self.inner.as_ptr().add(mem_range.offset as usize) as *mut _,
                mem_range.len,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_region_iter_empty() {
        let mut iter = MemRegionIter::new(&[]);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn mem_region_iter_one() {
        let mut iter = MemRegionIter::new(&[MemRegion { offset: 0, len: 4 }]);
        assert_eq!(iter.next(), Some(MemRegion { offset: 0, len: 4 }));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn mem_region_iter_one_len_usize_max() {
        let mut iter = MemRegionIter::new(&[MemRegion {
            offset: 0,
            len: usize::MAX,
        }]);
        assert_eq!(
            iter.next(),
            Some(MemRegion {
                offset: 0,
                len: usize::MAX
            })
        );
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn mem_region_iter_one_len_zero() {
        let mut iter = MemRegionIter::new(&[MemRegion { offset: 0, len: 0 }]);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn mem_region_iter_one_skip_partial() {
        let mut iter = MemRegionIter::new(&[MemRegion { offset: 0, len: 4 }]).skip_bytes(1);
        assert_eq!(iter.next(), Some(MemRegion { offset: 1, len: 3 }));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn mem_region_iter_one_skip_full() {
        let mut iter = MemRegionIter::new(&[MemRegion { offset: 0, len: 4 }]).skip_bytes(4);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn mem_region_iter_one_skip_excess() {
        let mut iter = MemRegionIter::new(&[MemRegion { offset: 0, len: 4 }]).skip_bytes(5);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn mem_region_iter_one_take_zero() {
        let mut iter = MemRegionIter::new(&[MemRegion { offset: 0, len: 4 }]).take_bytes(0);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn mem_region_iter_one_take_partial() {
        let mut iter = MemRegionIter::new(&[MemRegion { offset: 0, len: 4 }]).take_bytes(1);
        assert_eq!(iter.next(), Some(MemRegion { offset: 0, len: 1 }));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn mem_region_iter_one_take_full() {
        let mut iter = MemRegionIter::new(&[MemRegion { offset: 0, len: 4 }]).take_bytes(4);
        assert_eq!(iter.next(), Some(MemRegion { offset: 0, len: 4 }));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn mem_region_iter_one_take_excess() {
        let mut iter = MemRegionIter::new(&[MemRegion { offset: 0, len: 4 }]).take_bytes(5);
        assert_eq!(iter.next(), Some(MemRegion { offset: 0, len: 4 }));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn mem_region_iter_one_take_skip() {
        let mut iter = MemRegionIter::new(&[MemRegion { offset: 0, len: 4 }])
            .take_bytes(2)
            .skip_bytes(1);
        assert_eq!(iter.next(), Some(MemRegion { offset: 1, len: 1 }));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn mem_region_iter_one_skip_take() {
        let mut iter = MemRegionIter::new(&[MemRegion { offset: 0, len: 4 }])
            .skip_bytes(1)
            .take_bytes(2);
        assert_eq!(iter.next(), Some(MemRegion { offset: 1, len: 2 }));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn mem_region_iter_two() {
        let mut iter = MemRegionIter::new(&[
            MemRegion { offset: 0, len: 4 },
            MemRegion { offset: 8, len: 2 },
        ]);
        assert_eq!(iter.next(), Some(MemRegion { offset: 0, len: 4 }));
        assert_eq!(iter.next(), Some(MemRegion { offset: 8, len: 2 }));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn mem_region_iter_two_skip_partial() {
        let mut iter = MemRegionIter::new(&[
            MemRegion { offset: 0, len: 4 },
            MemRegion { offset: 8, len: 2 },
        ])
        .skip_bytes(1);
        assert_eq!(iter.next(), Some(MemRegion { offset: 1, len: 3 }));
        assert_eq!(iter.next(), Some(MemRegion { offset: 8, len: 2 }));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn mem_region_iter_two_skip_full() {
        let mut iter = MemRegionIter::new(&[
            MemRegion { offset: 0, len: 4 },
            MemRegion { offset: 8, len: 2 },
        ])
        .skip_bytes(4);
        assert_eq!(iter.next(), Some(MemRegion { offset: 8, len: 2 }));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn mem_region_iter_two_skip_excess() {
        let mut iter = MemRegionIter::new(&[
            MemRegion { offset: 0, len: 4 },
            MemRegion { offset: 8, len: 2 },
        ])
        .skip_bytes(5);
        assert_eq!(iter.next(), Some(MemRegion { offset: 9, len: 1 }));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn mem_region_iter_two_skip_multi() {
        let mut iter = MemRegionIter::new(&[
            MemRegion { offset: 0, len: 4 },
            MemRegion { offset: 8, len: 2 },
        ])
        .skip_bytes(6);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn mem_region_iter_two_take_partial() {
        let mut iter = MemRegionIter::new(&[
            MemRegion { offset: 0, len: 4 },
            MemRegion { offset: 8, len: 2 },
        ])
        .take_bytes(1);
        assert_eq!(iter.next(), Some(MemRegion { offset: 0, len: 1 }));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn mem_region_iter_two_take_partial2() {
        let mut iter = MemRegionIter::new(&[
            MemRegion { offset: 0, len: 4 },
            MemRegion { offset: 8, len: 2 },
        ])
        .take_bytes(5);
        assert_eq!(iter.next(), Some(MemRegion { offset: 0, len: 4 }));
        assert_eq!(iter.next(), Some(MemRegion { offset: 8, len: 1 }));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn mem_region_iter_two_take_full() {
        let mut iter = MemRegionIter::new(&[
            MemRegion { offset: 0, len: 4 },
            MemRegion { offset: 8, len: 2 },
        ])
        .take_bytes(6);
        assert_eq!(iter.next(), Some(MemRegion { offset: 0, len: 4 }));
        assert_eq!(iter.next(), Some(MemRegion { offset: 8, len: 2 }));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn mem_region_iter_two_take_excess() {
        let mut iter = MemRegionIter::new(&[
            MemRegion { offset: 0, len: 4 },
            MemRegion { offset: 8, len: 2 },
        ])
        .take_bytes(7);
        assert_eq!(iter.next(), Some(MemRegion { offset: 0, len: 4 }));
        assert_eq!(iter.next(), Some(MemRegion { offset: 8, len: 2 }));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn mem_region_iter_embedded_zero_len() {
        let mut iter = MemRegionIter::new(&[
            MemRegion { offset: 0, len: 4 },
            MemRegion { offset: 8, len: 2 },
            MemRegion { offset: 9, len: 0 },
            MemRegion { offset: 16, len: 5 },
            MemRegion { offset: 6, len: 0 },
            MemRegion { offset: 24, len: 9 },
        ])
        .skip_bytes(2)
        .take_bytes(12);
        assert_eq!(iter.next(), Some(MemRegion { offset: 2, len: 2 }));
        assert_eq!(iter.next(), Some(MemRegion { offset: 8, len: 2 }));
        assert_eq!(iter.next(), Some(MemRegion { offset: 16, len: 5 }));
        assert_eq!(iter.next(), Some(MemRegion { offset: 24, len: 3 }));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn mem_region_iter_skip_multi() {
        let mut iter = MemRegionIter::new(&[
            MemRegion { offset: 0, len: 4 },
            MemRegion { offset: 8, len: 2 },
            MemRegion { offset: 16, len: 5 },
            MemRegion { offset: 24, len: 9 },
        ])
        .skip_bytes(7);
        assert_eq!(iter.next(), Some(MemRegion { offset: 17, len: 4 }));
        assert_eq!(iter.next(), Some(MemRegion { offset: 24, len: 9 }));
        assert_eq!(iter.next(), None);
    }
}

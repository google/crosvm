// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp;
use std::ops::RangeInclusive;

use serde::Deserialize;
use serde::Serialize;

/// Represents a range of addresses from `start` to `end`, inclusive.
///
/// Why not use the standard `RangeInclusive`? `RangeInclusive` is not `Copy`, because it tries to
/// be an iterator as well as a range (which also means it is larger than necessary). Additionally,
/// we would also like to implement some convenience functions for our own type.
#[derive(Copy, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AddressRange {
    pub start: u64,
    pub end: u64,
}

impl AddressRange {
    /// Creates a new `AddressRange` from `start` and `end` (inclusive) addresses.
    pub const fn from_start_and_end(start: u64, end: u64) -> Self {
        AddressRange { start, end }
    }

    /// Creates a new `AddressRange` from `start` extending `size` bytes.
    ///
    /// Returns `None` if the generated range is not representable as an `AddressRange`.
    pub const fn from_start_and_size(start: u64, size: u64) -> Option<Self> {
        if size == 0 {
            Some(AddressRange::empty())
        } else if let Some(end) = start.checked_add(size - 1) {
            Some(AddressRange { start, end })
        } else {
            None
        }
    }

    /// Returns an empty range.
    pub const fn empty() -> Self {
        AddressRange { start: 1, end: 0 }
    }

    /// Returns `true` if this range is empty (contains no addresses).
    pub fn is_empty(&self) -> bool {
        self.end < self.start
    }

    /// Returns `true` if this range contains `address`.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.start && address <= self.end
    }

    /// Returns `true` if `other` is fully contained within this range.
    ///
    /// Empty ranges are considered to be not contained by any range.
    pub fn contains_range(&self, other: AddressRange) -> bool {
        !other.is_empty() && other.start >= self.start && other.end <= self.end
    }

    /// Returns `true` if the two ranges have any addresses in common.
    pub fn overlaps(&self, other: AddressRange) -> bool {
        !self.intersect(other).is_empty()
    }

    /// Find the intersection (overlapping region) of two ranges.
    ///
    /// If there is no intersection, the resulting `AddressRange` will be empty.
    pub fn intersect(&self, other: AddressRange) -> AddressRange {
        let start = cmp::max(self.start, other.start);
        let end = cmp::min(self.end, other.end);
        AddressRange { start, end }
    }

    /// Returns the ranges of addresses contained in `self` but not in `other`.
    ///
    /// The first returned range will contain the addresses in `self` that are less than the start
    /// of `other`, which will be empty if the starts of the ranges coincide.
    ///
    /// The second returned range will contain the addresses in `self` that are greater than the end
    /// of `other`, which will be empty if the ends of the ranges coincide.
    pub fn non_overlapping_ranges(&self, other: AddressRange) -> (AddressRange, AddressRange) {
        let before = if self.start >= other.start {
            Self::empty()
        } else {
            let start = cmp::min(self.start, other.start);

            // We know that self.start != other.start, so the maximum of the two cannot be 0, so it
            // is safe to subtract 1.
            let end = cmp::max(self.start, other.start) - 1;

            // For non-overlapping ranges, don't allow end to extend past self.end.
            let end = cmp::min(end, self.end);

            AddressRange { start, end }
        };

        let after = if self.end <= other.end {
            Self::empty()
        } else {
            // We know that self.end != other.end, so the minimum of the two cannot be `u64::MAX`,
            // so it is safe to add 1.
            let start = cmp::min(self.end, other.end) + 1;

            // For non-overlapping ranges, don't allow start to extend before self.start.
            let start = cmp::max(start, self.start);

            let end = cmp::max(self.end, other.end);

            AddressRange { start, end }
        };

        (before, after)
    }

    /// Returns the two subsets of this range split at the `split_start` address.
    ///
    /// If `split_start` is not contained in this range, returns the original range and an empty
    /// range.
    pub fn split_at(&self, split_start: u64) -> (AddressRange, AddressRange) {
        // split_start == self.start is handled as a special case so we know that split_start - 1 is
        // safe below (and so the empty range is always returned second if present).
        if split_start <= self.start || split_start > self.end {
            (*self, Self::empty())
        } else {
            (
                AddressRange {
                    start: self.start,
                    end: split_start - 1,
                },
                AddressRange {
                    start: split_start,
                    end: self.end,
                },
            )
        }
    }

    /// Computes the length of an `AddressRange`.
    ///
    /// Returns `None` if the length cannot be represented in `u64` (if the range is
    /// `0..=u64::MAX`).
    pub fn len(&self) -> Option<u64> {
        // Treat any range we consider "empty" (end < start) as having 0 length.
        if self.is_empty() {
            Some(0)
        } else {
            (self.end - self.start).checked_add(1)
        }
    }

    fn log(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.is_empty() {
            f.write_str("empty")
        } else {
            f.write_fmt(format_args!("{:#x}..={:#x}", self.start, self.end))
        }
    }
}

impl std::fmt::Display for AddressRange {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.log(f)
    }
}

impl std::fmt::Debug for AddressRange {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.log(f)
    }
}

impl From<RangeInclusive<u64>> for AddressRange {
    fn from(range: RangeInclusive<u64>) -> AddressRange {
        AddressRange {
            start: *range.start(),
            end: *range.end(),
        }
    }
}

impl From<AddressRange> for RangeInclusive<u64> {
    fn from(address_range: AddressRange) -> RangeInclusive<u64> {
        address_range.start..=address_range.end
    }
}

/// Custom comparison function that provides a total order over all possible `AddressRange` values
/// and considers all empty ranges to be equal.
impl cmp::Ord for AddressRange {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match (self.is_empty(), other.is_empty()) {
            // Any empty range is equal to any other empty range.
            (true, true) => cmp::Ordering::Equal,
            // An empty range is less than any non-empty range.
            (true, false) => cmp::Ordering::Less,
            // Any non-empty range is greater than an empty range.
            (false, true) => cmp::Ordering::Greater,
            // Two non-empty ranges are ordered based on `start`, and if those are equal, `end`.
            (false, false) => self
                .start
                .cmp(&other.start)
                .then_with(|| self.end.cmp(&other.end)),
        }
    }
}

impl cmp::PartialOrd for AddressRange {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(cmp::Ord::cmp(self, other))
    }
}

impl cmp::PartialEq for AddressRange {
    fn eq(&self, other: &Self) -> bool {
        cmp::Ord::cmp(self, other) == cmp::Ordering::Equal
    }
}

// The `PartialEq` implementation is reflexive, symmetric, and transitive.
impl cmp::Eq for AddressRange {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_empty() {
        assert!(AddressRange { start: 1, end: 0 }.is_empty());
        assert!(AddressRange {
            start: u64::MAX,
            end: 0
        }
        .is_empty());
        assert!(AddressRange {
            start: u64::MAX,
            end: u64::MAX - 1
        }
        .is_empty());
        assert!(AddressRange::empty().is_empty());

        assert!(!AddressRange { start: 0, end: 1 }.is_empty());
        assert!(!AddressRange { start: 1, end: 1 }.is_empty());
    }

    #[test]
    fn contains() {
        assert!(AddressRange { start: 0, end: 5 }.contains(3));
        assert!(AddressRange { start: 0, end: 0 }.contains(0));
        assert!(AddressRange {
            start: 0,
            end: u64::MAX
        }
        .contains(u64::MAX));

        // Empty ranges do not contain any addresses
        assert!(!AddressRange { start: 5, end: 0 }.contains(3));
    }

    #[test]
    fn contains_range() {
        assert!(AddressRange { start: 0, end: 5 }.contains_range(AddressRange { start: 0, end: 5 }));
        assert!(AddressRange { start: 0, end: 5 }.contains_range(AddressRange { start: 1, end: 3 }));

        // Partly overlapping ranges
        assert!(
            !AddressRange { start: 0, end: 5 }.contains_range(AddressRange { start: 3, end: 9 })
        );
        assert!(
            !AddressRange { start: 3, end: 9 }.contains_range(AddressRange { start: 0, end: 5 })
        );

        // Completely discontiguous ranges
        assert!(
            !AddressRange { start: 0, end: 5 }.contains_range(AddressRange { start: 6, end: 9 })
        );
        assert!(
            !AddressRange { start: 6, end: 9 }.contains_range(AddressRange { start: 0, end: 5 })
        );

        // Empty ranges do not contain anything
        assert!(
            !AddressRange { start: 5, end: 0 }.contains_range(AddressRange { start: 0, end: 5 })
        );
        assert!(
            !AddressRange { start: 5, end: 0 }.contains_range(AddressRange { start: 5, end: 0 })
        );
        assert!(
            !AddressRange { start: 5, end: 0 }.contains_range(AddressRange { start: 1, end: 3 })
        );

        // An empty range is not contained by anything
        assert!(
            !AddressRange { start: 0, end: 5 }.contains_range(AddressRange { start: 3, end: 1 })
        );
    }

    fn test_intersect(a: (u64, u64), b: (u64, u64), answer: (u64, u64)) {
        let a = AddressRange {
            start: a.0,
            end: a.1,
        };
        let b = AddressRange {
            start: b.0,
            end: b.1,
        };
        let answer = AddressRange {
            start: answer.0,
            end: answer.1,
        };

        // intersect() should be commutative, so try it both ways
        assert_eq!(a.intersect(b), answer);
        assert_eq!(b.intersect(a), answer);
    }

    #[test]
    fn intersect() {
        test_intersect((0, 5), (0, 5), (0, 5));
        test_intersect((0, 5), (0, 3), (0, 3));
        test_intersect((0, 5), (3, 5), (3, 5));
        test_intersect((0, 5), (5, 5), (5, 5));
        test_intersect((0, 5), (4, 9), (4, 5));
        test_intersect((0, u64::MAX), (3, 5), (3, 5));
        test_intersect((10, 20), (5, 15), (10, 15));
    }

    fn test_intersect_empty(a: (u64, u64), b: (u64, u64)) {
        let a = AddressRange {
            start: a.0,
            end: a.1,
        };
        let b = AddressRange {
            start: b.0,
            end: b.1,
        };
        assert!(a.intersect(b).is_empty());
        assert!(b.intersect(a).is_empty());
    }

    #[test]
    fn intersect_empty() {
        test_intersect_empty((0, 5), (10, 20));
        test_intersect_empty((5, 0), (3, 4));
        test_intersect_empty((10, 20), (20, 10));
        test_intersect_empty((10, 20), (30, 40));
    }

    #[test]
    fn non_overlapping_ranges() {
        // Two identical ranges have no non-overlapping ranges.
        assert_eq!(
            AddressRange { start: 0, end: 100 }
                .non_overlapping_ranges(AddressRange { start: 0, end: 100 }),
            (AddressRange::empty(), AddressRange::empty())
        );

        // Non-overlapping regions on both sides.
        assert_eq!(
            AddressRange { start: 0, end: 100 }
                .non_overlapping_ranges(AddressRange { start: 10, end: 20 }),
            (
                AddressRange { start: 0, end: 9 },
                AddressRange {
                    start: 21,
                    end: 100
                }
            )
        );

        // Non-overlapping region on the left but not on the right.
        assert_eq!(
            AddressRange { start: 0, end: 100 }.non_overlapping_ranges(AddressRange {
                start: 10,
                end: 100
            }),
            (AddressRange { start: 0, end: 9 }, AddressRange::empty())
        );

        // Non-overlapping region on the right but not on the left.
        assert_eq!(
            AddressRange { start: 0, end: 100 }
                .non_overlapping_ranges(AddressRange { start: 0, end: 50 }),
            (
                AddressRange::empty(),
                AddressRange {
                    start: 51,
                    end: 100
                }
            )
        );

        // Other range not contained within this range and greater than this range.
        assert_eq!(
            AddressRange { start: 0, end: 100 }.non_overlapping_ranges(AddressRange {
                start: 200,
                end: 300
            }),
            (AddressRange { start: 0, end: 100 }, AddressRange::empty())
        );

        // Other range not contained within this range and less than this range.
        assert_eq!(
            AddressRange {
                start: 200,
                end: 300
            }
            .non_overlapping_ranges(AddressRange { start: 0, end: 100 }),
            (
                AddressRange::empty(),
                AddressRange {
                    start: 200,
                    end: 300
                }
            )
        );

        // Partially overlapping region with non-overlapping region on the left.
        assert_eq!(
            AddressRange { start: 10, end: 20 }
                .non_overlapping_ranges(AddressRange { start: 15, end: 35 }),
            (AddressRange { start: 10, end: 14 }, AddressRange::empty())
        );

        // Partially overlapping region with non-overlapping region on the right.
        assert_eq!(
            AddressRange { start: 10, end: 20 }
                .non_overlapping_ranges(AddressRange { start: 5, end: 15 }),
            (AddressRange::empty(), AddressRange { start: 16, end: 20 })
        );
    }

    #[test]
    fn split_at() {
        assert_eq!(
            AddressRange { start: 10, end: 20 }.split_at(15),
            (
                AddressRange { start: 10, end: 14 },
                AddressRange { start: 15, end: 20 }
            )
        );
        assert_eq!(
            AddressRange { start: 10, end: 20 }.split_at(20),
            (
                AddressRange { start: 10, end: 19 },
                AddressRange { start: 20, end: 20 }
            )
        );
        assert_eq!(
            AddressRange { start: 10, end: 20 }.split_at(10),
            (AddressRange { start: 10, end: 20 }, AddressRange::empty())
        );
        assert_eq!(
            AddressRange { start: 10, end: 20 }.split_at(21),
            (AddressRange { start: 10, end: 20 }, AddressRange::empty())
        );
        assert_eq!(
            AddressRange { start: 10, end: 20 }.split_at(9),
            (AddressRange { start: 10, end: 20 }, AddressRange::empty())
        );
    }

    #[test]
    fn from_start_and_size_valid() {
        assert_eq!(
            AddressRange::from_start_and_size(0x100, 0x20),
            Some(AddressRange {
                start: 0x100,
                end: 0x11f
            })
        );

        // Max-sized range based at 0
        assert_eq!(
            AddressRange::from_start_and_size(0, u64::MAX),
            Some(AddressRange {
                start: 0,
                end: u64::MAX - 1
            })
        );

        // Max-sized range based at 1
        assert_eq!(
            AddressRange::from_start_and_size(1, u64::MAX),
            Some(AddressRange {
                start: 1,
                end: u64::MAX
            })
        );

        // One-byte range based at u64::MAX
        assert_eq!(
            AddressRange::from_start_and_size(u64::MAX, 1),
            Some(AddressRange {
                start: u64::MAX,
                end: u64::MAX
            })
        );

        // Empty range (size = 0) with arbitrary start
        assert!(AddressRange::from_start_and_size(u64::MAX, 0)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn from_start_and_size_invalid() {
        // 2 + u64::MAX - 1 overflows
        assert_eq!(AddressRange::from_start_and_size(2, u64::MAX), None);

        // 0x100 + u64::MAX - 1 overflows
        assert_eq!(AddressRange::from_start_and_size(0x100, u64::MAX), None);

        // 0x100 + (u64::MAX - 0xfe) - 1 overflows
        assert_eq!(
            AddressRange::from_start_and_size(0x100, u64::MAX - 0xfe),
            None
        );
    }

    #[test]
    fn display() {
        assert_eq!(
            format!(
                "{}",
                AddressRange {
                    start: 0x1234,
                    end: 0x5678
                }
            ),
            "0x1234..=0x5678"
        );
        assert_eq!(format!("{}", AddressRange::empty()), "empty");
    }

    #[test]
    fn cmp() {
        assert!(
            AddressRange {
                start: 0x1000,
                end: 0x2000
            } < AddressRange {
                start: 0x3000,
                end: 0x4000
            }
        );
        assert!(
            AddressRange {
                start: 0x1000,
                end: 0x2000
            } == AddressRange {
                start: 0x1000,
                end: 0x2000
            }
        );
        assert!(
            AddressRange {
                start: 0x3000,
                end: 0x4000
            } > AddressRange {
                start: 0x1000,
                end: 0x2000
            }
        );
        assert!(
            AddressRange {
                start: 0x1000,
                end: 0x2000
            } < AddressRange {
                start: 0x1000,
                end: 0x3000
            }
        );
    }

    #[test]
    fn cmp_empty() {
        // Empty ranges are less than any non-empty range and equal to any other empty range.
        assert!(
            AddressRange {
                start: 0x1000,
                end: 0x2000
            } > AddressRange::empty()
        );
        assert!(
            AddressRange::empty()
                < AddressRange {
                    start: 0x1000,
                    end: 0x2000
                }
        );
        assert!(AddressRange { start: 5, end: 3 } == AddressRange { start: 10, end: 1 });
    }
}

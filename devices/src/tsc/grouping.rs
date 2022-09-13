// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::Ordering;
use std::cmp::Reverse;
use std::ops::Sub;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Result;
use base::warn;

fn abs_diff<T: Sub<Output = T> + Ord>(x: T, y: T) -> T {
    if x < y {
        y - x
    } else {
        x - y
    }
}

#[derive(Default, Debug, Clone, Copy, Eq, PartialEq)]
pub struct CoreOffset {
    pub core: usize,
    pub offset: i128,
}

impl Ord for CoreOffset {
    // CoreOffsets are ordered by offset ascending, then by their core number ascending
    fn cmp(&self, other: &Self) -> Ordering {
        (self.offset, self.core).cmp(&(other.offset, other.core))
    }
}

impl PartialOrd for CoreOffset {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct CoreGroup {
    pub cores: Vec<CoreOffset>,
}

impl CoreGroup {
    fn size(&self) -> usize {
        self.cores.len()
    }

    fn add(&self, core: CoreOffset, limit: u128) -> Result<Self> {
        let diff_from_min = abs_diff(self.cores.iter().min().unwrap().offset, core.offset) as u128;
        let diff_from_max = abs_diff(self.cores.iter().max().unwrap().offset, core.offset) as u128;
        let can_add = diff_from_min < limit && diff_from_max < limit;

        if can_add {
            let mut new = self.clone();
            new.cores.push(core);
            Ok(new)
        } else {
            Err(anyhow!(
                "offset {} not within {} of all members of core group",
                core.offset,
                limit
            ))
        }
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct CoreGrouping {
    groups: Vec<CoreGroup>,
}

impl Ord for CoreGrouping {
    fn cmp(&self, other: &Self) -> Ordering {
        // Ordered by largest group size descending, then by number of groups ascending
        (Reverse(self.largest_group().size()), self.groups.len())
            .cmp(&(Reverse(other.largest_group().size()), other.groups.len()))
    }
}

impl PartialOrd for CoreGrouping {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl CoreGrouping {
    pub(super) fn new(groups: Vec<CoreGroup>) -> Result<Self> {
        // Other functions in this type rely on the fact that there is at least one CoreGroup.
        if groups.is_empty() {
            return Err(anyhow!("Cannot create an empty CoreGrouping."));
        }
        Ok(CoreGrouping { groups })
    }

    pub fn size(&self) -> usize {
        self.groups.len()
    }

    pub fn largest_group_index(&self) -> usize {
        // Sort by Reverse(size) then group index, and take the min.
        // We could sort by size then Reverse(index), but then getting the index out is hard.
        self.groups
            .iter()
            .enumerate()
            .map(|(i, g)| (Reverse(g.size()), i))
            .min()
            .unwrap_or((Reverse(0), 0))
            .1
    }

    pub fn largest_group(&self) -> &CoreGroup {
        &self.groups[self.largest_group_index()]
    }

    pub fn core_grouping_bitmask(&self) -> u64 {
        // If there's only one group, then all cores are in sync
        if self.size() == 0 {
            return 0;
        }

        let mut bitmask = 0u64;
        let largest_group_index = self.largest_group_index();
        for (i, group) in self.groups.iter().enumerate() {
            // The largest group is considered the in-sync group
            if i == largest_group_index {
                continue;
            }

            // Set the bitmask to 1 for all cores in all other groups
            for core in &group.cores {
                if core.core > 63 {
                    warn!("Core grouping bitmask cannot contain core {}", core.core);
                    continue;
                }
                bitmask |= 1 << core.core;
            }
        }

        bitmask
    }

    fn add_group(&mut self, group: CoreGroup) {
        self.groups.push(group)
    }

    fn add_core_to_last_group(&self, core: CoreOffset, in_sync_threshold: u128) -> Option<Self> {
        let last_group = self.groups.len() - 1;
        self.groups[last_group]
            .add(core, in_sync_threshold)
            .map(|new_group| {
                let mut new_grouping = self.clone();
                new_grouping.groups[last_group] = new_group;
                new_grouping
            })
            .ok()
    }
}

/// Group cores by their offsets that are within `in_sync_threshold` of each other.
///
/// This uses a generic integer grouping algorithm. Because we're grouping within a threshold,
/// there are potentially multiple ways we can group the integers, and we want to find the "best"
/// grouping. Our definition of best grouping is:
///   1. The grouping who's largest group is the largest.
///   2. If there are multiple groupings with the same size largest group, take the one with the
///      fewest groups.
///
/// We could naively generate all possible groupings by iterating through the sorted integers and,
/// for each grouping, either adding that integer as it's own group or adding it to the last group
/// of that grouping. This could generate 2^N groupings, where N is the number of integers. Instead,
/// we still iterate through the sorted integers and, for each grouping, we add it to the last
/// group of that grouping. But we only add the integer as it's own group to the current best
/// grouping. This optimization avoids creating groupings that we know will not be the "best"
/// grouping, because adding the integer as it's own group means that all subsequent integers
/// cannot be grouped with the existing groups, and thus we only care about the optimal existing
/// groups.
pub(super) fn group_core_offsets(
    offsets: &[(usize, i128)],
    in_sync_threshold: Duration,
    tsc_frequency: u64,
) -> Result<CoreGrouping> {
    if offsets.is_empty() {
        bail!("Per-core offsets cannot be empty");
    }

    // Convert threshold to TSC ticks
    let in_sync_threshold_ticks =
        in_sync_threshold.as_nanos() * tsc_frequency as u128 / 1_000_000_000u128;

    let mut cores: Vec<CoreOffset> = offsets
        .iter()
        .map(|(i, offset)| CoreOffset {
            core: *i,
            offset: *offset,
        })
        .collect();

    // Cores are sorted by their ascending by their offset then ascending by their core #. See the
    // Ord implementation for CoreOffset.
    cores.sort();

    let mut grouping_options: Vec<CoreGrouping> = vec![CoreGrouping::new(vec![CoreGroup {
        cores: vec![cores[0]],
    }])?];
    for core in &cores[1..] {
        let mut best = grouping_options[0].clone();
        best.add_group(CoreGroup { cores: vec![*core] });

        let mut next_grouping_options = vec![best];

        for grouping_option in &grouping_options {
            if let Some(new_grouping) =
                grouping_option.add_core_to_last_group(*core, in_sync_threshold_ticks)
            {
                next_grouping_options.push(new_grouping);
            }
        }

        next_grouping_options.sort();
        grouping_options = next_grouping_options;
    }

    Ok(grouping_options[0].clone())
}

#[cfg(test)]
mod tests {
    use super::super::TscState;
    use super::*;

    #[test]
    fn test_simple_offset_grouping() {
        let offsets = vec![(0, 10), (1, 10), (2, 10), (3, 1000)];
        let state = TscState::new(1_000_000_000, offsets, Duration::from_nanos(1))
            .expect("TscState::new should not fail for this test");

        let group0 = CoreGroup {
            cores: vec![
                CoreOffset {
                    core: 0,
                    offset: 10,
                },
                CoreOffset {
                    core: 1,
                    offset: 10,
                },
                CoreOffset {
                    core: 2,
                    offset: 10,
                },
            ],
        };
        let group1 = CoreGroup {
            cores: vec![CoreOffset {
                core: 3,
                offset: 1000,
            }],
        };
        assert_eq!(
            state.core_grouping,
            CoreGrouping::new(vec![group0.clone(), group1])
                .expect("CoreGrouping::new should not fail here")
        );

        assert_eq!(state.core_grouping.largest_group().clone(), group0);
        assert_eq!(state.core_grouping.core_grouping_bitmask(), 0b1000u64);
    }

    #[test]
    fn test_ambiguous_offset_grouping() {
        // Could be grouped in several ways:
        //  - [10, 20] [30, 40] [50] <--- we like to have core0 be in a larger group
        //  - [10] [20, 30] [40, 50]
        //  - [10, 20] [30] [40, 50]
        let offsets = vec![(0, 10), (1, 20), (2, 30), (3, 40), (4, 50)];
        let state = TscState::new(1_000_000_000, offsets, Duration::from_nanos(20))
            .expect("TscState::new should not fail for this test");

        let group0 = CoreGroup {
            cores: vec![
                CoreOffset {
                    core: 0,
                    offset: 10,
                },
                CoreOffset {
                    core: 1,
                    offset: 20,
                },
            ],
        };
        let group1 = CoreGroup {
            cores: vec![
                CoreOffset {
                    core: 2,
                    offset: 30,
                },
                CoreOffset {
                    core: 3,
                    offset: 40,
                },
            ],
        };
        let group2 = CoreGroup {
            cores: vec![CoreOffset {
                core: 4,
                offset: 50,
            }],
        };
        assert_eq!(
            state.core_grouping,
            CoreGrouping::new(vec![group0.clone(), group1, group2])
                .expect("CoreGrouping::new should not fail here")
        );

        // largest_group should return the first group over other equally large groups
        assert_eq!(state.core_grouping.largest_group().clone(), group0);
        assert_eq!(state.core_grouping.core_grouping_bitmask(), 0b11100u64);
    }

    #[test]
    fn test_worst_case_grouping() {
        // Worst case for the grouping algorithm, where if your algorithm isn't smart you can
        // generate 2^129 groupings, which would be too large for a Vec to hold. This test just
        // verifies that we don't crash or run out of memory.
        let offsets = (0..129).map(|i| (i, 0)).collect();
        TscState::new(1_000_000_000, offsets, Duration::from_nanos(1))
            .expect("TscState::new should not fail for this test");
    }
}

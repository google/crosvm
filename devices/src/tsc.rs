// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Handles operations using platform Time Stamp Counter (TSC).

// TODO(b/213149158): Remove after uses are added.
#![allow(dead_code)]

use std::arch::x86_64::_rdtsc;

use anyhow::anyhow;
use anyhow::Result;
use base::debug;
use base::error;
use once_cell::sync::Lazy;

mod calibrate;
mod cpuid;
mod grouping;

pub use calibrate::*;
pub use cpuid::*;

fn rdtsc_safe() -> u64 {
    // Safe because _rdtsc takes no arguments
    unsafe { _rdtsc() }
}

// Singleton for getting the state of the host TSCs, to avoid calibrating multiple times.
static TSC_STATE: Lazy<Option<TscState>> = Lazy::new(|| match calibrate_tsc_state() {
    Ok(tsc_state) => {
        debug!("Using calibrated tsc frequency: {} Hz", tsc_state.frequency);
        for (core, offset) in tsc_state.offsets.iter().enumerate() {
            debug!("Core {} has tsc offset of {:?} ns", core, offset);
        }
        Some(tsc_state)
    }
    Err(e) => {
        error!("Failed to calibrate tsc state: {:#}", e);
        None
    }
});

/// Returns the frequency of the host TSC. Calibration only happens once.
pub fn tsc_frequency() -> Result<u64> {
    let state = TSC_STATE
        .as_ref()
        .ok_or(anyhow!("TSC calibration failed"))?;
    Ok(state.frequency)
}

/// Returns the state of the host TSCs. Calibration only happens once.
pub fn tsc_state() -> Result<TscState> {
    Ok(TSC_STATE
        .as_ref()
        .ok_or(anyhow!("TSC calibration failed"))?
        .clone())
}

#[derive(Default, Debug)]
pub struct TscSyncMitigations {
    /// Vec of per-vcpu affinities to apply to each vcpu thread. If None, no affinity should be
    /// applied.
    pub affinities: Vec<Option<Vec<usize>>>,
    /// Vec of TSC offsets to set on each vcpu. If None, no offset should be applied.
    pub offsets: Vec<Option<u64>>,
}

impl TscSyncMitigations {
    fn new(num_vcpus: usize) -> Self {
        TscSyncMitigations {
            affinities: vec![None; num_vcpus],
            offsets: vec![None; num_vcpus],
        }
    }

    pub fn get_vcpu_affinity(&self, cpu_id: usize) -> Option<Vec<usize>> {
        self.affinities.get(cpu_id).unwrap().clone()
    }

    pub fn get_vcpu_tsc_offset(&self, cpu_id: usize) -> Option<u64> {
        *self.offsets.get(cpu_id).unwrap()
    }
}

/// Given the state of the host TSCs in `tsc_state`, and the number of vcpus that are intended to
/// be run, return a set of affinities and TSC offsets to apply to those vcpus.
pub fn get_tsc_sync_mitigations(tsc_state: &TscState, num_vcpus: usize) -> TscSyncMitigations {
    tsc_sync_mitigations_inner(tsc_state, num_vcpus, rdtsc_safe)
}

fn tsc_sync_mitigations_inner(
    tsc_state: &TscState,
    num_vcpus: usize,
    rdtsc: fn() -> u64,
) -> TscSyncMitigations {
    let mut mitigations = TscSyncMitigations::new(num_vcpus);
    // If there's only one core grouping that means all the TSCs are in sync and no mitigations are
    // needed.
    if tsc_state.core_grouping.size() == 1 {
        return mitigations;
    }

    let largest_group = tsc_state.core_grouping.largest_group();
    let num_cores = tsc_state.offsets.len();

    // If the largest core group is larger than the number of vcpus, just pin all vcpus to that core
    // group, and no need to set offsets.
    if largest_group.cores.len() >= num_vcpus {
        let affinity: Vec<usize> = largest_group.cores.iter().map(|core| core.core).collect();
        for i in 0..num_vcpus {
            mitigations.affinities[i] = Some(affinity.clone());
        }
    } else {
        // Otherwise, we pin each vcpu to a core and set it's offset to compensate.
        let host_tsc_now = rdtsc();

        for i in 0..num_vcpus {
            // This handles the case where num_vcpus > num_cores, even though we try to avoid that in
            // practice.
            let pinned_core = i % num_cores;

            mitigations.affinities[i] = Some(vec![pinned_core]);
            // The guest TSC value is calculated like so:
            //   host_tsc + tsc_offset = guest_tsc
            // If we assume that each host core has it's own error (core_offset), then it's more
            // like this:
            //   host_tsc + core_offset + tsc_offset = guest_tsc
            // We want guest_tsc to be 0 at boot, so the formula is this:
            //   host_tsc + core_offset + tsc_offset = 0
            // and then you subtract host_tsc and core_offset from both sides and you get:
            //   tsc_offset = 0 - host_tsc - core_offset
            mitigations.offsets[i] = Some(
                0u64.wrapping_sub(host_tsc_now)
                    // Note: wrapping_add and casting tsc_state from an i64 to a u64 should be the
                    //  same as using the future wrapping_add_signed function, which is only in
                    //  nightly. This should be switched to using wrapping_add_signed once that is
                    //  in stable.
                    .wrapping_add(tsc_state.offsets[pinned_core].1.wrapping_neg() as i64 as u64),
            );
        }
    }

    mitigations
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::tsc::grouping::CoreGroup;
    use crate::tsc::grouping::CoreGrouping;
    use crate::tsc::grouping::CoreOffset;

    #[test]
    fn test_sync_mitigation_set_offsets() {
        let offsets = vec![(0, 0), (1, 1000), (2, -1000), (3, 2000)];
        // frequency of 1GHz means 20 nanos is 20 ticks
        let state = TscState::new(1_000_000_000, offsets, Duration::from_nanos(20))
            .expect("TscState::new should not fail for this test");

        assert_eq!(
            state.core_grouping,
            CoreGrouping::new(vec![
                CoreGroup {
                    cores: vec![CoreOffset {
                        core: 2,
                        offset: -1000
                    }]
                },
                CoreGroup {
                    cores: vec![CoreOffset { core: 0, offset: 0 }]
                },
                CoreGroup {
                    cores: vec![CoreOffset {
                        core: 1,
                        offset: 1000
                    }]
                },
                CoreGroup {
                    cores: vec![CoreOffset {
                        core: 3,
                        offset: 2000
                    }]
                },
            ])
            .expect("CoreGrouping::new should not fail here")
        );

        fn fake_rdtsc() -> u64 {
            u64::MAX
        }

        let mitigations = tsc_sync_mitigations_inner(&state, 4, fake_rdtsc);

        // core offsets are:
        //  - core 0: has an offset of 0, so TSC offset = 0 - u64::MAX - 0 = 1
        //  - core 1: has an offset of 1000, so TSC offset = 0 - u64::MAX - 1000 = -999
        //  - core 2: has an offset of -1000, so TSC offset = 0 - u64::MAX + 1000 = 1001
        //  - core 3: has an offset of 2000, so TSC offset = 0 - u64::MAX - 2000 = -1999
        let expected = [1, 1u64.wrapping_sub(1000), 1001u64, 1u64.wrapping_sub(2000)];

        for (i, expect) in expected.iter().enumerate() {
            assert_eq!(
                mitigations
                    .get_vcpu_tsc_offset(i)
                    .unwrap_or_else(|| panic!("core {} should have an offset of {}", i, expect)),
                *expect
            );

            assert_eq!(
                mitigations
                    .get_vcpu_affinity(i)
                    .unwrap_or_else(|| panic!("core {} should have an affinity of [{}]", i, i)),
                vec![i]
            );
        }
    }

    #[test]
    fn test_sync_mitigation_large_group() {
        // 8 cores, and cores 1,3,5,7 are in-sync at offset -1000
        let offsets = vec![
            (0, 0),
            (1, -1000),
            (2, 1000),
            (3, -1000),
            (4, 2000),
            (5, -1000),
            (6, 3000),
            (7, -1000),
        ];
        // frequency of 1GHz means 20 nanos is 20 ticks
        let state = TscState::new(1_000_000_000, offsets, Duration::from_nanos(20))
            .expect("TscState::new should not fail for this test");

        assert_eq!(
            state.core_grouping,
            CoreGrouping::new(vec![
                CoreGroup {
                    cores: vec![
                        CoreOffset {
                            core: 1,
                            offset: -1000
                        },
                        CoreOffset {
                            core: 3,
                            offset: -1000
                        },
                        CoreOffset {
                            core: 5,
                            offset: -1000
                        },
                        CoreOffset {
                            core: 7,
                            offset: -1000
                        }
                    ]
                },
                CoreGroup {
                    cores: vec![CoreOffset { core: 0, offset: 0 }]
                },
                CoreGroup {
                    cores: vec![CoreOffset {
                        core: 2,
                        offset: 1000
                    }]
                },
                CoreGroup {
                    cores: vec![CoreOffset {
                        core: 4,
                        offset: 2000
                    }]
                },
                CoreGroup {
                    cores: vec![CoreOffset {
                        core: 6,
                        offset: 3000
                    }]
                },
            ])
            .expect("CoreGrouping::new should not fail here")
        );

        fn fake_rdtsc() -> u64 {
            u64::MAX
        }

        let num_vcpus = 4;
        let mitigations = tsc_sync_mitigations_inner(&state, num_vcpus, fake_rdtsc);

        let expected_affinity = vec![1, 3, 5, 7];
        for i in 0..num_vcpus {
            assert_eq!(
                mitigations.get_vcpu_affinity(i).unwrap_or_else(|| panic!(
                    "core {} should have an affinity of {:?}",
                    i, expected_affinity
                )),
                expected_affinity
            );
            assert_eq!(mitigations.get_vcpu_tsc_offset(i), None);
        }
    }

    #[test]
    fn more_vcpus_than_cores() {
        // 4 cores, two can be grouped but it doesn't matter because we'll have more vcpus than
        // the largest group.
        let offsets = vec![(0, 0), (1, 0), (2, 1000), (3, 2000)];
        // frequency of 1GHz means 20 nanos is 20 ticks
        let state = TscState::new(1_000_000_000, offsets, Duration::from_nanos(20))
            .expect("TscState::new should not fail for this test");

        assert_eq!(
            state.core_grouping,
            CoreGrouping::new(vec![
                CoreGroup {
                    cores: vec![
                        CoreOffset { core: 0, offset: 0 },
                        CoreOffset { core: 1, offset: 0 }
                    ]
                },
                CoreGroup {
                    cores: vec![CoreOffset {
                        core: 2,
                        offset: 1000
                    }]
                },
                CoreGroup {
                    cores: vec![CoreOffset {
                        core: 3,
                        offset: 2000
                    }]
                },
            ])
            .expect("CoreGrouping::new should not fail here")
        );

        fn fake_rdtsc() -> u64 {
            u64::MAX
        }

        // 8 vcpus, more than we have cores
        let num_vcpus = 8;
        let mitigations = tsc_sync_mitigations_inner(&state, num_vcpus, fake_rdtsc);
        let expected_offsets = [1, 1, 1u64.wrapping_sub(1000), 1u64.wrapping_sub(2000)];

        for i in 0..num_vcpus {
            assert_eq!(
                mitigations.get_vcpu_affinity(i).unwrap_or_else(|| panic!(
                    "core {} should have an affinity of {:?}",
                    i,
                    i % 4
                )),
                // expected affinity is the vcpu modulo 4
                vec![i % 4]
            );
            assert_eq!(
                mitigations.get_vcpu_tsc_offset(i).unwrap_or_else(|| panic!(
                    "core {} should have an offset of {:?}",
                    i,
                    expected_offsets[i % 4]
                )),
                expected_offsets[i % 4]
            );
        }
    }
}

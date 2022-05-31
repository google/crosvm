// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::{anyhow, bail, Context, Result};
use base::set_cpu_affinity;
use std::collections::HashSet;
use std::iter::FromIterator;
use std::time::{Duration, Instant};

use super::grouping::*;

const TSC_CALIBRATION_SAMPLES: usize = 10;
const TSC_CALIBRATION_DURATION: Duration = Duration::from_millis(100);
// remove data that is outside 3 standard deviations off the median
const TSC_CALIBRATION_STANDARD_DEVIATION_LIMIT: f64 = 3.0;
// We consider two TSC cores to be in sync if they are within 2 microseconds of each other.
// An optimal context switch takes about 1-3 microseconds.
const TSC_OFFSET_GROUPING_THRESHOLD: Duration = Duration::from_micros(2);

/// Get the standard deviation of a Vec<T>.
pub fn standard_deviation<T: num_traits::ToPrimitive + num_traits::Num + Copy>(items: &[T]) -> f64 {
    let sum: T = items.iter().fold(T::zero(), |acc: T, elem| acc + *elem);
    let count = items.len();

    let mean: f64 = sum.to_f64().unwrap_or(0.0) / count as f64;

    let variance = items
        .iter()
        .map(|x| {
            let diff = mean - (x.to_f64().unwrap_or(0.0));
            diff * diff
        })
        .sum::<f64>();
    (variance / count as f64).sqrt()
}

fn sort_and_get_bounds(items: &mut Vec<i128>, stdev_limit: f64) -> (f64, f64) {
    items.sort_unstable();
    let median = items[items.len() / 2];

    let standard_deviation = standard_deviation(items);
    let lower_bound = median as f64 - stdev_limit * standard_deviation;
    let upper_bound = median as f64 + stdev_limit * standard_deviation;
    (lower_bound, upper_bound)
}

/// Represents the host monotonic time and the TSC value at a single moment in time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct TscMoment {
    time: Instant,
    tsc: u64,
}

impl TscMoment {
    fn now(rdtsc: fn() -> u64) -> Self {
        TscMoment {
            time: Instant::now(),
            tsc: rdtsc(),
        }
    }

    /// Measure the tsc frequency using two `TscMoment`s.
    fn measure_tsc_frequency(first: &TscMoment, second: &TscMoment) -> i128 {
        // handle case where first is actually second in time
        let (first, second) = if first.time > second.time {
            (second, first)
        } else {
            (first, second)
        };

        let time_delta = second.time - first.time;
        let tsc_delta = second.tsc as i128 - first.tsc as i128;

        tsc_delta * 1_000_000_000i128 / time_delta.as_nanos() as i128
    }

    /// Measure the tsc offset using two `TscMoment`s and the TSC frequency.
    fn measure_tsc_offset(first: &TscMoment, second: &TscMoment, tsc_frequency: u64) -> i128 {
        // handle case where first is actually second in time
        let (first, second) = if first.time > second.time {
            (second, first)
        } else {
            (first, second)
        };

        let tsc_delta = second.tsc as i128 - first.tsc as i128;
        let time_delta_as_tsc_ticks =
            (second.time - first.time).as_nanos() * tsc_frequency as u128 / 1_000_000_000u128;
        tsc_delta - time_delta_as_tsc_ticks as i128
    }
}

#[derive(Default, Debug, Clone)]
pub struct TscState {
    pub frequency: u64,
    pub offsets: Vec<i128>,
    pub core_grouping: CoreGrouping,
}

impl TscState {
    pub(crate) fn new(
        tsc_frequency: u64,
        offsets: Vec<i128>,
        in_sync_threshold: Duration,
    ) -> Result<Self> {
        let core_grouping = group_core_offsets(&offsets, in_sync_threshold, tsc_frequency)
            .context("Failed to group cores by their TSC offsets")?;
        Ok(TscState {
            frequency: tsc_frequency,
            offsets,
            core_grouping,
        })
    }
}

/// Calibrate the TSC frequency of `core`.
///
/// This function first pins itself to `core`, generates `num_samples` start `TscMoment`s, sleeps
/// for `calibration_duration`, and then generates `num_samples` end `TscMoment`s. For each pair
/// of start and end moments, a TSC frequency value is calculated. Any frequencies that are
/// outside of `stddev_limit` standard deviations from the median offset are discarded, because
/// they may represent an interrupt that occurred while a TscMoment was generated. The remaining
/// non-discarded frequencies are then averaged. The function returns the TSC frequency average, as
/// well as a Vec of `TscMoment`s, which are all of the end moments that were associated with at
/// least one non-discarded frequency.
///
/// # Arguments
/// * `core` - Core that this function should run on.
/// * `rdtsc` - Function for reading the TSC value, usually just runs RDTSC instruction.
/// * `num_samples` - Number of start and end `TscMoment`s to generate.
/// * `calibration_duration` - How long to sleep in between gathering start and end moments.
/// * `stdev_limit` - Number of standard deviations outside of which frequencies are discarded.
fn calibrate_tsc_frequency(
    rdtsc: fn() -> u64,
    core: usize,
    num_samples: usize,
    calibration_duration: Duration,
    stdev_limit: f64,
) -> Result<(i128, Vec<TscMoment>)> {
    set_cpu_affinity(vec![core])
        .context(format!("failed to set thread cpu affinity to [{}]", core))?;

    let starts: Vec<TscMoment> = (0..num_samples).map(|_| TscMoment::now(rdtsc)).collect();

    std::thread::sleep(calibration_duration);

    let ends: Vec<TscMoment> = (0..num_samples).map(|_| TscMoment::now(rdtsc)).collect();

    let mut freqs = Vec::with_capacity(num_samples * num_samples);
    for start in &starts {
        for end in &ends {
            freqs.push(TscMoment::measure_tsc_frequency(start, end))
        }
    }

    let (lower_bound, upper_bound) = sort_and_get_bounds(&mut freqs, stdev_limit);

    let mut good_samples: Vec<i128> = Vec::with_capacity(num_samples * num_samples);
    let mut good_end_moments: HashSet<TscMoment> = HashSet::new();
    for i in 0..num_samples {
        for j in 0..num_samples {
            let freq = freqs[i * num_samples + j];

            if lower_bound < (freq as f64) && (freq as f64) < upper_bound {
                good_end_moments.insert(ends[j]);
                good_samples.push(freq);
            }
        }
    }

    Ok((
        good_samples.iter().map(|&x| x as i128).sum::<i128>() / good_samples.len() as i128,
        Vec::from_iter(good_end_moments),
    ))
}

/// Measure the TSC offset for `core` from core 0 where `reference_moments` were gathered.
///
/// This function first pins itself to `core`, then generates `num_samples` `TscMoment`s for this
/// core, and then measures the TSC offset between those moments and all `reference_moments`. Any
/// moments that are outside of `stddev_limit` standard deviations from the median offset are
/// discarded, because they may represent an interrupt that occurred while a TscMoment was
/// generated. The remaining offsets are averaged and returned as nanoseconds.
///
/// # Arguments
/// * `core` - Core that this function should run on.
/// * `rdtsc` - Function for reading the TSC value, usually just runs RDTSC instruction.
/// * `tsc_frequency` - TSC frequency measured from core 0.
/// * `reference_moments` - `TscMoment`s gathered from core 0.
/// * `num_samples` - Number of `TscMoment`s to generate on this thread for measuring the offset.
/// * `stdev_limit` - Number of standard deviations outside of which offsets are discarded.
fn measure_tsc_offset(
    core: usize,
    rdtsc: fn() -> u64,
    tsc_frequency: u64,
    reference_moments: Vec<TscMoment>,
    num_samples: usize,
    stdev_limit: f64,
) -> Result<i128> {
    set_cpu_affinity(vec![core]).context("failed to set cpu affinity")?;

    let mut diffs: Vec<i128> = Vec::with_capacity(num_samples);

    for _ in 0..num_samples {
        let now = TscMoment::now(rdtsc);
        for reference_moment in &reference_moments {
            diffs.push(TscMoment::measure_tsc_offset(
                reference_moment,
                &now,
                tsc_frequency,
            ));
        }
    }

    let (lower_bound, upper_bound) = sort_and_get_bounds(&mut diffs, stdev_limit);

    let mut good_samples: Vec<i128> = Vec::with_capacity(num_samples);
    for diff in &diffs {
        if lower_bound < (*diff as f64) && (*diff as f64) < upper_bound {
            good_samples.push(*diff);
        }
    }

    let average_diff =
        good_samples.iter().map(|&x| x as i128).sum::<i128>() / good_samples.len() as i128;

    // Convert the diff to nanoseconds using the tsc_frequency
    Ok(average_diff * 1_000_000_000 / tsc_frequency as i128)
}

/// Calibrate the TSC state.
///
/// This function first runs a TSC frequency calibration thread for 100ms, which is pinned to
/// core0. The TSC calibration thread returns both the calibrated frequency, as well as a Vec of
/// TscMoment objects which were validated to be accurate (meaning it's unlikely an interrupt
/// occurred between moment's `time` and `tsc` values). This function then runs a tsc offset
/// measurement thread for each core, which takes the TSC frequency and the Vec of TscMoments and
/// measures whether or not the TSC values for that core are offset from core 0, and by how much.
/// The frequency and the per-core offsets are returned as a TscState.
///
/// # Arguments
///
/// * `rdtsc` - Function for reading the TSC value, usually just runs RDTSC instruction.
pub fn calibrate_tsc_state(rdtsc: fn() -> u64) -> Result<TscState> {
    let handle = std::thread::spawn(move || {
        calibrate_tsc_frequency(
            rdtsc,
            0, // calibrate on core 0
            TSC_CALIBRATION_SAMPLES,
            TSC_CALIBRATION_DURATION,
            TSC_CALIBRATION_STANDARD_DEVIATION_LIMIT,
        )
        .context("Failed to calibrate tsc frequency")
    });

    let (freq, reference_moments) = handle
        .join()
        .unwrap_or_else(|e| Err(anyhow!("TSC calibration thread failed: {:?}", e)))?;

    let freq = if freq <= 0 {
        bail!("TSC calibration resulted in TSC frequency of {} Hz", freq);
    } else {
        freq as u64
    };

    let num_cores =
        base::number_of_logical_cores().context("Failed to get number of logical cores")?;

    let mut offsets: Vec<i128> = Vec::with_capacity(num_cores);
    for core in 0..num_cores {
        let thread_reference_moments = reference_moments.clone();
        let handle = std::thread::spawn(move || {
            measure_tsc_offset(
                core,
                rdtsc,
                freq,
                thread_reference_moments,
                TSC_CALIBRATION_SAMPLES,
                TSC_CALIBRATION_STANDARD_DEVIATION_LIMIT,
            )
            .context("Failed to measure tsc offset")
        });
        let offset = handle.join().unwrap_or_else(|e| {
            Err(anyhow!(
                "TSC offset measurement thread for core {} failed: {:?}",
                core,
                e
            ))
        })?;
        offsets.push(offset);
    }

    TscState::new(freq as u64, offsets, TSC_OFFSET_GROUPING_THRESHOLD)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::arch::x86_64::{__rdtscp, _rdtsc};

    const ACCEPTABLE_OFFSET_MEASUREMENT_ERROR: i128 = 2_000i128;

    #[test]
    fn test_frequency_higher_than_u32() {
        // This test is making sure that we're not truncating our TSC frequencies in the case that
        // they are greater than u32::MAX.

        fn rdtsc_safe() -> u64 {
            // Safe because rdtsc takes no arguments
            unsafe { _rdtsc() }
        }
        let host_state = calibrate_tsc_state(rdtsc_safe).expect("failed to calibrate host freq");

        // We use a static multiplier of 1000 here because the function has to be static (fn).
        // 1000 should work for tsc frequency > 4.2MHz, which should apply to basically any
        // processor. This if statement checks and bails early if that's not the case.
        if host_state.frequency * 1000 < (u32::MAX as u64) {
            return;
        }

        fn rdtsc_frequency_higher_than_u32() -> u64 {
            unsafe { _rdtsc() }.wrapping_mul(1000)
        }

        let state = calibrate_tsc_state(rdtsc_frequency_higher_than_u32).unwrap();

        let expected_freq = host_state.frequency * 1000;
        let margin_of_error = expected_freq / 100;
        assert!(state.frequency < expected_freq + margin_of_error);
        assert!(state.frequency > expected_freq - margin_of_error);
    }

    #[test]
    #[ignore]
    fn test_offset_identification_core_0() {
        fn rdtsc_with_core_0_offset_by_100_000() -> u64 {
            let mut id = 0u32;
            let mut value = unsafe { __rdtscp(&mut id as *mut u32) };
            if id == 0 {
                value += 100_000;
            }

            value
        }

        // This test only works if the host has >=2 logical cores.
        let num_cores =
            base::number_of_logical_cores().expect("Failed to get number of logical cores");
        if num_cores < 2 {
            return;
        }

        let state = calibrate_tsc_state(rdtsc_with_core_0_offset_by_100_000).unwrap();

        for core in 0..num_cores {
            let expected_offset_ns = if core > 0 {
                -100_000i128 * 1_000_000_000i128 / state.frequency as i128
            } else {
                0i128
            };
            assert!(state.offsets[core] < expected_offset_ns + ACCEPTABLE_OFFSET_MEASUREMENT_ERROR);
            assert!(state.offsets[core] > expected_offset_ns - ACCEPTABLE_OFFSET_MEASUREMENT_ERROR);
        }
    }

    #[test]
    #[ignore]
    fn test_offset_identification_core_1() {
        fn rdtsc_with_core_1_offset_by_100_000() -> u64 {
            let mut id = 0u32;
            let mut value = unsafe { __rdtscp(&mut id as *mut u32) };
            if id == 1 {
                value += 100_000;
            }

            value
        }

        // This test only works if the host has >=2 logical cores.
        let num_cores =
            base::number_of_logical_cores().expect("Failed to get number of logical cores");
        if num_cores < 2 {
            return;
        }

        let state = calibrate_tsc_state(rdtsc_with_core_1_offset_by_100_000).unwrap();

        for core in 0..num_cores {
            let expected_offset_ns = if core == 1 {
                100_000i128 * 1_000_000_000i128 / state.frequency as i128
            } else {
                0i128
            };
            assert!(state.offsets[core] < expected_offset_ns + ACCEPTABLE_OFFSET_MEASUREMENT_ERROR);
            assert!(state.offsets[core] > expected_offset_ns - ACCEPTABLE_OFFSET_MEASUREMENT_ERROR);
        }
    }
}

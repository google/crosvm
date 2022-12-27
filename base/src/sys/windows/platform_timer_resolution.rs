// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::time::Duration;

use super::platform_timer_utils::measure_timer_resolution;
use super::platform_timer_utils::nt_query_timer_resolution;
use super::platform_timer_utils::nt_set_timer_resolution;
use super::platform_timer_utils::set_time_period;
use crate::info;
use crate::warn;
use crate::EnabledHighResTimer;
use crate::Result;

/// Restores the Windows platform timer resolution to its original value on Drop.
struct NtSetTimerResolution {
    previous_duration: Duration,
    nt_set_timer_res: fn(Duration) -> Result<()>,
}
impl EnabledHighResTimer for NtSetTimerResolution {}

impl NtSetTimerResolution {
    fn new(
        query_timer_res: fn() -> Result<(Duration, Duration)>,
        nt_set_timer_res: fn(Duration) -> Result<()>,
        measure_timer_res: fn() -> Duration,
    ) -> Option<NtSetTimerResolution> {
        match query_timer_res() {
            Ok((current_res, max_res)) if max_res <= Duration::from_micros(500) => {
                match nt_set_timer_res(Duration::from_micros(500)) {
                    Ok(()) => {
                        let actual_res = measure_timer_res();
                        if actual_res < Duration::from_millis(2) {
                            info!("Successfully set timer res to 0.5ms with NtSetTimerResolution. Measured {}us.", actual_res.as_micros());
                            Some(NtSetTimerResolution {
                                previous_duration: current_res,
                                nt_set_timer_res,
                            })
                        } else {
                            warn!(
                                "Set timer res to 0.5ms with NtSetTimerResolution, but measured {}us.",
                                actual_res.as_micros()
                            );
                            None
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Failed to execute NtSetTimeResolution, got error code: {}",
                            e
                        );
                        None
                    }
                }
            }
            Ok((_, max_res)) => {
                info!(
                    "System does not support 0.5ms timer. Max res: {}us",
                    max_res.as_micros()
                );
                None
            }
            Err(e) => {
                warn!(
                    "Failed to execute NtQueryTimeResolution, got error code: {}",
                    e
                );
                None
            }
        }
    }
}

struct TimeBeginPeriod {
    time_period_setter: fn(Duration, bool) -> Result<()>,
}
impl EnabledHighResTimer for TimeBeginPeriod {}

impl Drop for NtSetTimerResolution {
    fn drop(&mut self) {
        if let Err(e) = (self.nt_set_timer_res)(self.previous_duration) {
            warn!("Failed to unset nt timer resolution w/ error code: {}", e)
        }
    }
}

impl Drop for TimeBeginPeriod {
    fn drop(&mut self) {
        if let Err(e) = (self.time_period_setter)(Duration::from_millis(1), false) {
            warn!("Failed to unset timer resolution w/ error code: {}", e)
        }
    }
}

/// Sets the Windows platform timer resolution to at least 1ms, or 0.5ms if possible on the
/// system.
pub fn enable_high_res_timers() -> Result<Box<dyn EnabledHighResTimer>> {
    enable_high_res_timers_inner(
        set_time_period,
        nt_query_timer_resolution,
        nt_set_timer_resolution,
        measure_timer_resolution,
    )
}

fn enable_high_res_timers_inner(
    time_period_setter: fn(Duration, bool) -> Result<()>,
    query_timer_res: fn() -> Result<(Duration, Duration)>,
    nt_set_timer_res: fn(Duration) -> Result<()>,
    measure_timer_res: fn() -> Duration,
) -> Result<Box<dyn EnabledHighResTimer>> {
    // Determine if possible to set 500 micro timer res, and if so proceed with using
    // undocumented winapis to do so. In case of any failures using the undocumented APIs,
    // we'll fall back on timeBegin/EndPeriod.
    let nt_timer_res =
        NtSetTimerResolution::new(query_timer_res, nt_set_timer_res, measure_timer_res);

    match nt_timer_res {
        Some(timer_res) => Ok(Box::new(timer_res)),
        None => {
            time_period_setter(Duration::from_millis(1), true)?;
            let actual_res = measure_timer_res();
            if actual_res > Duration::from_millis(2) {
                warn!(
                    "Set timer res to 1ms using timeBeginPeriod, but measured >2ms (measured: {}us).",
                    actual_res.as_micros(),
                );
            } else {
                warn!(
                    "Set timer res to 1ms using timeBeginPeriod. Measured {}us.",
                    actual_res.as_micros(),
                );
            }
            Ok(Box::new(TimeBeginPeriod { time_period_setter }))
        }
    }
}

#[cfg(test)]
/// Note that nearly all of these tests cannot run on Kokoro due to random slowness in that
/// environment.
mod tests {
    use super::*;
    use crate::Error;

    fn time_period_setter_broken(_d: Duration, _b: bool) -> Result<()> {
        Err(Error::new(100))
    }

    fn query_timer_failure() -> Result<(Duration, Duration)> {
        Err(Error::new(100))
    }

    fn query_timer_res_high_res_available() -> Result<(Duration, Duration)> {
        Ok((Duration::from_millis(15), Duration::from_micros(500)))
    }

    fn query_timer_res_high_res_unavailable() -> Result<(Duration, Duration)> {
        Ok((Duration::from_millis(15), Duration::from_millis(1)))
    }

    fn nt_set_timer_res_broken(_: Duration) -> Result<()> {
        Err(Error::new(100))
    }
    fn measure_timer_res_1ms() -> Duration {
        Duration::from_millis(1)
    }

    fn measure_timer_res_2ms() -> Duration {
        Duration::from_millis(2)
    }

    fn assert_res_within_bound(actual_res: Duration) {
        assert!(
            actual_res <= Duration::from_millis(2),
            "actual_res was {:?}, expected <= 2ms",
            actual_res
        );
    }

    // Note that on some systems, a <1ms timer is not available. In these cases, this test
    // will not exercise the NtSetTimerResolution path.
    #[test]
    #[ignore]
    fn test_nt_timer_works() {
        let _timer_res = enable_high_res_timers_inner(
            set_time_period,
            nt_query_timer_resolution,
            nt_set_timer_resolution,
            measure_timer_res_1ms,
        )
        .unwrap();
        assert_res_within_bound(measure_timer_resolution())
    }

    #[test]
    #[ignore]
    fn test_nt_timer_falls_back_on_failure() {
        let _timer_res = enable_high_res_timers_inner(
            set_time_period,
            query_timer_res_high_res_available,
            nt_set_timer_res_broken,
            measure_timer_res_1ms,
        )
        .unwrap();
        assert_res_within_bound(measure_timer_resolution())
    }

    #[test]
    #[ignore]
    fn test_nt_timer_falls_back_on_measurement_failure() {
        let _timer_res = enable_high_res_timers_inner(
            set_time_period,
            query_timer_res_high_res_available,
            nt_set_timer_res_broken,
            measure_timer_res_2ms,
        )
        .unwrap();
        assert_res_within_bound(measure_timer_resolution())
    }

    #[test]
    #[ignore]
    fn test_nt_timer_falls_back_on_low_res_system() {
        let _timer_res = enable_high_res_timers_inner(
            set_time_period,
            query_timer_res_high_res_unavailable,
            nt_set_timer_res_broken,
            measure_timer_res_1ms,
        )
        .unwrap();
        assert_res_within_bound(measure_timer_resolution())
    }

    #[test]
    #[ignore]
    fn test_nt_timer_falls_back_on_query_failure() {
        let _timer_res = enable_high_res_timers_inner(
            set_time_period,
            query_timer_failure,
            nt_set_timer_res_broken,
            measure_timer_res_1ms,
        )
        .unwrap();
        assert_res_within_bound(measure_timer_resolution())
    }

    #[test]
    fn test_all_timer_sets_fail() {
        assert!(enable_high_res_timers_inner(
            time_period_setter_broken,
            query_timer_failure,
            nt_set_timer_res_broken,
            measure_timer_res_1ms,
        )
        .is_err());
    }
}

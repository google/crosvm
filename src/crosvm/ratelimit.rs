// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Utility file to provide a ratelimit object

use std::cmp;
use std::time::Duration;
use std::time::Instant;

const BUS_LOCK_SLICE_TIME: u32 = 1000000000;

pub struct Ratelimit {
    slice_start_time: Instant,
    slice_end_time: Instant,
    slice_quota: u64,
    slice_ns: Duration,
    dispatched: u64,
}

impl Ratelimit {
    pub fn new() -> Self {
        Ratelimit {
            slice_start_time: Instant::now(),
            slice_end_time: Instant::now(),
            slice_quota: 0,
            slice_ns: Duration::new(0, BUS_LOCK_SLICE_TIME),
            dispatched: 0,
        }
    }
    pub fn ratelimit_set_speed(&mut self, speed: u64) {
        if speed == 0 {
            self.slice_quota = 0;
        } else {
            self.slice_quota = cmp::max(
                speed * self.slice_ns.as_nanos() as u64 / BUS_LOCK_SLICE_TIME as u64,
                1,
            );
        }
    }
    /// Calculate and return delay for next request in ns
    /// Record that we sent n data units (where n matches the scale chosen
    /// during ratelimit_set_speed).If we may send more data units in the
    ///  current time slice, return 0 (i.e. no delay).
    /// Otherwise return the amount of time (in ns) until the start of
    /// the next time slice that will permit sending the next chunk of data.
    ///
    /// Recording sent data units even after exceeding the quota is permitted;
    /// the time slice will be extended accordingly.
    pub fn ratelimit_calculate_delay(&mut self, n: u64) -> u64 {
        let now: Instant = Instant::now();
        if self.slice_quota == 0 {
            return 0;
        }
        if self.slice_end_time < now {
            // Previous, possibly extended, time slice finished; reset the accounting.
            self.slice_start_time = now;
            self.slice_end_time = now + self.slice_ns;
            self.dispatched = 0;
        }

        self.dispatched += n;
        if self.dispatched < self.slice_quota {
            // We may send further data within the current time slice,
            // no need to delay the next request.
            return 0;
        }
        // Quota exceeded. Wait based on the excess amount and then start a new slice.
        let delay_slices: f64 = self.dispatched as f64 / self.slice_quota as f64;
        self.slice_end_time = self.slice_start_time + delay_slices as u32 * self.slice_ns;
        (self.slice_end_time - now).as_nanos() as u64
    }
}

// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Utility file to provide a fake clock object representing current time, and a timer driven by
// that time.

use std::time::{Duration, Instant};

use super::Event;
use crate::descriptor::AsRawDescriptor;

#[derive(Debug, Copy, Clone)]
pub struct Clock(Instant);
impl Clock {
    pub fn new() -> Self {
        Clock(Instant::now())
    }

    pub fn now(&self) -> Self {
        Clock(Instant::now())
    }

    pub fn duration_since(&self, earlier: &Self) -> Duration {
        self.0.duration_since(earlier.0)
    }

    pub fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }

    pub fn checked_sub(&self, duration: Duration) -> Option<Self> {
        Some(Clock(self.0.checked_sub(duration)?))
    }
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}

const NS_PER_SEC: u64 = 1_000_000_000;
/// A fake clock that can be used in tests to give exact control over the time.
/// For a code example, see the tests in sys_util/src/timer.rs.
#[derive(Debug)]
pub struct FakeClock {
    ns_since_epoch: u64,
    deadlines: Vec<(u64, Event)>,
}

impl FakeClock {
    pub fn new() -> Self {
        FakeClock {
            ns_since_epoch: 1_547_163_599 * NS_PER_SEC,
            deadlines: Vec::new(),
        }
    }

    /// Get the current time, according to this clock.
    pub fn now(&self) -> Self {
        FakeClock {
            ns_since_epoch: self.ns_since_epoch,
            deadlines: Vec::new(),
        }
    }

    ///  Get the current time in ns, according to this clock.
    pub fn nanos(&self) -> u64 {
        self.ns_since_epoch
    }

    /// Get the duration since |earlier|, assuming that earlier < self.
    pub fn duration_since(&self, earlier: &Self) -> Duration {
        let ns_diff = self.ns_since_epoch - earlier.ns_since_epoch;
        Duration::new(ns_diff / NS_PER_SEC, (ns_diff % NS_PER_SEC) as u32)
    }

    /// Get the time that has elapsed since this clock was made. Always returns 0 on a FakeClock.
    pub fn elapsed(&self) -> Duration {
        self.now().duration_since(self)
    }

    pub fn checked_sub(&self, duration: Duration) -> Option<Self> {
        Some(FakeClock {
            ns_since_epoch: self
                .ns_since_epoch
                .checked_sub(duration.as_nanos() as u64)?,
            deadlines: Vec::new(),
        })
    }

    /// Register the event descriptor for a notification when self's time is |deadline_ns|.
    /// Drop any existing events registered to the same raw descriptor.
    pub fn add_event(&mut self, deadline_ns: u64, descriptor: Event) {
        self.deadlines.retain(|(_, old_descriptor)| {
            descriptor.as_raw_descriptor() != old_descriptor.as_raw_descriptor()
        });
        self.deadlines.push((deadline_ns, descriptor));
    }

    pub fn add_ns(&mut self, ns: u64) {
        self.ns_since_epoch += ns;
        let time = self.ns_since_epoch;
        self.deadlines.retain(|(ns, descriptor)| {
            let expired = *ns <= time;
            if expired {
                descriptor.write(1).unwrap();
            }
            !expired
        });
    }
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::new()
    }
}

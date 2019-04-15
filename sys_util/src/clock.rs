// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Utility file to provide a fake clock object representing current time, and a timerfd driven by
// that time.

use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

use crate::EventFd;

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
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}

const NS_PER_SEC: u64 = 1_000_000_000;
/// A fake clock that can be used in tests to give exact control over the time.
/// For a code example, see the tests in sys_util/src/timerfd.rs.
#[derive(Debug)]
pub struct FakeClock {
    ns_since_epoch: u64,
    deadlines: Vec<(u64, EventFd)>,
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

    /// Register the event fd for a notification when self's time is |deadline_ns|.
    /// Drop any existing events registered to the same raw fd.
    pub fn add_event_fd(&mut self, deadline_ns: u64, fd: EventFd) {
        self.deadlines
            .retain(|(_, old_fd)| fd.as_raw_fd() != old_fd.as_raw_fd());
        self.deadlines.push((deadline_ns, fd));
    }

    pub fn add_ns(&mut self, ns: u64) {
        self.ns_since_epoch += ns;
        let time = self.ns_since_epoch;
        self.deadlines.retain(|(ns, fd)| {
            let expired = *ns <= time;
            if expired {
                fd.write(1).unwrap();
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

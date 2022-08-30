// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Utility file to provide a fake clock object representing current time, and a timer driven by
// that time.

use std::time::Duration;
use std::time::Instant;

use crate::descriptor::AsRawDescriptor;
use crate::Event;

#[derive(Debug, Default, Copy, Clone)]
pub struct Clock {}
impl Clock {
    pub fn new() -> Self {
        Clock {}
    }

    pub fn now(&self) -> Instant {
        Instant::now()
    }
}

/// A fake clock that can be used in tests to give exact control over the time.
/// For a code example, see the tests in base/src/timer.rs.
#[derive(Debug)]
pub struct FakeClock {
    epoch: Instant,
    ns_since_epoch: u64,
    deadlines: Vec<(u64, Event)>,
}

impl FakeClock {
    pub fn new() -> Self {
        FakeClock {
            epoch: Instant::now(),
            ns_since_epoch: 0,
            deadlines: Vec::new(),
        }
    }

    /// Get the current time, according to this clock.
    pub fn now(&self) -> Instant {
        self.epoch + Duration::from_nanos(self.ns_since_epoch)
    }

    ///  Get the current time in ns, according to this clock.
    pub fn nanos(&self) -> u64 {
        self.ns_since_epoch
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
                descriptor.signal().unwrap();
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

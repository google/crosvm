// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::EventFd;
use crate::descriptor::AsRawDescriptor;
use crate::{FakeClock, Result};

use crate::platform::TimerFd;
use std::{sync::Arc, time::Duration};
use sync::Mutex;

pub type Timer = TimerFd;

/// FakeTimer: For use in tests.
pub struct FakeTimer {
    clock: Arc<Mutex<FakeClock>>,
    deadline_ns: Option<u64>,
    interval: Option<Duration>,
    fd: EventFd,
}

impl FakeTimer {
    /// Creates a new fake timerfd.  The timer is initally disarmed and must be armed by calling
    /// `reset`.
    pub fn new(clock: Arc<Mutex<FakeClock>>) -> Self {
        FakeTimer {
            clock,
            deadline_ns: None,
            interval: None,
            fd: EventFd::new().unwrap(),
        }
    }

    fn duration_to_nanos(d: Duration) -> u64 {
        d.as_secs() * 1_000_000_000 + u64::from(d.subsec_nanos())
    }

    /// Sets the timer to expire after `dur`.  If `interval` is not `None` it represents
    /// the period for repeated expirations after the initial expiration.  Otherwise
    /// the timer will expire just once.  Cancels any existing duration and repeating interval.
    pub fn reset(&mut self, dur: Duration, interval: Option<Duration>) -> Result<()> {
        let mut guard = self.clock.lock();
        let deadline = guard.nanos() + FakeTimer::duration_to_nanos(dur);
        self.deadline_ns = Some(deadline);
        self.interval = interval;
        guard.add_event_fd(deadline, self.fd.try_clone()?);
        Ok(())
    }

    /// Waits until the timer expires.  The return value represents the number of times the timer
    /// has expired since the last time `wait` was called.  If the timer has not yet expired once
    /// this call will block until it does.
    pub fn wait(&mut self) -> Result<u64> {
        loop {
            self.fd.read()?;
            if let Some(deadline_ns) = &mut self.deadline_ns {
                let mut guard = self.clock.lock();
                let now = guard.nanos();
                if now >= *deadline_ns {
                    let mut expirys = 0;
                    if let Some(interval) = self.interval {
                        let interval_ns = FakeTimer::duration_to_nanos(interval);
                        if interval_ns > 0 {
                            expirys += (now - *deadline_ns) / interval_ns;
                            *deadline_ns += (expirys + 1) * interval_ns;
                            guard.add_event_fd(*deadline_ns, self.fd.try_clone()?);
                        }
                    }
                    return Ok(expirys + 1);
                }
            }
        }
    }

    /// Disarms the timer.
    pub fn clear(&mut self) -> Result<()> {
        self.deadline_ns = None;
        self.interval = None;
        Ok(())
    }

    /// Returns the resolution of timers on the host.
    pub fn resolution() -> Result<Duration> {
        Ok(Duration::from_nanos(1))
    }

    pub fn try_clone(&self) -> std::result::Result<TimerFd, std::io::Error> {
        unimplemented!()
    }
}

impl AsRawDescriptor for FakeTimer {
    fn as_raw_descriptor(&self) -> crate::RawDescriptor {
        self.fd.as_raw_descriptor()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn fake_one_shot() {
        let clock = Arc::new(Mutex::new(FakeClock::new()));
        let mut tfd = FakeTimer::new(clock.clone());

        let dur = Duration::from_nanos(200);
        tfd.reset(dur, None).expect("failed to arm timer");

        clock.lock().add_ns(200);

        let count = tfd.wait().expect("unable to wait for timer");

        assert_eq!(count, 1);
    }

    #[test]
    fn fake_repeating() {
        let clock = Arc::new(Mutex::new(FakeClock::new()));
        let mut tfd = FakeTimer::new(clock.clone());

        let dur = Duration::from_nanos(200);
        let interval = Duration::from_nanos(100);
        tfd.reset(dur, Some(interval)).expect("failed to arm timer");

        clock.lock().add_ns(300);

        let mut count = tfd.wait().expect("unable to wait for timer");
        // An expiration from the initial expiry and from 1 repeat.
        assert_eq!(count, 2);

        clock.lock().add_ns(300);
        count = tfd.wait().expect("unable to wait for timer");
        assert_eq!(count, 3);
    }
}

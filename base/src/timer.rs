// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use sync::Mutex;

use super::Event;
use super::EventWaitResult;
use super::FakeClock;
use super::RawDescriptor;
use super::Result;
use crate::descriptor::AsRawDescriptor;
use crate::descriptor::FromRawDescriptor;
use crate::descriptor::IntoRawDescriptor;
use crate::descriptor::SafeDescriptor;

/// A trait for timer objects that delivers timer expiration
/// notifications to an underlying descriptor.
pub trait TimerTrait: AsRawDescriptor + IntoRawDescriptor + Send {
    /// Sets the timer to expire after `dur` without repeating. Cancels any existing timer.
    fn reset_oneshot(&mut self, dur: Duration) -> Result<()>;

    /// Sets the timer to fire repeatedly at `dur` intervals. Cancels any existing timer.
    fn reset_repeating(&mut self, dur: Duration) -> Result<()>;

    /// Waits until the timer expires.
    fn wait(&mut self) -> Result<()>;

    /// After a timer is triggered from an EventContext, mark the timer as having been waited for.
    /// If a timer is not marked waited, it will immediately trigger the event context again. This
    /// does not need to be called after calling Timer::wait.
    ///
    /// Returns true if the timer has been adjusted since the EventContext was triggered by this
    /// timer.
    fn mark_waited(&mut self) -> Result<bool>;

    /// Disarms the timer.
    fn clear(&mut self) -> Result<()>;

    /// Returns the resolution of timers on the host.
    fn resolution(&self) -> Result<Duration>;
}

pub struct Timer {
    pub(crate) handle: SafeDescriptor,
    pub(crate) interval: Option<Duration>,
}

impl Timer {
    /// Creates a new `Timer` instance that shares the same underlying `SafeDescriptor` as the
    /// existing `Timer` instance.
    pub fn try_clone(&self) -> std::result::Result<Timer, std::io::Error> {
        self.handle
            .try_clone()
            .map(|handle| Timer {
                handle,
                interval: self.interval,
            })
            .map_err(|err| std::io::Error::from_raw_os_error(err.errno()))
    }
}

// This enum represents those two different retrun values from a "wait" call. Either the
// timer will "expire", meaning it has reached it's duration, or the caller will time out
// waiting for the timer to expire. If no timeout option is provieded to the wait call
// then it can only return WaitResult::Expired or an error.
#[derive(PartialEq, Eq, Debug)]
enum WaitResult {
    Expired,
    Timeout,
}

impl AsRawDescriptor for Timer {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.handle.as_raw_descriptor()
    }
}

impl FromRawDescriptor for Timer {
    unsafe fn from_raw_descriptor(handle: RawDescriptor) -> Self {
        Timer {
            handle: SafeDescriptor::from_raw_descriptor(handle),
            interval: None,
        }
    }
}

impl IntoRawDescriptor for Timer {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self.handle.into_raw_descriptor()
    }
}

/// FakeTimer: For use in tests.
pub struct FakeTimer {
    clock: Arc<Mutex<FakeClock>>,
    deadline_ns: Option<u64>,
    interval: Option<Duration>,
    event: Event,
}

impl FakeTimer {
    /// Creates a new fake Timer.  The timer is initally disarmed and must be armed by calling
    /// `reset`.
    pub fn new(clock: Arc<Mutex<FakeClock>>) -> Self {
        FakeTimer {
            clock,
            deadline_ns: None,
            interval: None,
            event: Event::new().unwrap(),
        }
    }

    fn reset(&mut self, dur: Duration) -> Result<()> {
        let mut guard = self.clock.lock();
        let deadline = guard.nanos() + dur.as_nanos() as u64;
        self.deadline_ns = Some(deadline);
        guard.add_event(deadline, self.event.try_clone()?);
        Ok(())
    }

    /// Waits until the timer expires or an optional wait timeout expires, whichever happens first.
    ///
    /// # Returns
    ///
    /// - `WaitResult::Expired` if the timer expired.
    /// - `WaitResult::Timeout` if `timeout` was not `None` and the timer did not expire within the
    ///   specified timeout period.
    fn wait_for(&mut self, timeout: Option<Duration>) -> Result<WaitResult> {
        let wait_start = Instant::now();
        loop {
            if let Some(timeout) = timeout {
                let elapsed = Instant::now() - wait_start;
                if let Some(remaining) = elapsed.checked_sub(timeout) {
                    if let EventWaitResult::TimedOut = self.event.wait_timeout(remaining)? {
                        return Ok(WaitResult::Timeout);
                    }
                } else {
                    return Ok(WaitResult::Timeout);
                }
            } else {
                self.event.wait()?;
            }

            if let Some(deadline_ns) = &mut self.deadline_ns {
                let mut guard = self.clock.lock();
                let now = guard.nanos();
                if now >= *deadline_ns {
                    let mut expirys = 0;
                    if let Some(interval) = self.interval {
                        let interval_ns = interval.as_nanos() as u64;
                        if interval_ns > 0 {
                            expirys += (now - *deadline_ns) / interval_ns;
                            *deadline_ns += (expirys + 1) * interval_ns;
                            guard.add_event(*deadline_ns, self.event.try_clone()?);
                        }
                    }
                    return Ok(WaitResult::Expired);
                }
            }
        }
    }
}

impl TimerTrait for FakeTimer {
    fn reset_oneshot(&mut self, dur: Duration) -> Result<()> {
        self.interval = None;
        self.reset(dur)
    }

    fn reset_repeating(&mut self, dur: Duration) -> Result<()> {
        self.interval = Some(dur);
        self.reset(dur)
    }

    fn wait(&mut self) -> Result<()> {
        self.wait_for(None).map(|_| ())
    }

    fn mark_waited(&mut self) -> Result<bool> {
        // Just do a self.wait with a timeout of 0. If it times out then the timer has been
        // adjusted.
        if let WaitResult::Timeout = self.wait_for(Some(Duration::from_secs(0)))? {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn clear(&mut self) -> Result<()> {
        self.deadline_ns = None;
        self.interval = None;
        Ok(())
    }

    fn resolution(&self) -> Result<Duration> {
        Ok(Duration::from_nanos(1))
    }
}

impl AsRawDescriptor for FakeTimer {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.event.as_raw_descriptor()
    }
}
impl IntoRawDescriptor for FakeTimer {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self.event.into_raw_descriptor()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::time::Instant;

    use super::*;

    // clock error is 2*clock_resolution + 100 microseconds to handle
    // time change from calling now() to arming timer
    fn get_clock_error() -> Duration {
        Timer::new()
            .unwrap()
            .resolution()
            .expect("expected to be able to read timer resolution")
            .checked_mul(2)
            .expect("timer resolution x 2 should not overflow")
            .checked_add(Duration::from_micros(100))
            .expect("timer resolution x 2 + 100 microsecond should not overflow")
    }

    #[test]
    #[ignore]
    fn one_shot() {
        // This test relies on the host having a reliable clock and not being
        // overloaded, so it's marked as "ignore".  You can run by running
        // cargo test -p base timer -- --ignored

        let mut tfd = Timer::new().expect("failed to create Timer");

        let dur = Duration::from_millis(1000);
        let clock_error = get_clock_error();

        let now = Instant::now();
        tfd.reset_oneshot(dur).expect("failed to arm timer");

        tfd.wait().expect("unable to wait for timer");
        let elapsed = now.elapsed();
        // elapsed is within +-clock_error from expected duration
        assert!(
            elapsed - clock_error <= dur,
            "expected {:?} - {:?} <= {:?}",
            elapsed,
            clock_error,
            dur
        );
        assert!(
            elapsed + clock_error >= dur,
            "expected {:?} + {:?} >= {:?}",
            elapsed,
            clock_error,
            dur
        );
    }

    /// Similar to one_shot, except this one waits for a clone of the timer.
    #[test]
    #[ignore]
    fn one_shot_cloned() {
        let mut tfd = Timer::new().expect("failed to create Timer");
        let dur = Duration::from_millis(1000);
        let mut cloned_tfd = tfd.try_clone().expect("failed to clone timer");

        // clock error is 2*clock_resolution + 100 microseconds to handle
        // time change from calling now() to arming timer
        let clock_error = get_clock_error();

        let now = Instant::now();
        tfd.reset_oneshot(dur).expect("failed to arm timer");
        cloned_tfd.wait().expect("unable to wait for timer");
        let elapsed = now.elapsed();

        // elapsed is within +-clock_error from expected duration
        assert!(
            elapsed - clock_error <= dur,
            "expected {:?} - {:?} <= {:?}",
            elapsed,
            clock_error,
            dur
        );
        assert!(
            elapsed + clock_error >= dur,
            "expected {:?} + {:?} >= {:?}",
            elapsed,
            clock_error,
            dur
        );
    }

    #[test]
    #[ignore]
    fn repeating() {
        // This test relies on the host having a reliable clock and not being
        // overloaded, so it's marked as "ignore".  You can run by running
        // cargo test -p base timer -- --ignored

        let mut tfd = Timer::new().expect("failed to create Timer");

        // clock error is 2*clock_resolution + 100 microseconds to handle
        // time change from calling now() to arming timer
        let clock_error = Timer::new()
            .unwrap()
            .resolution()
            .expect("expected to be able to read timer resolution")
            .checked_mul(2)
            .expect("timer resolution x 2 should not overflow")
            .checked_add(Duration::from_micros(100))
            .expect("timer resolution x 2 + 100 microsecond should not overflow");
        let interval = Duration::from_millis(100);
        let now = Instant::now();
        tfd.reset_repeating(interval).expect("failed to arm timer");

        tfd.wait().expect("unable to wait for timer");
        // should take `interval` duration for the first wait
        assert!(now.elapsed() + clock_error >= interval);
        tfd.wait().expect("unable to wait for timer");
        // subsequent waits should take "interval" duration
        assert!(now.elapsed() + clock_error >= interval * 2);
        tfd.wait().expect("unable to wait for timer");
        assert!(now.elapsed() + clock_error >= interval * 3);
    }

    #[test]
    fn fake_one_shot() {
        let clock = Arc::new(Mutex::new(FakeClock::new()));
        let mut tfd = FakeTimer::new(clock.clone());

        let dur = Duration::from_nanos(200);
        tfd.reset_oneshot(dur).expect("failed to arm timer");

        clock.lock().add_ns(200);

        assert_eq!(tfd.wait().is_ok(), true);
    }

    #[test]
    fn fake_one_shot_timeout() {
        let clock = Arc::new(Mutex::new(FakeClock::new()));
        let mut tfd = FakeTimer::new(clock.clone());

        let dur = Duration::from_nanos(200);
        tfd.reset_oneshot(dur).expect("failed to arm timer");

        clock.lock().add_ns(100);
        let result = tfd
            .wait_for(Some(Duration::from_millis(0)))
            .expect("unable to wait for timer");
        assert_eq!(result, WaitResult::Timeout);
        let result = tfd
            .wait_for(Some(Duration::from_millis(1)))
            .expect("unable to wait for timer");
        assert_eq!(result, WaitResult::Timeout);

        clock.lock().add_ns(100);
        let result = tfd
            .wait_for(Some(Duration::from_millis(0)))
            .expect("unable to wait for timer");
        assert_eq!(result, WaitResult::Expired);
    }

    #[test]
    fn fake_repeating() {
        let clock = Arc::new(Mutex::new(FakeClock::new()));
        let mut tfd = FakeTimer::new(clock.clone());

        let interval = Duration::from_nanos(100);
        tfd.reset_repeating(interval).expect("failed to arm timer");

        clock.lock().add_ns(150);

        // An expiration from the initial expiry and from 1 repeat.
        assert_eq!(tfd.wait().is_ok(), true);

        clock.lock().add_ns(100);
        assert_eq!(tfd.wait().is_ok(), true);
    }
}

// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    os::windows::io::{AsRawHandle, RawHandle},
    ptr,
    time::Duration,
};

use win_util::{LargeInteger, SecurityAttributes, SelfRelativeSecurityDescriptor};
use winapi::{
    shared::{minwindef::FALSE, winerror::WAIT_TIMEOUT},
    um::{
        synchapi::{CancelWaitableTimer, SetWaitableTimer, WaitForSingleObject},
        winbase::{CreateWaitableTimerA, INFINITE, WAIT_OBJECT_0},
    },
};

use super::{
    super::{errno_result, win::nt_query_timer_resolution, Result},
    Timer, WaitResult,
};
use crate::descriptor::{AsRawDescriptor, FromRawDescriptor, SafeDescriptor};

impl AsRawHandle for Timer {
    fn as_raw_handle(&self) -> RawHandle {
        self.handle.as_raw_descriptor()
    }
}

impl Timer {
    /// Creates a new timer.  The timer is initally disarmed and must be armed by calling
    /// `reset`.
    pub fn new() -> Result<Timer> {
        // Safe because this doesn't modify any memory and we check the return value.
        let handle = unsafe {
            CreateWaitableTimerA(
                // Not inheritable, duplicate before passing to child prcesses
                SecurityAttributes::new_with_security_descriptor(
                    SelfRelativeSecurityDescriptor::get_singleton(),
                    /* inherit= */ false,
                )
                .as_mut(),
                // This is a synchronization timer, not a manual-reset timer.
                FALSE,
                // TODO (colindr) b/145622516 - we may have to give this a name if we later
                // want to use names to test object equality
                ptr::null_mut(),
            )
        };

        if handle.is_null() {
            return errno_result();
        }

        // Safe because we uniquely own the file descriptor.
        Ok(Timer {
            handle: unsafe { SafeDescriptor::from_raw_descriptor(handle) },
            interval: None,
        })
    }

    /// Sets the timer to expire after `dur`. If `interval` is not `None` and non-zero
    /// it represents the period for repeated expirations after the initial expiration.
    /// Otherwise the timer will expire just once.  Cancels any existing duration and
    /// repeating interval.
    pub fn reset(&mut self, dur: Duration, mut interval: Option<Duration>) -> Result<()> {
        // If interval is 0 or None it means that this timer does not repeat. We
        // set self.interval to None in this case so it can easily be checked
        // in self.wait.
        if interval == Some(Duration::from_secs(0)) {
            interval = None;
        }
        self.interval = interval;
        // Windows timers use negative values for relative times, and positive
        // values for absolute times, so we'll use negative times.

        // Windows timers also use a 64 number of 100 nanosecond intervals,
        // which we get like so: (dur.as_secs()*1e7 + dur.subsec_nanos()/100)

        let due_time = LargeInteger::new(
            -((dur.as_secs() * 10_000_000 + (dur.subsec_nanos() as u64) / 100) as i64),
        );
        let period: i32 = match interval {
            Some(int) => int.as_millis() as i32,
            None => 0,
        };

        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe {
            SetWaitableTimer(
                self.as_raw_descriptor(),
                &*due_time,
                period,
                None,            // no completion routine
                ptr::null_mut(), // or routine argument
                FALSE,           // no restoring system from power conservation mode
            )
        };
        if ret == 0 {
            return errno_result();
        }

        Ok(())
    }

    /// Waits until the timer expires, returing WaitResult::Expired when it expires.
    ///
    /// If timeout is not None, block for a maximum of the given `timeout` duration.
    /// If a timeout occurs, return WaitResult::Timeout.
    pub fn wait(&mut self, timeout: Option<Duration>) -> Result<WaitResult> {
        let timeout = match timeout {
            None => INFINITE,
            Some(dur) => dur.as_millis() as u32,
        };

        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe { WaitForSingleObject(self.as_raw_descriptor(), timeout) };

        // Should return WAIT_OBJECT_0, otherwise it's some sort of error or
        // timeout (which shouldn't happen in this case).
        match ret {
            WAIT_OBJECT_0 => Ok(WaitResult::Expired),
            WAIT_TIMEOUT => Ok(WaitResult::Timeout),
            _ => errno_result(),
        }
    }

    /// After a timer is triggered from an EventContext, mark the timer as having been waited for.
    /// If a timer is not marked waited, it will immediately trigger the event context again. This
    /// does not need to be called after calling Timer::wait.
    ///
    /// Returns true if the timer has been adjusted since the EventContext was triggered by this
    /// timer.
    pub fn mark_waited(&mut self) -> Result<bool> {
        // We use a synchronization timer on windows, meaning waiting on the timer automatically
        // un-signals the timer. We assume this is atomic so the return value is always false.
        Ok(false)
    }

    /// Disarms the timer.
    pub fn clear(&mut self) -> Result<()> {
        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe { CancelWaitableTimer(self.as_raw_descriptor()) };

        if ret == 0 {
            return errno_result();
        }

        self.interval = None;
        Ok(())
    }

    /// Returns the resolution of timers on the host.
    pub fn resolution() -> Result<Duration> {
        nt_query_timer_resolution().map(|(current_res, _)| current_res)
    }
}

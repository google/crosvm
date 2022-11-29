// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::windows::io::AsRawHandle;
use std::os::windows::io::RawHandle;
use std::ptr;
use std::time::Duration;

use win_util::LargeInteger;
use win_util::SecurityAttributes;
use win_util::SelfRelativeSecurityDescriptor;
use winapi::shared::minwindef::FALSE;
use winapi::um::synchapi::CancelWaitableTimer;
use winapi::um::synchapi::SetWaitableTimer;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::CreateWaitableTimerA;
use winapi::um::winbase::INFINITE;
use winapi::um::winbase::WAIT_OBJECT_0;

use super::errno_result;
use super::win::nt_query_timer_resolution;
use super::Result;
use crate::descriptor::AsRawDescriptor;
use crate::descriptor::FromRawDescriptor;
use crate::descriptor::SafeDescriptor;
use crate::timer::Timer;

impl AsRawHandle for Timer {
    fn as_raw_handle(&self) -> RawHandle {
        self.handle.as_raw_descriptor()
    }
}

impl Timer {
    /// Creates a new timer.  The timer is initally disarmed and must be armed by calling
    /// `reset`. Note that this timer MAY wake/trigger early due to limitations on
    /// SetWaitableTimer (see https://github.com/rust-lang/rust/issues/43376).
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
            Some(int) => {
                if int.is_zero() {
                    // Duration of zero implies non-periodic, which means setting period
                    // to 0ms.
                    0
                } else {
                    // Otherwise, convert to ms and make sure it's >=1ms.
                    std::cmp::max(1, int.as_millis() as i32)
                }
            }
            // Period of 0ms=non-periodic.
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

    /// Waits until the timer expires.
    pub fn wait(&mut self) -> Result<()> {
        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe { WaitForSingleObject(self.as_raw_descriptor(), INFINITE) };

        // Should return WAIT_OBJECT_0, otherwise it's some sort of error or
        // timeout (which shouldn't happen in this case).
        match ret {
            WAIT_OBJECT_0 => Ok(()),
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

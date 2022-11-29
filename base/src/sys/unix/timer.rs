// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::ptr;
use std::time::Duration;

use libc::clock_getres;
use libc::timerfd_create;
use libc::timerfd_settime;
use libc::CLOCK_MONOTONIC;
use libc::EAGAIN;
use libc::POLLIN;
use libc::TFD_CLOEXEC;

use super::super::errno_result;
use super::super::Error;
use super::super::Result;
use super::duration_to_timespec;
use crate::descriptor::AsRawDescriptor;
use crate::descriptor::FromRawDescriptor;
use crate::descriptor::SafeDescriptor;
use crate::timer::Timer;

impl AsRawFd for Timer {
    fn as_raw_fd(&self) -> RawFd {
        self.handle.as_raw_descriptor()
    }
}

impl Timer {
    /// Creates a new timerfd.  The timer is initally disarmed and must be armed by calling
    /// `reset`.
    pub fn new() -> Result<Timer> {
        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe { timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC) };
        if ret < 0 {
            return errno_result();
        }

        // Safe because we uniquely own the file descriptor.
        Ok(Timer {
            handle: unsafe { SafeDescriptor::from_raw_descriptor(ret) },
            interval: None,
        })
    }

    // Calls `timerfd_settime()` and stores the new value of `interval`.
    fn set_time(&mut self, dur: Option<Duration>, interval: Option<Duration>) -> Result<()> {
        // The posix implementation of timer does not need self.interval, but we
        // save it anyways to keep a consistent interface.
        self.interval = interval;

        let spec = libc::itimerspec {
            it_interval: duration_to_timespec(interval.unwrap_or_default()),
            it_value: duration_to_timespec(dur.unwrap_or_default()),
        };

        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe { timerfd_settime(self.as_raw_descriptor(), 0, &spec, ptr::null_mut()) };
        if ret < 0 {
            return errno_result();
        }

        Ok(())
    }

    /// Sets the timer to expire after `dur`.  If `interval` is not `None` and non-zero it
    /// represents the period for repeated expirations after the initial expiration.  Otherwise
    /// the timer will expire just once.  Cancels any existing duration and repeating interval.
    pub fn reset(&mut self, dur: Duration, interval: Option<Duration>) -> Result<()> {
        self.set_time(Some(dur), interval)
    }

    /// Disarms the timer.
    pub fn clear(&mut self) -> Result<()> {
        self.set_time(None, None)
    }

    /// Waits until the timer expires.
    pub fn wait(&mut self) -> Result<()> {
        let mut pfd = libc::pollfd {
            fd: self.as_raw_descriptor(),
            events: POLLIN,
            revents: 0,
        };

        // Safe because this only modifies |pfd| and we check the return value
        let ret = handle_eintr_errno!(unsafe {
            libc::ppoll(
                &mut pfd as *mut libc::pollfd,
                1,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        });

        if ret < 0 {
            return errno_result();
        }

        // EAGAIN is a valid error in the case where another thread has called timerfd_settime
        // in between this thread calling ppoll and read. Since the ppoll returned originally
        // without any revents it means the timer did expire, so we treat this as a
        // WaitResult::Expired.
        let _ = self.mark_waited()?;

        Ok(())
    }

    /// After a timer is triggered from an EventContext, mark the timer as having been waited for.
    /// If a timer is not marked waited, it will immediately trigger the event context again. This
    /// does not need to be called after calling Timer::wait.
    ///
    /// Returns true if the timer has been adjusted since the EventContext was triggered by this
    /// timer.
    pub fn mark_waited(&mut self) -> Result<bool> {
        let mut count = 0u64;

        // The timerfd is in non-blocking mode, so this should return immediately.
        let ret = unsafe {
            libc::read(
                self.as_raw_descriptor(),
                &mut count as *mut _ as *mut libc::c_void,
                mem::size_of_val(&count),
            )
        };

        if ret < 0 {
            if Error::last().errno() == EAGAIN {
                Ok(true)
            } else {
                errno_result()
            }
        } else {
            Ok(false)
        }
    }

    /// Returns the resolution of timers on the host.
    pub fn resolution() -> Result<Duration> {
        // Safe because we are zero-initializing a struct with only primitive member fields.
        let mut res: libc::timespec = unsafe { mem::zeroed() };

        // Safe because it only modifies a local struct and we check the return value.
        let ret = unsafe { clock_getres(CLOCK_MONOTONIC, &mut res) };

        if ret != 0 {
            return errno_result();
        }

        Ok(Duration::new(res.tv_sec as u64, res.tv_nsec as u32))
    }
}

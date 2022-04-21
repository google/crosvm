// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    mem,
    os::unix::io::{AsRawFd, RawFd},
    ptr,
    time::Duration,
};

use libc::{
    clock_getres, timerfd_create, timerfd_settime, CLOCK_MONOTONIC, EAGAIN, POLLIN, TFD_CLOEXEC,
    {self},
};

use super::super::{errno_result, Error, Result};
use crate::descriptor::{AsRawDescriptor, FromRawDescriptor, SafeDescriptor};

use crate::timer::{Timer, WaitResult};

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

    /// Sets the timer to expire after `dur`.  If `interval` is not `None` it represents
    /// the period for repeated expirations after the initial expiration.  Otherwise
    /// the timer will expire just once.  Cancels any existing duration and repeating interval.
    pub fn reset(&mut self, dur: Duration, interval: Option<Duration>) -> Result<()> {
        // Safe because we are zero-initializing a struct with only primitive member fields.
        let mut spec: libc::itimerspec = unsafe { mem::zeroed() };
        spec.it_value.tv_sec = dur.as_secs() as libc::time_t;
        // nsec always fits in i32 because subsec_nanos is defined to be less than one billion.
        let nsec = dur.subsec_nanos() as i32;
        spec.it_value.tv_nsec = libc::c_long::from(nsec);

        // The posix implementation of timer does not need self.interval, but we
        // save it anyways to keep a consistent interface.
        self.interval = interval;

        if let Some(int) = interval {
            spec.it_interval.tv_sec = int.as_secs() as libc::time_t;
            // nsec always fits in i32 because subsec_nanos is defined to be less than one billion.
            let nsec = int.subsec_nanos() as i32;
            spec.it_interval.tv_nsec = libc::c_long::from(nsec);
        }

        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe { timerfd_settime(self.as_raw_descriptor(), 0, &spec, ptr::null_mut()) };
        if ret < 0 {
            return errno_result();
        }

        Ok(())
    }

    /// Waits until the timer expires, returing WaitResult::Expired when it expires.
    ///
    /// If timeout is not None, block for a maximum of the given `timeout` duration.
    /// If a timeout occurs, return WaitResult::Timeout.
    pub fn wait_for(&mut self, timeout: Option<Duration>) -> Result<WaitResult> {
        let mut pfd = libc::pollfd {
            fd: self.as_raw_descriptor(),
            events: POLLIN,
            revents: 0,
        };

        // Safe because we are zero-initializing a struct with only primitive member fields.

        let ret = if let Some(timeout_inner) = timeout {
            let mut timeoutspec: libc::timespec = unsafe { mem::zeroed() };

            timeoutspec.tv_sec = timeout_inner.as_secs() as libc::time_t;
            // nsec always fits in i32 because subsec_nanos is defined to be less than one billion.
            let nsec = timeout_inner.subsec_nanos() as i32;
            timeoutspec.tv_nsec = libc::c_long::from(nsec);
            // Safe because this only modifies |pfd| and we check the return value
            unsafe {
                libc::ppoll(
                    &mut pfd as *mut libc::pollfd,
                    1,
                    &timeoutspec,
                    ptr::null_mut(),
                )
            }
        } else {
            // Safe because this only modifies |pfd| and we check the return value
            unsafe {
                libc::ppoll(
                    &mut pfd as *mut libc::pollfd,
                    1,
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            }
        };

        if ret < 0 {
            return errno_result();
        }

        // no return events (revents) means we got a timeout
        if pfd.revents == 0 {
            return Ok(WaitResult::Timeout);
        }

        let mut count = 0u64;

        // Safe because this will only modify |buf| and we check the return value.
        let ret = unsafe {
            libc::read(
                self.as_raw_descriptor(),
                &mut count as *mut _ as *mut libc::c_void,
                mem::size_of_val(&count),
            )
        };

        // EAGAIN is a valid error in the case where another thread has called timerfd_settime
        // in between this thread calling ppoll and read. Since the ppoll returned originally
        // without any revents it means the timer did expire, so we treat this as a
        // WaitResult::Expired.
        if ret < 0 {
            let error = Error::last();
            if error.errno() != EAGAIN {
                return Err(error);
            }
        }

        Ok(WaitResult::Expired)
    }

    /// Block for a maximum of the given `timeout` duration.
    /// If a timeout occurs, return WaitResult::Timeout.
    pub fn wait(&mut self) -> Result<WaitResult> {
        self.wait_for(None)
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

    /// Disarms the timer.
    pub fn clear(&mut self) -> Result<()> {
        // Safe because we are zero-initializing a struct with only primitive member fields.
        let spec: libc::itimerspec = unsafe { mem::zeroed() };

        // Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe { timerfd_settime(self.as_raw_descriptor(), 0, &spec, ptr::null_mut()) };
        if ret < 0 {
            return errno_result();
        }

        self.interval = None;

        Ok(())
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

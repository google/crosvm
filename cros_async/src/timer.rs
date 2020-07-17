// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::time::Duration;

use sys_util::{Result as SysResult, TimerFd};

use crate::{AsyncResult, Executor, IntoAsync, IoSourceExt};
#[cfg(test)]
use crate::{FdExecutor, URingExecutor};

/// An async version of sys_util::TimerFd.
pub struct TimerAsync {
    io_source: Box<dyn IoSourceExt<TimerFd>>,
}

impl TimerAsync {
    pub fn new(timer: TimerFd, ex: &Executor) -> AsyncResult<TimerAsync> {
        ex.async_from(timer)
            .map(|io_source| TimerAsync { io_source })
    }

    #[cfg(test)]
    pub(crate) fn new_poll(timer: TimerFd, ex: &FdExecutor) -> AsyncResult<TimerAsync> {
        crate::executor::async_poll_from(timer, ex).map(|io_source| TimerAsync { io_source })
    }

    #[cfg(test)]
    pub(crate) fn new_uring(timer: TimerFd, ex: &URingExecutor) -> AsyncResult<TimerAsync> {
        crate::executor::async_uring_from(timer, ex).map(|io_source| TimerAsync { io_source })
    }

    /// Gets the next value from the timer.
    pub async fn next_val(&self) -> AsyncResult<u64> {
        self.io_source.read_u64().await
    }

    /// Sets the timer to expire after `dur`.  If `interval` is not `None` it represents
    /// the period for repeated expirations after the initial expiration.  Otherwise
    /// the timer will expire just once.  Cancels any existing duration and repeating interval.
    pub fn reset(&mut self, dur: Duration, interval: Option<Duration>) -> SysResult<()> {
        self.io_source.as_source_mut().reset(dur, interval)
    }
}

impl IntoAsync for TimerFd {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn one_shot() {
        async fn this_test(ex: &URingExecutor) -> () {
            let tfd = TimerFd::new().expect("failed to create timerfd");
            assert_eq!(tfd.is_armed().unwrap(), false);

            let dur = Duration::from_millis(200);
            let now = Instant::now();
            tfd.reset(dur, None).expect("failed to arm timer");

            assert_eq!(tfd.is_armed().unwrap(), true);

            let t = TimerAsync::new_uring(tfd, ex).unwrap();
            let count = t.next_val().await.expect("unable to wait for timer");

            assert_eq!(count, 1);
            assert!(now.elapsed() >= dur);
        }

        let ex = URingExecutor::new().unwrap();
        ex.run_until(this_test(&ex)).unwrap();
    }

    #[test]
    fn one_shot_fd() {
        async fn this_test(ex: &FdExecutor) -> () {
            let tfd = TimerFd::new().expect("failed to create timerfd");
            assert_eq!(tfd.is_armed().unwrap(), false);

            let dur = Duration::from_millis(200);
            let now = Instant::now();
            tfd.reset(dur, None).expect("failed to arm timer");

            assert_eq!(tfd.is_armed().unwrap(), true);

            let t = TimerAsync::new_poll(tfd, ex).unwrap();
            let count = t.next_val().await.expect("unable to wait for timer");

            assert_eq!(count, 1);
            assert!(now.elapsed() >= dur);
        }

        let ex = FdExecutor::new().unwrap();
        ex.run_until(this_test(&ex)).unwrap();
    }
}

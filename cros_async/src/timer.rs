// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::io_ext::async_from;
use crate::{AsyncError, AsyncResult, IntoAsync, IoSourceExt};
use std::convert::TryFrom;
use sys_util::TimerFd;

/// An async version of sys_util::TimerFd.
pub struct TimerAsync {
    io_source: Box<dyn IoSourceExt<TimerFd>>,
}

impl TimerAsync {
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn new_poll(timer: TimerFd) -> AsyncResult<TimerAsync> {
        Ok(TimerAsync {
            io_source: crate::io_ext::async_poll_from(timer)?,
        })
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn new_uring(timer: TimerFd) -> AsyncResult<TimerAsync> {
        Ok(TimerAsync {
            io_source: crate::io_ext::async_uring_from(timer)?,
        })
    }

    /// Gets the next value from the timer.
    #[allow(dead_code)]
    pub async fn next_val(&self) -> AsyncResult<u64> {
        self.io_source.read_u64().await
    }
}

impl TryFrom<TimerFd> for TimerAsync {
    type Error = AsyncError;

    /// Creates a new TimerAsync wrapper around the provided timer.
    fn try_from(timer: TimerFd) -> AsyncResult<Self> {
        Ok(TimerAsync {
            io_source: async_from(timer)?,
        })
    }
}

impl IntoAsync for TimerFd {}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::pin_mut;
    use std::time::{Duration, Instant};

    #[test]
    fn one_shot() {
        async fn this_test() -> () {
            let tfd = TimerFd::new().expect("failed to create timerfd");
            assert_eq!(tfd.is_armed().unwrap(), false);

            let dur = Duration::from_millis(200);
            let now = Instant::now();
            tfd.reset(dur, None).expect("failed to arm timer");

            assert_eq!(tfd.is_armed().unwrap(), true);

            let t = TimerAsync::try_from(tfd).unwrap();
            let count = t.next_val().await.expect("unable to wait for timer");

            assert_eq!(count, 1);
            assert!(now.elapsed() >= dur);
        }

        let fut = this_test();
        pin_mut!(fut);
        crate::run_executor(crate::RunOne::new(fut)).unwrap();
    }

    #[test]
    fn one_shot_fd() {
        async fn this_test() -> () {
            let tfd = TimerFd::new().expect("failed to create timerfd");
            assert_eq!(tfd.is_armed().unwrap(), false);

            let dur = Duration::from_millis(200);
            let now = Instant::now();
            tfd.reset(dur, None).expect("failed to arm timer");

            assert_eq!(tfd.is_armed().unwrap(), true);

            let t = TimerAsync::new_poll(tfd).unwrap();
            let count = t.next_val().await.expect("unable to wait for timer");

            assert_eq!(count, 1);
            assert!(now.elapsed() >= dur);
        }

        let fut = this_test();
        pin_mut!(fut);
        crate::run_one_poll(fut).unwrap();
    }
}

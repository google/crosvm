// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// For the moment, the only platform specific code is related to tests.
#![cfg(test)]

use super::{FdExecutor, URingExecutor};
use crate::{sys::unix::executor, AsyncResult, TimerAsync};
use base::Timer;

impl TimerAsync {
    pub(crate) fn new_poll(timer: Timer, ex: &FdExecutor) -> AsyncResult<TimerAsync> {
        executor::async_poll_from(timer, ex).map(|io_source| TimerAsync { io_source })
    }

    pub(crate) fn new_uring(timer: Timer, ex: &URingExecutor) -> AsyncResult<TimerAsync> {
        executor::async_uring_from(timer, ex).map(|io_source| TimerAsync { io_source })
    }
}

mod tests {
    use super::*;
    use crate::{sys::unix::uring_executor::use_uring, Executor};
    use std::time::{Duration, Instant};

    #[test]
    fn timer() {
        async fn this_test(ex: &Executor) {
            let dur = Duration::from_millis(200);
            let now = Instant::now();
            TimerAsync::sleep(ex, dur).await.expect("unable to sleep");
            assert!(now.elapsed() >= dur);
        }

        let ex = Executor::new().expect("creating an executor failed");
        ex.run_until(this_test(&ex)).unwrap();
    }

    #[test]
    fn one_shot() {
        if !use_uring() {
            return;
        }

        async fn this_test(ex: &URingExecutor) {
            let mut tfd = Timer::new().expect("failed to create timerfd");

            let dur = Duration::from_millis(200);
            let now = Instant::now();
            tfd.reset(dur, None).expect("failed to arm timer");

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
        async fn this_test(ex: &FdExecutor) {
            let mut tfd = Timer::new().expect("failed to create timerfd");

            let dur = Duration::from_millis(200);
            let now = Instant::now();
            tfd.reset(dur, None).expect("failed to arm timer");

            let t = TimerAsync::new_poll(tfd, ex).unwrap();
            let count = t.next_val().await.expect("unable to wait for timer");

            assert_eq!(count, 1);
            assert!(now.elapsed() >= dur);
        }

        let ex = FdExecutor::new().unwrap();
        ex.run_until(this_test(&ex)).unwrap();
    }
}

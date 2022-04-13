// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::{AsyncResult, Error, Executor, IntoAsync, IoSourceExt};
use base::{Result as SysResult, Timer};
use std::time::Duration;

/// An async version of base::Timer.
pub struct TimerAsync {
    pub(crate) io_source: Box<dyn IoSourceExt<Timer>>,
}

impl TimerAsync {
    pub fn new(timer: Timer, ex: &Executor) -> AsyncResult<TimerAsync> {
        ex.async_from(timer)
            .map(|io_source| TimerAsync { io_source })
    }

    /// Gets the next value from the timer.
    pub async fn next_val(&self) -> AsyncResult<u64> {
        self.io_source.wait_for_handle().await
    }

    /// Async sleep for the given duration
    pub async fn sleep(ex: &Executor, dur: Duration) -> std::result::Result<(), Error> {
        let mut tfd = Timer::new().map_err(Error::Timer)?;
        tfd.reset(dur, None).map_err(Error::Timer)?;
        let t = TimerAsync::new(tfd, ex).map_err(Error::TimerAsync)?;
        t.next_val().await.map_err(Error::TimerAsync)?;
        Ok(())
    }

    /// Sets the timer to expire after `dur`.  If `interval` is not `None` it represents
    /// the period for repeated expirations after the initial expiration.  Otherwise
    /// the timer will expire just once.  Cancels any existing duration and repeating interval.
    pub fn reset(&mut self, dur: Duration, interval: Option<Duration>) -> SysResult<()> {
        self.io_source.as_source_mut().reset(dur, interval)
    }
}

impl IntoAsync for Timer {}

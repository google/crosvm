// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::time::Duration;

use base::Result as SysResult;
use base::Timer;

use crate::AsyncResult;
use crate::Error;
use crate::Executor;
use crate::IntoAsync;
use crate::IoSourceExt;

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
    ///
    /// NOTE: on Windows, this may return/wake early. See `base::Timer` docs
    /// for details.
    pub async fn next_val(&self) -> AsyncResult<u64> {
        self.io_source.wait_for_handle().await
    }

    /// Async sleep for the given duration.
    ///
    /// NOTE: on Windows, this sleep may wake early. See `base::Timer` docs
    /// for details.
    pub async fn sleep(ex: &Executor, dur: Duration) -> std::result::Result<(), Error> {
        let mut tfd = Timer::new().map_err(Error::Timer)?;
        tfd.reset(dur, None).map_err(Error::Timer)?;
        let t = TimerAsync::new(tfd, ex).map_err(Error::TimerAsync)?;
        t.next_val().await.map_err(Error::TimerAsync)?;
        Ok(())
    }

    /// Sets the timer to expire after `dur`.  If `interval` is not `None` and non-zero it
    /// represents the period for repeated expirations after the initial expiration.  Otherwise
    /// the timer will expire just once.  Cancels any existing duration and repeating interval.
    pub fn reset(&mut self, dur: Duration, interval: Option<Duration>) -> SysResult<()> {
        self.io_source.as_source_mut().reset(dur, interval)
    }
}

impl IntoAsync for Timer {}

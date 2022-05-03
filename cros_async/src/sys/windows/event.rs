// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::{AsyncError, AsyncResult, EventAsync, Executor};
use base::{Event, EventExt};

impl EventAsync {
    pub fn new(event: Event, ex: &Executor) -> AsyncResult<EventAsync> {
        ex.async_from(event).map(|io_source| EventAsync {
            io_source,
            reset_after_read: true,
        })
    }

    /// For Windows events, especially those used in overlapped IO, we don't want to reset them
    /// after "reading" from them because the signaling state is entirely managed by the kernel.
    pub fn new_without_reset(event: Event, ex: &Executor) -> AsyncResult<EventAsync> {
        ex.async_from(event).map(|io_source| EventAsync {
            io_source,
            reset_after_read: false,
        })
    }

    /// Gets the next value from the eventfd.
    pub async fn next_val(&self) -> AsyncResult<u64> {
        let res = self.io_source.wait_for_handle().await;

        if self.reset_after_read {
            self.io_source
                .as_source()
                .reset()
                .map_err(AsyncError::EventAsync)?;
        }
        res
    }
}

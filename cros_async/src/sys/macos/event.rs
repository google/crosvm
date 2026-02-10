// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::Event;

use crate::AsyncError;
use crate::AsyncResult;
use crate::EventAsync;
use crate::Executor;

impl EventAsync {
    pub fn new(event: Event, ex: &Executor) -> AsyncResult<EventAsync> {
        ex.async_from(event)
            .map(|io_source| EventAsync { io_source })
    }

    /// Gets the next value from the eventfd.
    pub async fn next_val(&self) -> AsyncResult<u64> {
        let (n, v) = self
            .io_source
            .read_to_vec(None, 0u64.to_ne_bytes().to_vec())
            .await?;
        if n != 8 {
            return Err(AsyncError::EventAsync(base::Error::new(libc::ENODATA)));
        }
        Ok(u64::from_ne_bytes(v.try_into().unwrap()))
    }
}

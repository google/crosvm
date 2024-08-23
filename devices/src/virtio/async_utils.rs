// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Virtio device async helper functions.

use anyhow::Context;
use anyhow::Result;
use base::Event;
use cros_async::EventAsync;
use cros_async::Executor;

/// Async task that waits for a signal from `event`.  Once this event is readable, exit. Exiting
/// this future will cause the main loop to break and the worker thread to exit.
pub async fn await_and_exit(ex: &Executor, event: Event) -> Result<()> {
    let event_async = EventAsync::new(event, ex).context("failed to create EventAsync")?;
    let _ = event_async.next_val().await;
    Ok(())
}

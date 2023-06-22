// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Virtio device async helper functions.

use anyhow::Context;
use anyhow::Result;
use base::Event;
use cros_async::EventAsync;
use cros_async::Executor;

use super::Interrupt;

/// Async task that waits for a signal from `event`.  Once this event is readable, exit. Exiting
/// this future will cause the main loop to break and the worker thread to exit.
pub async fn await_and_exit(ex: &Executor, event: Event) -> Result<()> {
    let event_async = EventAsync::new(event, ex).context("failed to create EventAsync")?;
    let _ = event_async.next_val().await;
    Ok(())
}

/// Async task that resamples the status of the interrupt when the guest sends a request by
/// signalling the resample event associated with the interrupt.
pub async fn handle_irq_resample(ex: &Executor, interrupt: Interrupt) -> Result<()> {
    // Clone resample_evt if interrupt has one.
    if let Some(resample_evt) = interrupt.get_resample_evt() {
        let resample_evt = resample_evt
            .try_clone()
            .context("resample_evt.try_clone() failed")?;
        let resample_evt =
            EventAsync::new(resample_evt, ex).context("failed to create async resample event")?;
        loop {
            let _ = resample_evt
                .next_val()
                .await
                .context("failed to read resample event")?;
            interrupt.do_interrupt_resample();
        }
    } else {
        // No resample event; park the future.
        std::future::pending::<()>().await;
        Ok(())
    }
}

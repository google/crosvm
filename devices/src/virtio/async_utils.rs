// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Virtio device async helper functions.

use std::cell::RefCell;
use std::rc::Rc;

use anyhow::{Context, Result};
use base::Event;
use cros_async::{EventAsync, Executor};

use super::{Interrupt, SignalableInterrupt};

/// Async task that waits for a signal from `event`.  Once this event is readable, exit. Exiting
/// this future will cause the main loop to break and the worker thread to exit.
pub async fn await_and_exit(ex: &Executor, event: Event) -> Result<()> {
    let event_async = EventAsync::new(event.0, ex).context("failed to create EventAsync")?;
    let _ = event_async.next_val().await;
    Ok(())
}

/// Async task that resamples the status of the interrupt when the guest sends a request by
/// signalling the resample event associated with the interrupt.
pub async fn handle_irq_resample(ex: &Executor, interrupt: Rc<RefCell<Interrupt>>) -> Result<()> {
    // Clone resample_evt if interrupt has one.
    // This is a separate block so that we do not hold a RefCell borrow across await.
    let resample_evt = if let Some(resample_evt) = interrupt.borrow().get_resample_evt() {
        let resample_evt = resample_evt
            .try_clone()
            .context("resample_evt.try_clone() failed")?;
        Some(EventAsync::new(resample_evt.0, ex).context("failed to create async resample event")?)
    } else {
        None
    };

    if let Some(resample_evt) = resample_evt {
        loop {
            let _ = resample_evt
                .next_val()
                .await
                .context("failed to read resample event")?;
            interrupt.borrow().do_interrupt_resample();
        }
    } else {
        // No resample event; park the future.
        let () = futures::future::pending().await;
    }
    Ok(())
}

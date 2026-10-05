// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Interrupt coalescing for batches of asynchronous request completions.

use std::cell::Cell;

use futures::future::OptionFuture;
use futures::future::Ready;

/// Holds the current state of deferred interrupts for a batch of requests.
#[derive(Clone, Copy, PartialEq)]
enum BatchSignalState {
    /// No requests have completed in this batch.
    Idle,
    /// One request has completed and it called `trigger_interrupt`.
    Notified,
    /// Requests have completed without calling `trigger_interrupt`.
    Pending,
}

/// Signals the first completion immediately and defers subsequent interrupts until the batch ends.
pub(super) struct InterruptCoalescer {
    batch_state: Cell<BatchSignalState>,
}

impl InterruptCoalescer {
    /// Creates an idle `InterruptCoalescer`.
    pub(super) fn new() -> Self {
        Self {
            batch_state: Cell::new(BatchSignalState::Idle),
        }
    }

    /// Calls `signal` immediately for the first completion, deferring the rest until `complete`.
    pub(super) fn trigger_interrupt(&self, signal: impl FnOnce()) {
        if self.batch_state.get() == BatchSignalState::Idle {
            signal();
            self.batch_state.set(BatchSignalState::Notified);
        } else {
            self.batch_state.set(BatchSignalState::Pending);
        }
    }

    /// Calls `signal` if any interrupts are pending due to interrupt coalescing.
    pub(super) fn complete(&self, signal: impl FnOnce()) {
        if self.batch_state.replace(BatchSignalState::Idle) == BatchSignalState::Pending {
            signal();
        }
    }

    /// Returns ready whenever a batch is active (Notified or Pending) so the event loop can flush
    /// and reset the coalescer.
    pub(super) fn active(&self) -> OptionFuture<Ready<()>> {
        (self.batch_state.get() != BatchSignalState::Idle)
            .then(|| futures::future::ready(()))
            .into()
    }
}

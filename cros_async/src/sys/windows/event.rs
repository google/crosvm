// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem::ManuallyDrop;

use base::AsRawDescriptor;
use base::Event;
use base::FromRawDescriptor;

use crate::AsyncError;
use crate::AsyncResult;
use crate::EventAsync;
use crate::Executor;

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

    /// Given a non-owning raw descriptor to an Event, will make a clone to construct this async
    /// Event. Use for cases where you have a valid raw event descriptor, but don't own it.
    pub fn clone_raw_without_reset(
        descriptor: &dyn AsRawDescriptor,
        ex: &Executor,
    ) -> AsyncResult<EventAsync> {
        // Safe because:
        // a) the underlying Event should be validated by the caller.
        // b) we do NOT take ownership of the underlying Event. If we did that would cause an early
        //    free (and later a double free @ the end of this scope). This is why we have to wrap
        //    it in ManuallyDrop.
        // c) we own the clone that is produced exclusively, so it is safe to take ownership of it.
        Self::new_without_reset(
            unsafe {
                ManuallyDrop::new(Event::from_raw_descriptor(descriptor.as_raw_descriptor()))
            }
            .try_clone()
            .map_err(AsyncError::EventAsync)?,
            ex,
        )
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

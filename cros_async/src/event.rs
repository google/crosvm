// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem::ManuallyDrop;

use base::AsRawDescriptor;
use base::Event;
use base::FromRawDescriptor;

use crate::AsyncError;
use crate::AsyncResult;
use crate::Executor;
use crate::IntoAsync;
use crate::IoSourceExt;

/// An async version of `base::Event`.
pub struct EventAsync {
    pub(crate) io_source: Box<dyn IoSourceExt<Event>>,
    #[cfg(windows)]
    pub(crate) reset_after_read: bool,
}

impl EventAsync {
    pub fn get_io_source_ref(&self) -> &dyn IoSourceExt<Event> {
        self.io_source.as_ref()
    }

    /// Given a non-owning raw descriptor to an Event, will make a clone to construct this async
    /// Event. Use for cases where you have a valid raw event descriptor, but don't own it.
    pub fn clone_raw(descriptor: &dyn AsRawDescriptor, ex: &Executor) -> AsyncResult<EventAsync> {
        // Safe because:
        // a) the underlying Event should be validated by the caller.
        // b) we do NOT take ownership of the underlying Event. If we did that would cause an early
        //    free (and later a double free @ the end of this scope). This is why we have to wrap
        //    it in ManuallyDrop.
        // c) we own the clone that is produced exclusively, so it is safe to take ownership of it.
        Self::new(
            unsafe {
                ManuallyDrop::new(Event::from_raw_descriptor(descriptor.as_raw_descriptor()))
            }
            .try_clone()
            .map_err(AsyncError::EventAsync)?,
            ex,
        )
    }
}

impl IntoAsync for Event {}

// Safe because an `Event` is used underneath, which is safe to pass between threads.
unsafe impl Send for EventAsync {}

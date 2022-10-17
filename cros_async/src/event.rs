// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::Event;

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
}

impl IntoAsync for Event {}

// Safe because an `Event` is used underneath, which is safe to pass between threads.
unsafe impl Send for EventAsync {}

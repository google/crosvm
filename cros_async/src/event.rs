// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::Event;

use crate::IntoAsync;
use crate::IoSource;

/// An async version of `base::Event`.
pub struct EventAsync {
    pub(crate) io_source: IoSource<Event>,
    #[cfg(windows)]
    pub(crate) reset_after_read: bool,
}

impl EventAsync {
    pub fn get_io_source_ref(&self) -> &IoSource<Event> {
        &self.io_source
    }
}

impl IntoAsync for Event {}

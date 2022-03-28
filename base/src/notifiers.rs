// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use crate::descriptor::AsRawDescriptor;

pub trait ReadNotifier {
    /// Gets a descriptor that can be used in EventContext to wait for events to be available (e.g.
    /// to avoid receive_events blocking).
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor;
}

pub trait CloseNotifier {
    /// Gets a descriptor that can be used in EventContext to wait for the closed event.
    fn get_close_notifier(&self) -> &dyn AsRawDescriptor;
}

#[cfg(unix)]
impl ReadNotifier for UnixStream {
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
        self
    }
}

#[cfg(unix)]
impl CloseNotifier for UnixStream {
    fn get_close_notifier(&self) -> &dyn AsRawDescriptor {
        self
    }
}

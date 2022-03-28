// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    mem,
    ops::Deref,
    os::unix::io::{AsRawFd, FromRawFd, IntoRawFd},
    ptr,
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::descriptor::{AsRawDescriptor, FromRawDescriptor, IntoRawDescriptor};
pub use crate::platform::EventReadResult;
use crate::{generate_scoped_event, platform::EventFd, RawDescriptor, Result};

/// See [EventFd](crate::platform::EventFd) for struct- and method-level
/// documentation.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Event(pub EventFd);
impl Event {
    pub fn new() -> Result<Event> {
        EventFd::new().map(Event)
    }

    pub fn write(&self, v: u64) -> Result<()> {
        self.0.write(v)
    }

    pub fn read(&self) -> Result<u64> {
        self.0.read()
    }

    pub fn read_timeout(&self, timeout: Duration) -> Result<EventReadResult> {
        self.0.read_timeout(timeout)
    }

    pub fn try_clone(&self) -> Result<Event> {
        self.0.try_clone().map(Event)
    }
}

impl AsRawDescriptor for Event {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.0.as_raw_fd()
    }
}

impl FromRawDescriptor for Event {
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
        Event(EventFd::from_raw_fd(descriptor))
    }
}

impl IntoRawDescriptor for Event {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self.0.into_raw_fd()
    }
}

generate_scoped_event!(Event);

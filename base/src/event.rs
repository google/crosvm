// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::time::Duration;

use serde::Deserialize;
use serde::Serialize;

use crate::descriptor::AsRawDescriptor;
use crate::descriptor::FromRawDescriptor;
use crate::descriptor::IntoRawDescriptor;
use crate::descriptor::SafeDescriptor;
use crate::platform::Event as PlatformEvent;
use crate::RawDescriptor;
use crate::Result;

/// Result of reading an Event with a timeout.
#[derive(Debug, PartialEq, Eq)]
pub enum EventReadResult {
    /// Number of times the event has been written to. Always non-negative.
    Count(u64),
    /// Timed out before witnessing a write.
    Timeout,
}

/// See the [platform-specific Event struct](crate::platform::Event) for struct- and method-level
/// documentation.
// TODO(b:231344063) Move/update documentation.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Event(pub(crate) PlatformEvent);
impl Event {
    pub fn new() -> Result<Event> {
        PlatformEvent::new().map(Event)
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
        self.0.as_raw_descriptor()
    }
}

impl FromRawDescriptor for Event {
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
        Event(PlatformEvent::from_raw_descriptor(descriptor))
    }
}

impl IntoRawDescriptor for Event {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self.0.into_raw_descriptor()
    }
}

impl From<Event> for SafeDescriptor {
    fn from(evt: Event) -> Self {
        Self::from(evt.0)
    }
}

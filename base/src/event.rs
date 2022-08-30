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
use crate::platform::PlatformEvent;
use crate::RawDescriptor;
use crate::Result;

/// An inter-process event wait/notify mechanism. Loosely speaking: Writes signal the event. Reads
/// block until the event is signaled and then clear the signal.
///
/// Supports multiple simultaneous writers (i.e. signalers) but only one simultaneous reader (i.e.
/// waiter). The behavior of multiple readers is undefined in cross platform code.
///
/// Multiple `Event`s can be polled at once via `WaitContext`.
///
/// Implementation notes:
/// - Uses eventfd on Linux.
/// - Uses synchapi event objects on Windows.
/// - The `Event` and `WaitContext` APIs together cannot easily be implemented with the same
///   semantics on all platforms. In particular, it is difficult to support multiple readers, so only
///   a single reader is allowed for now. Multiple readers will result in undefined behavior.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Event(pub(crate) PlatformEvent);

#[derive(PartialEq, Eq, Debug)]
pub enum EventWaitResult {
    /// The `Event` was signaled.
    Signaled,
    /// Timeout limit reached.
    TimedOut,
}

impl Event {
    /// Creates new event in an unsignaled state.
    pub fn new() -> Result<Event> {
        PlatformEvent::new().map(Event)
    }

    /// Signals the event.
    pub fn signal(&self) -> Result<()> {
        self.0.signal()
    }

    /// Blocks until the event is signaled and clears the signal.
    ///
    /// It is undefined behavior to wait on an event from multiple threads or processes
    /// simultaneously.
    pub fn wait(&self) -> Result<()> {
        self.0.wait()
    }

    /// Blocks until the event is signaled and clears the signal, or until the timeout duration
    /// expires.
    ///
    /// It is undefined behavior to wait on an event from multiple threads or processes
    /// simultaneously.
    pub fn wait_timeout(&self, timeout: Duration) -> Result<EventWaitResult> {
        self.0.wait_timeout(timeout)
    }

    /// Clones the event. The event's state is shared between cloned instances.
    ///
    /// The documented caveats for `Event` also apply to a set of cloned instances, e.g., it is
    /// undefined behavior to clone an event and then call `Event::wait` simultaneously on both
    /// objects.
    ///
    /// Implementation notes:
    ///   * Linux: The cloned instance uses a separate file descriptor.
    ///   * Windows: The cloned instance uses a separate handle.
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

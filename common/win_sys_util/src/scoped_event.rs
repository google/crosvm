// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem;
use std::ops::Deref;
use std::ptr;

use crate::{Event, Result};

/// An `Event` wrapper which triggers when it goes out of scope.
///
/// If the underlying `Event` fails to trigger during drop, a panic is triggered instead.
pub struct ScopedEvent(Event);

impl ScopedEvent {
    /// Creates a new `ScopedEvent` which triggers when it goes out of scope.
    pub fn new() -> Result<ScopedEvent> {
        Ok(Event::new()?.into())
    }
}

impl From<Event> for ScopedEvent {
    fn from(e: Event) -> Self {
        Self(e)
    }
}

impl From<ScopedEvent> for Event {
    fn from(scoped_event: ScopedEvent) -> Self {
        // Rust doesn't allow moving out of types with a Drop implementation, so we have to use
        // something that copies instead of moves. This is safe because we prevent the drop of
        // `scoped_event` using `mem::forget`, so the underlying `Event` will not experience a
        // double-drop.
        let evt = unsafe { ptr::read(&scoped_event.0) };
        mem::forget(scoped_event);
        evt
    }
}

impl Deref for ScopedEvent {
    type Target = Event;

    fn deref(&self) -> &Event {
        &self.0
    }
}

impl Drop for ScopedEvent {
    fn drop(&mut self) {
        self.write(1).expect("failed to trigger scoped event");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_event() {
        let scoped_evt = ScopedEvent::new().unwrap();
        let evt_clone: Event = scoped_evt.try_clone().unwrap();
        drop(scoped_evt);
        assert_eq!(evt_clone.read(), Ok(1));
    }

    #[test]
    fn eventfd_from_scoped_event() {
        let scoped_evt = ScopedEvent::new().unwrap();
        let evt: Event = scoped_evt.into();
        evt.write(1).unwrap();
    }
}

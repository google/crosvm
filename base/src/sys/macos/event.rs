// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::time::Duration;

use crate::errno::Result;
use crate::event::EventWaitResult;
use crate::sys::macos::kqueue::make_kevent;
use crate::sys::macos::kqueue::Kqueue;
use crate::sys::unix::RawDescriptor;
use crate::SafeDescriptor;

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PlatformEvent {
    queue: Kqueue,
}

impl PlatformEvent {
    pub fn new() -> Result<PlatformEvent> {
        let event = PlatformEvent {
            queue: Kqueue::new()?,
        };
        let reg = make_kevent(
            libc::EVFILT_USER,
            libc::EV_ADD | libc::EV_CLEAR,
            libc::NOTE_FFNOP,
        );
        event.queue.kevent(&[reg], &mut [], None)?;
        Ok(event)
    }

    pub fn signal(&self) -> Result<()> {
        let event = make_kevent(libc::EVFILT_USER, 0, libc::NOTE_TRIGGER);
        self.queue.kevent(&[event], &mut [], None)?;
        Ok(())
    }

    pub fn wait(&self) -> Result<()> {
        let mut event = [make_kevent(0, 0, 0)];
        self.queue.kevent(&[], &mut event[..], None)?;
        Ok(())
    }

    pub fn wait_timeout(&self, timeout: Duration) -> Result<EventWaitResult> {
        let mut event = [make_kevent(0, 0, 0)];
        if self.queue.kevent(&[], &mut event[..], Some(timeout))?.len() == 0 {
            Ok(EventWaitResult::TimedOut)
        } else {
            Ok(EventWaitResult::Signaled)
        }
    }

    pub fn reset(&self) -> Result<()> {
        self.wait_timeout(Duration::ZERO)?;
        Ok(())
    }

    pub fn try_clone(&self) -> Result<PlatformEvent> {
        self.queue.try_clone().map(|queue| PlatformEvent { queue })
    }
}

impl crate::AsRawDescriptor for PlatformEvent {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.queue.as_raw_descriptor()
    }
}

impl crate::FromRawDescriptor for PlatformEvent {
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
        PlatformEvent {
            queue: Kqueue::from_raw_descriptor(descriptor),
        }
    }
}

impl crate::IntoRawDescriptor for PlatformEvent {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self.queue.into_raw_descriptor()
    }
}

impl From<PlatformEvent> for SafeDescriptor {
    fn from(evt: PlatformEvent) -> Self {
        SafeDescriptor::from(evt.queue)
    }
}

impl From<SafeDescriptor> for PlatformEvent {
    fn from(queue: SafeDescriptor) -> Self {
        PlatformEvent {
            queue: Kqueue::from(queue),
        }
    }
}

// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ptr;
use std::time::Duration;

use crate::descriptor::AsRawDescriptor;
use crate::descriptor::FromRawDescriptor;
use crate::errno::errno_result;
use crate::errno::Result;
use crate::event::EventWaitResult;
use crate::sys::unix::RawDescriptor;
use crate::unix::duration_to_timespec;
use crate::SafeDescriptor;

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PlatformEvent {
    // TODO(schuffelen): Implement a more complete kqueue abstraction?
    queue: SafeDescriptor,
}

// Only accepts the subset of parameters we actually use
fn make_kevent(filter: i16, flags: u16, fflags: u32) -> libc::kevent {
    libc::kevent {
        ident: 0, /* hopefully not global? */
        filter,
        flags,
        fflags,
        data: 0,
        udata: ptr::null_mut(),
    }
}

impl PlatformEvent {
    pub fn new() -> Result<PlatformEvent> {
        // SAFETY: Trivially safe
        let raw_queue = unsafe { libc::kqueue() };
        if raw_queue < 0 {
            return crate::errno::errno_result();
        }
        // SAFETY: Tested whether it was a valid file descriptor
        let queue = unsafe { SafeDescriptor::from_raw_descriptor(raw_queue) };
        let event = PlatformEvent { queue };
        let reg = make_kevent(
            libc::EVFILT_USER,
            libc::EV_ADD | libc::EV_CLEAR,
            libc::NOTE_FFNOP,
        );
        event.kevent(&[reg], &mut [], None)?;
        Ok(event)
    }

    fn kevent(
        &self,
        changelist: &[libc::kevent],
        eventlist: &mut [libc::kevent],
        timeout: Option<Duration>,
    ) -> Result<libc::c_int> {
        let timespec = timeout.map(duration_to_timespec);
        // SAFETY: `queue` is a valid kqueue, `changelist` and `eventlist` are supplied with lengths
        // based on valid slices
        let res = unsafe {
            libc::kevent(
                self.queue.as_raw_descriptor(),
                changelist.as_ptr(),
                changelist.len() as i32,
                eventlist.as_mut_ptr(),
                eventlist.len() as i32,
                if let Some(timeout) = timespec {
                    &timeout
                } else {
                    ptr::null()
                },
            )
        };
        if res < 0 {
            errno_result()
        } else {
            Ok(res)
        }
    }

    pub fn signal(&self) -> Result<()> {
        let event = make_kevent(libc::EVFILT_USER, 0, libc::NOTE_TRIGGER);
        self.kevent(&[event], &mut [], None)?;
        Ok(())
    }

    pub fn wait(&self) -> Result<()> {
        let mut event = [make_kevent(0, 0, 0)];
        self.kevent(&[], &mut event[..], None)?;
        Ok(())
    }

    pub fn wait_timeout(&self, timeout: Duration) -> Result<EventWaitResult> {
        let mut event = [make_kevent(0, 0, 0)];
        if self.kevent(&[], &mut event[..], Some(timeout))? == 0 {
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
            queue: SafeDescriptor::from_raw_descriptor(descriptor),
        }
    }
}

impl crate::IntoRawDescriptor for PlatformEvent {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self.queue.into_raw_descriptor()
    }
}

impl From<PlatformEvent> for crate::SafeDescriptor {
    fn from(evt: PlatformEvent) -> Self {
        evt.queue
    }
}

impl From<SafeDescriptor> for PlatformEvent {
    fn from(queue: SafeDescriptor) -> Self {
        PlatformEvent { queue }
    }
}

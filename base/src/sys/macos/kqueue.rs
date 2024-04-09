// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ptr;
use std::time::Duration;

use crate::descriptor::AsRawDescriptor;
use crate::descriptor::FromRawDescriptor;
use crate::errno::errno_result;
use crate::errno::Error;
use crate::errno::Result;
use crate::sys::unix::RawDescriptor;
use crate::unix::duration_to_timespec;
use crate::unix::set_descriptor_cloexec;
use crate::SafeDescriptor;

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(in crate::sys::macos) struct Kqueue {
    queue: SafeDescriptor,
}

// Only accepts the subset of parameters we actually use
pub(in crate::sys::macos) fn make_kevent(filter: i16, flags: u16, fflags: u32) -> libc::kevent64_s {
    libc::kevent64_s {
        ident: 0, /* hopefully not global? */
        filter,
        flags,
        fflags,
        data: 0,
        udata: 0,
        ext: [0, 0],
    }
}

impl Kqueue {
    pub(in crate::sys::macos) fn new() -> Result<Kqueue> {
        // SAFETY: Trivially safe
        let raw_queue = unsafe { libc::kqueue() };
        if raw_queue < 0 {
            return crate::errno::errno_result();
        }
        // SAFETY: Tested whether it was a valid file descriptor
        let queue = unsafe { SafeDescriptor::from_raw_descriptor(raw_queue) };
        set_descriptor_cloexec(&queue)?;
        Ok(Kqueue { queue })
    }

    pub(in crate::sys::macos) fn kevent<'a>(
        &self,
        changelist: &[libc::kevent64_s],
        eventlist: &'a mut [libc::kevent64_s],
        timeout: Option<Duration>,
    ) -> Result<&'a mut [libc::kevent64_s]> {
        let timespec = timeout.map(duration_to_timespec);
        // SAFETY: `queue` is a valid kqueue, `changelist` and `eventlist` are supplied with lengths
        // based on valid slices
        let res = unsafe {
            libc::kevent64(
                self.queue.as_raw_descriptor(),
                changelist.as_ptr(),
                changelist.len() as i32,
                eventlist.as_mut_ptr(),
                eventlist.len() as i32,
                0,
                if let Some(timeout) = timespec {
                    &timeout
                } else {
                    ptr::null()
                },
            )
        };
        if res < 0 {
            return errno_result();
        }
        let returned_events = eventlist.split_at_mut(res as usize).0;
        for event in returned_events.iter() {
            if event.flags & libc::EV_ERROR != 0 {
                return Err(Error::new(event.data));
            }
        }
        Ok(returned_events)
    }

    pub(in crate::sys::macos) fn try_clone(&self) -> Result<Kqueue> {
        self.queue.try_clone().map(|queue| Kqueue { queue })
    }
}

impl crate::AsRawDescriptor for Kqueue {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.queue.as_raw_descriptor()
    }
}

impl crate::FromRawDescriptor for Kqueue {
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
        Kqueue {
            queue: SafeDescriptor::from_raw_descriptor(descriptor),
        }
    }
}

impl crate::IntoRawDescriptor for Kqueue {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self.queue.into_raw_descriptor()
    }
}

impl From<Kqueue> for crate::SafeDescriptor {
    fn from(queue: Kqueue) -> Self {
        queue.queue
    }
}

impl From<SafeDescriptor> for Kqueue {
    fn from(queue: SafeDescriptor) -> Self {
        Kqueue { queue }
    }
}

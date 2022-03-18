// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    mem,
    ops::Deref,
    os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
    ptr,
    time::Duration,
};

use libc::{c_void, eventfd, read, write, POLLIN};
use serde::{Deserialize, Serialize};

use super::{
    duration_to_timespec, errno_result, generate_scoped_event, AsRawDescriptor, FromRawDescriptor,
    IntoRawDescriptor, RawDescriptor, Result, SafeDescriptor,
};

/// A safe wrapper around a Linux eventfd (man 2 eventfd).
///
/// An eventfd is useful because it is sendable across processes and can be used for signaling in
/// and out of the KVM API. They can also be polled like any other file descriptor.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventFd {
    event_handle: SafeDescriptor,
}

/// Wrapper around the return value of doing a read on an EventFd which distinguishes between
/// getting a valid count of the number of times the eventfd has been written to and timing out
/// waiting for the count to be non-zero.
#[derive(Debug, PartialEq, Eq)]
pub enum EventReadResult {
    Count(u64),
    Timeout,
}

impl EventFd {
    /// Creates a new blocking EventFd with an initial value of 0.
    pub fn new() -> Result<EventFd> {
        // This is safe because eventfd merely allocated an eventfd for our process and we handle
        // the error case.
        let ret = unsafe { eventfd(0, 0) };
        if ret < 0 {
            return errno_result();
        }
        // This is safe because we checked ret for success and know the kernel gave us an fd that we
        // own.
        Ok(EventFd {
            event_handle: unsafe { SafeDescriptor::from_raw_descriptor(ret) },
        })
    }

    /// Adds `v` to the eventfd's count, blocking until this won't overflow the count.
    pub fn write(&self, v: u64) -> Result<()> {
        // This is safe because we made this fd and the pointer we pass can not overflow because we
        // give the syscall's size parameter properly.
        let ret = unsafe {
            write(
                self.as_raw_fd(),
                &v as *const u64 as *const c_void,
                mem::size_of::<u64>(),
            )
        };
        if ret <= 0 {
            return errno_result();
        }
        Ok(())
    }

    /// Blocks until the the eventfd's count is non-zero, then resets the count to zero.
    pub fn read(&self) -> Result<u64> {
        let mut buf: u64 = 0;
        let ret = unsafe {
            // This is safe because we made this fd and the pointer we pass can not overflow because
            // we give the syscall's size parameter properly.
            read(
                self.as_raw_fd(),
                &mut buf as *mut u64 as *mut c_void,
                mem::size_of::<u64>(),
            )
        };
        if ret <= 0 {
            return errno_result();
        }
        Ok(buf)
    }

    /// Blocks for a maximum of `timeout` duration until the the eventfd's count is non-zero. If
    /// a timeout does not occur then the count is returned as a EventReadResult::Count(count),
    /// and the count is reset to 0. If a timeout does occur then this function will return
    /// EventReadResult::Timeout.
    pub fn read_timeout(&self, timeout: Duration) -> Result<EventReadResult> {
        let mut pfd = libc::pollfd {
            fd: self.as_raw_descriptor(),
            events: POLLIN,
            revents: 0,
        };
        let timeoutspec: libc::timespec = duration_to_timespec(timeout);
        // Safe because this only modifies |pfd| and we check the return value
        let ret = unsafe {
            libc::ppoll(
                &mut pfd as *mut libc::pollfd,
                1,
                &timeoutspec,
                ptr::null_mut(),
            )
        };
        if ret < 0 {
            return errno_result();
        }

        // no return events (revents) means we got a timeout
        if pfd.revents == 0 {
            return Ok(EventReadResult::Timeout);
        }

        let mut buf = 0u64;
        // This is safe because we made this fd and the pointer we pass can not overflow because
        // we give the syscall's size parameter properly.
        let ret = unsafe {
            libc::read(
                self.as_raw_descriptor(),
                &mut buf as *mut _ as *mut c_void,
                mem::size_of::<u64>(),
            )
        };
        if ret < 0 {
            return errno_result();
        }
        Ok(EventReadResult::Count(buf))
    }

    /// Clones this EventFd, internally creating a new file descriptor. The new EventFd will share
    /// the same underlying count within the kernel.
    pub fn try_clone(&self) -> Result<EventFd> {
        self.event_handle
            .try_clone()
            .map(|event_handle| EventFd { event_handle })
    }
}

impl AsRawFd for EventFd {
    fn as_raw_fd(&self) -> RawFd {
        self.event_handle.as_raw_fd()
    }
}

impl AsRawDescriptor for EventFd {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.event_handle.as_raw_descriptor()
    }
}

impl FromRawFd for EventFd {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        EventFd {
            event_handle: SafeDescriptor::from_raw_descriptor(fd),
        }
    }
}

impl IntoRawFd for EventFd {
    fn into_raw_fd(self) -> RawFd {
        self.event_handle.into_raw_descriptor()
    }
}

impl From<EventFd> for SafeDescriptor {
    fn from(evt: EventFd) -> Self {
        evt.event_handle
    }
}

generate_scoped_event!(EventFd);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new() {
        EventFd::new().unwrap();
    }

    #[test]
    fn read_write() {
        let evt = EventFd::new().unwrap();
        evt.write(55).unwrap();
        assert_eq!(evt.read(), Ok(55));
    }

    #[test]
    fn clone() {
        let evt = EventFd::new().unwrap();
        let evt_clone = evt.try_clone().unwrap();
        evt.write(923).unwrap();
        assert_eq!(evt_clone.read(), Ok(923));
    }

    #[test]
    fn scoped_event() {
        let scoped_evt = ScopedEvent::new().unwrap();
        let evt_clone: EventFd = scoped_evt.try_clone().unwrap();
        drop(scoped_evt);
        assert_eq!(evt_clone.read(), Ok(1));
    }

    #[test]
    fn eventfd_from_scoped_event() {
        let scoped_evt = ScopedEvent::new().unwrap();
        let evt: EventFd = scoped_evt.into();
        evt.write(1).unwrap();
    }

    #[test]
    fn timeout() {
        let evt = EventFd::new().expect("failed to create eventfd");
        assert_eq!(
            evt.read_timeout(Duration::from_millis(1))
                .expect("failed to read from eventfd with timeout"),
            EventReadResult::Timeout
        );
    }
}

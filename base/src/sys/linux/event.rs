// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem;
use std::ptr;
use std::time::Duration;

use libc::c_void;
use libc::eventfd;
use libc::read;
use libc::write;
use libc::POLLIN;
use serde::Deserialize;
use serde::Serialize;

use super::errno_result;
use super::Error;
use super::RawDescriptor;
use super::Result;
use crate::descriptor::AsRawDescriptor;
use crate::descriptor::FromRawDescriptor;
use crate::descriptor::IntoRawDescriptor;
use crate::descriptor::SafeDescriptor;
use crate::handle_eintr_errno;
use crate::unix::duration_to_timespec;
use crate::EventWaitResult;

/// A safe wrapper around a Linux eventfd (man 2 eventfd).
///
/// An eventfd is useful because it is sendable across processes and can be used for signaling in
/// and out of the KVM API. They can also be polled like any other file descriptor.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct PlatformEvent {
    event_handle: SafeDescriptor,
}

/// Linux specific extensions to `Event`.
pub trait EventExt {
    /// Adds `v` to the eventfd's count, blocking until this won't overflow the count.
    fn write_count(&self, v: u64) -> Result<()>;
    /// Blocks until the the eventfd's count is non-zero, then resets the count to zero.
    fn read_count(&self) -> Result<u64>;
}

impl EventExt for crate::Event {
    fn write_count(&self, v: u64) -> Result<()> {
        self.0.write_count(v)
    }

    fn read_count(&self) -> Result<u64> {
        self.0.read_count()
    }
}

impl PlatformEvent {
    /// Creates a new blocking eventfd with an initial value of 0.
    pub fn new() -> Result<PlatformEvent> {
        // SAFETY:
        // This is safe because eventfd merely allocated an eventfd for our process and we handle
        // the error case.
        let ret = unsafe { eventfd(0, 0) };
        if ret < 0 {
            return errno_result();
        }
        Ok(PlatformEvent {
            // SAFETY:
            // This is safe because we checked ret for success and know the kernel gave us an fd
            // that we own.
            event_handle: unsafe { SafeDescriptor::from_raw_descriptor(ret) },
        })
    }

    /// See `EventExt::write_count`.
    pub fn write_count(&self, v: u64) -> Result<()> {
        // SAFETY:
        // This is safe because we made this fd and the pointer we pass can not overflow because we
        // give the syscall's size parameter properly.
        let ret = handle_eintr_errno!(unsafe {
            write(
                self.as_raw_descriptor(),
                &v as *const u64 as *const c_void,
                mem::size_of::<u64>(),
            )
        });
        if ret < 0 {
            return errno_result();
        }
        if ret as usize != mem::size_of::<u64>() {
            return Err(Error::new(libc::EIO));
        }
        Ok(())
    }

    /// See `EventExt::read_count`.
    pub fn read_count(&self) -> Result<u64> {
        let mut buf: u64 = 0;
        // SAFETY:
        // This is safe because we made this fd and the pointer we pass can not overflow because
        // we give the syscall's size parameter properly.
        let ret = handle_eintr_errno!(unsafe {
            read(
                self.as_raw_descriptor(),
                &mut buf as *mut u64 as *mut c_void,
                mem::size_of::<u64>(),
            )
        });
        if ret < 0 {
            return errno_result();
        }
        if ret as usize != mem::size_of::<u64>() {
            return Err(Error::new(libc::EIO));
        }
        Ok(buf)
    }

    /// See `Event::signal`.
    pub fn signal(&self) -> Result<()> {
        self.write_count(1)
    }

    /// See `Event::wait`.
    pub fn wait(&self) -> Result<()> {
        self.read_count().map(|_| ())
    }

    /// See `Event::wait_timeout`.
    pub fn wait_timeout(&self, timeout: Duration) -> Result<EventWaitResult> {
        let mut pfd = libc::pollfd {
            fd: self.as_raw_descriptor(),
            events: POLLIN,
            revents: 0,
        };
        let timeoutspec: libc::timespec = duration_to_timespec(timeout);
        // SAFETY:
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
            return Ok(EventWaitResult::TimedOut);
        }

        self.wait()?;
        Ok(EventWaitResult::Signaled)
    }

    /// See `Event::reset`.
    pub fn reset(&self) -> Result<()> {
        // If the eventfd is currently signaled (counter > 0), `wait_timeout()` will `read()` it to
        // reset the count. Otherwise (if the eventfd is not signaled), `wait_timeout()` will return
        // immediately since we pass a zero duration. We don't care about the EventWaitResult; we
        // just want a non-blocking read to reset the counter.
        let _: EventWaitResult = self.wait_timeout(Duration::ZERO)?;
        Ok(())
    }

    /// Clones this eventfd, internally creating a new file descriptor. The new eventfd will share
    /// the same underlying count within the kernel.
    pub fn try_clone(&self) -> Result<PlatformEvent> {
        self.event_handle
            .try_clone()
            .map(|event_handle| PlatformEvent { event_handle })
    }
}

impl AsRawDescriptor for PlatformEvent {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.event_handle.as_raw_descriptor()
    }
}

impl FromRawDescriptor for PlatformEvent {
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
        PlatformEvent {
            event_handle: SafeDescriptor::from_raw_descriptor(descriptor),
        }
    }
}

impl IntoRawDescriptor for PlatformEvent {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self.event_handle.into_raw_descriptor()
    }
}

impl From<PlatformEvent> for SafeDescriptor {
    fn from(evt: PlatformEvent) -> Self {
        evt.event_handle
    }
}

impl From<SafeDescriptor> for PlatformEvent {
    fn from(sd: SafeDescriptor) -> Self {
        PlatformEvent { event_handle: sd }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Event;
    use crate::EventExt;

    #[test]
    fn new() {
        Event::new().unwrap();
    }

    #[test]
    fn read_write() {
        let evt = Event::new().unwrap();
        evt.write_count(55).unwrap();
        assert_eq!(evt.read_count(), Ok(55));
    }

    #[test]
    fn clone() {
        let evt = Event::new().unwrap();
        let evt_clone = evt.try_clone().unwrap();
        evt.write_count(923).unwrap();
        assert_eq!(evt_clone.read_count(), Ok(923));
    }

    #[test]
    fn timeout() {
        let evt = Event::new().expect("failed to create eventfd");
        assert_eq!(
            evt.wait_timeout(Duration::from_millis(1))
                .expect("failed to read from eventfd with timeout"),
            EventWaitResult::TimedOut
        );
    }
}

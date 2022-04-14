// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::generate_scoped_event;
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    mem,
    mem::MaybeUninit,
    ops::Deref,
    os::windows::io::{AsRawHandle, RawHandle},
    ptr,
    ptr::null,
    time::Duration,
};
use win_util::{SecurityAttributes, SelfRelativeSecurityDescriptor};
use winapi::{
    shared::{
        minwindef::{DWORD, FALSE, TRUE},
        winerror::WAIT_TIMEOUT,
    },
    um::{
        handleapi::DuplicateHandle,
        processthreadsapi::GetCurrentProcess,
        synchapi::{CreateEventA, OpenEventA, ResetEvent, SetEvent, WaitForSingleObject},
        winbase::WAIT_FAILED,
        winnt::{DUPLICATE_SAME_ACCESS, EVENT_MODIFY_STATE, HANDLE},
    },
};

use super::{errno_result, Error, RawDescriptor, Result};
use crate::descriptor::{AsRawDescriptor, FromRawDescriptor, IntoRawDescriptor, SafeDescriptor};

/// A safe wrapper around Windows synchapi methods used to mimic Linux eventfd (man 2 eventfd).
/// Since the eventfd isn't using "EFD_SEMAPHORE", we don't need to keep count so we can just use
/// events.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Event {
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

impl Event {
    pub fn new_with_manual_reset(manual_reset: bool) -> Result<Event> {
        let handle = unsafe {
            CreateEventA(
                SecurityAttributes::new_with_security_descriptor(
                    SelfRelativeSecurityDescriptor::get_singleton(),
                    /* inherit= */ false,
                )
                .as_mut(),
                if manual_reset { TRUE } else { FALSE },
                FALSE, // initial state = unsignalled
                null(),
            )
        };
        if handle.is_null() {
            return errno_result();
        }
        Ok(Event {
            event_handle: unsafe { SafeDescriptor::from_raw_descriptor(handle) },
        })
    }

    pub fn create_event_with_name(name: &str) -> Result<Event> {
        let event_str = CString::new(String::from(name)).unwrap();
        let handle = unsafe {
            CreateEventA(
                SecurityAttributes::new_with_security_descriptor(
                    SelfRelativeSecurityDescriptor::get_singleton(),
                    /* inherit= */ false,
                )
                .as_mut(),
                FALSE, // manual_reset = false
                FALSE, // initial state = unsignalled
                event_str.as_ptr(),
            )
        };
        if handle.is_null() {
            return errno_result();
        }
        Ok(Event {
            event_handle: unsafe { SafeDescriptor::from_raw_descriptor(handle) },
        })
    }

    pub fn new() -> Result<Event> {
        // Require manual reset
        Event::new_with_manual_reset(true)
    }

    pub fn open(name: &str) -> Result<Event> {
        let event_str = CString::new(String::from(name)).unwrap();
        let handle = unsafe { OpenEventA(EVENT_MODIFY_STATE, FALSE, event_str.as_ptr()) };
        if handle.is_null() {
            return errno_result();
        }
        Ok(Event {
            event_handle: unsafe { SafeDescriptor::from_raw_descriptor(handle) },
        })
    }

    pub fn new_auto_reset() -> Result<Event> {
        Event::new_with_manual_reset(false)
    }

    pub fn write(&self, _v: u64) -> Result<()> {
        let event_result = unsafe { SetEvent(self.event_handle.as_raw_descriptor()) };
        if event_result == 0 {
            return errno_result();
        }
        Ok(())
    }

    pub fn read(&self) -> Result<u64> {
        let read_result = self.read_timeout(Duration::new(std::i64::MAX as u64, 0));
        match read_result {
            Ok(EventReadResult::Count(c)) => Ok(c),
            Ok(EventReadResult::Timeout) => Err(Error::new(WAIT_TIMEOUT)),
            Err(e) => Err(e),
        }
    }

    pub fn reset(&self) -> Result<()> {
        let res = unsafe { ResetEvent(self.event_handle.as_raw_descriptor()) };
        if res == 0 {
            errno_result()
        } else {
            Ok(())
        }
    }

    /// Blocks for a maximum of `timeout` duration until the the event is signaled. If
    /// a timeout does not occur then the count is returned as a EventReadResult::Count(1),
    /// and the event resets. If a timeout does occur then this function will return
    /// EventReadResult::Timeout.
    pub fn read_timeout(&self, timeout: Duration) -> Result<EventReadResult> {
        let wait_result = unsafe {
            WaitForSingleObject(
                self.event_handle.as_raw_descriptor(),
                timeout.as_millis() as DWORD,
            )
        };

        // We are using an infinite timeout so we can ignore WAIT_ABANDONED
        match wait_result {
            WAIT_FAILED => errno_result(),
            WAIT_TIMEOUT => Ok(EventReadResult::Timeout),
            _ => {
                // Safe because self manages the handle and we know it was valid as it
                // was just successfully waited upon. It is safe to reset a non manual reset event as well.
                match unsafe { ResetEvent(self.event_handle.as_raw_descriptor()) } {
                    0 => errno_result(),
                    _ => Ok(EventReadResult::Count(1)),
                }
            }
        }
    }

    pub fn try_clone(&self) -> Result<Event> {
        let mut event_clone: HANDLE = MaybeUninit::uninit().as_mut_ptr();
        let duplicate_result = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                self.event_handle.as_raw_descriptor(),
                GetCurrentProcess(),
                &mut event_clone,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if duplicate_result == 0 {
            return errno_result();
        }
        Ok(unsafe { Event::from_raw_descriptor(event_clone) })
    }
}

impl AsRawDescriptor for Event {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.event_handle.as_raw_descriptor()
    }
}

impl FromRawDescriptor for Event {
    unsafe fn from_raw_descriptor(descriptor: RawDescriptor) -> Self {
        Event {
            event_handle: SafeDescriptor::from_raw_descriptor(descriptor),
        }
    }
}

impl AsRawHandle for Event {
    fn as_raw_handle(&self) -> RawHandle {
        self.as_raw_descriptor()
    }
}

impl IntoRawDescriptor for Event {
    fn into_raw_descriptor(self) -> RawDescriptor {
        self.event_handle.into_raw_descriptor()
    }
}

// Event is safe for send & Sync despite containing a raw handle to its
// file mapping object. As long as the instance to Event stays alive, this
// pointer will be a valid handle.
unsafe impl Send for Event {}
unsafe impl Sync for Event {}

generate_scoped_event!(Event);

#[cfg(test)]
mod tests {
    use super::*;
    use winapi::{
        shared::winerror::WAIT_TIMEOUT,
        um::winbase::{INFINITE, WAIT_OBJECT_0},
    };

    #[test]
    fn new() {
        Event::new().unwrap();
    }

    #[test]
    fn read_write() {
        let evt = Event::new().unwrap();
        evt.write(55).unwrap();
        assert_eq!(evt.read(), Ok(1));
    }

    #[test]
    fn read_write_auto_reset() {
        let evt = Event::new_auto_reset().unwrap();
        evt.write(55).unwrap();

        // Wait for the notification.
        let result = unsafe { WaitForSingleObject(evt.as_raw_descriptor(), INFINITE) };
        assert_eq!(result, WAIT_OBJECT_0);

        // The notification should have reset since we already received it.
        let result = unsafe { WaitForSingleObject(evt.as_raw_descriptor(), 0) };
        assert_eq!(result, WAIT_TIMEOUT);
    }

    #[test]
    fn read_write_notifies_until_read() {
        let evt = Event::new().unwrap();
        evt.write(55).unwrap();

        // Wait for the notification.
        let result = unsafe { WaitForSingleObject(evt.as_raw_descriptor(), INFINITE) };
        assert_eq!(result, WAIT_OBJECT_0);

        // The notification should still be active because read wasn't called.
        let result = unsafe { WaitForSingleObject(evt.as_raw_descriptor(), 0) };
        assert_eq!(result, WAIT_OBJECT_0);

        // Read and ensure the notification has cleared.
        evt.read().expect("Failed to read event.");
        let result = unsafe { WaitForSingleObject(evt.as_raw_descriptor(), 0) };
        assert_eq!(result, WAIT_TIMEOUT);
    }

    #[test]
    fn clone() {
        let evt = Event::new().unwrap();
        let evt_clone = evt.try_clone().unwrap();
        evt.write(923).unwrap();
        assert_eq!(evt_clone.read(), Ok(1));
    }

    #[test]
    fn timeout() {
        let evt = Event::new().expect("failed to create event");
        assert_eq!(
            evt.read_timeout(Duration::from_millis(1))
                .expect("failed to read from event with timeout"),
            EventReadResult::Timeout
        );
    }

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

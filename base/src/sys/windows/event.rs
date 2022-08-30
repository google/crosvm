// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::RawHandle;
use std::ptr::null;
use std::time::Duration;

use serde::Deserialize;
use serde::Serialize;
use win_util::SecurityAttributes;
use win_util::SelfRelativeSecurityDescriptor;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::FALSE;
use winapi::shared::minwindef::TRUE;
use winapi::shared::winerror::WAIT_TIMEOUT;
use winapi::um::handleapi::DuplicateHandle;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::synchapi::CreateEventA;
use winapi::um::synchapi::OpenEventA;
use winapi::um::synchapi::ResetEvent;
use winapi::um::synchapi::SetEvent;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::WAIT_FAILED;
use winapi::um::winnt::DUPLICATE_SAME_ACCESS;
use winapi::um::winnt::EVENT_MODIFY_STATE;
use winapi::um::winnt::HANDLE;

use super::errno_result;
use super::Error;
use super::RawDescriptor;
use super::Result;
use crate::descriptor::AsRawDescriptor;
use crate::descriptor::FromRawDescriptor;
use crate::descriptor::IntoRawDescriptor;
use crate::descriptor::SafeDescriptor;
use crate::Event;
use crate::EventWaitResult;

/// A safe wrapper around Windows synchapi methods used to mimic Linux eventfd (man 2 eventfd).
/// Since the eventfd isn't using "EFD_SEMAPHORE", we don't need to keep count so we can just use
/// events.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct PlatformEvent {
    event_handle: SafeDescriptor,
}

pub trait EventExt {
    fn reset(&self) -> Result<()>;
    fn new_with_manual_reset(manual_reset: bool) -> Result<Event>;
    fn new_auto_reset() -> Result<Event>;
    fn open(name: &str) -> Result<Event>;
    fn create_event_with_name(name: &str) -> Result<Event>;
}

impl EventExt for Event {
    fn reset(&self) -> Result<()> {
        self.0.reset()
    }

    fn new_with_manual_reset(manual_reset: bool) -> Result<Event> {
        PlatformEvent::new_with_manual_reset(manual_reset).map(Event)
    }

    fn new_auto_reset() -> Result<Event> {
        Event::new_with_manual_reset(false)
    }

    fn open(name: &str) -> Result<Event> {
        PlatformEvent::open(name).map(Event)
    }

    fn create_event_with_name(name: &str) -> Result<Event> {
        PlatformEvent::create_event_with_name(name).map(Event)
    }
}

impl PlatformEvent {
    pub fn new_with_manual_reset(manual_reset: bool) -> Result<PlatformEvent> {
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
        Ok(PlatformEvent {
            event_handle: unsafe { SafeDescriptor::from_raw_descriptor(handle) },
        })
    }

    pub fn create_event_with_name(name: &str) -> Result<PlatformEvent> {
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
        Ok(PlatformEvent {
            event_handle: unsafe { SafeDescriptor::from_raw_descriptor(handle) },
        })
    }

    pub fn new() -> Result<PlatformEvent> {
        // Require manual reset
        PlatformEvent::new_with_manual_reset(true)
    }

    pub fn open(name: &str) -> Result<PlatformEvent> {
        let event_str = CString::new(String::from(name)).unwrap();
        let handle = unsafe { OpenEventA(EVENT_MODIFY_STATE, FALSE, event_str.as_ptr()) };
        if handle.is_null() {
            return errno_result();
        }
        Ok(PlatformEvent {
            event_handle: unsafe { SafeDescriptor::from_raw_descriptor(handle) },
        })
    }

    pub fn new_auto_reset() -> Result<PlatformEvent> {
        PlatformEvent::new_with_manual_reset(false)
    }

    /// See `Event::signal`.
    pub fn signal(&self) -> Result<()> {
        let event_result = unsafe { SetEvent(self.event_handle.as_raw_descriptor()) };
        if event_result == 0 {
            return errno_result();
        }
        Ok(())
    }

    /// See `Event::wait`.
    pub fn wait(&self) -> Result<()> {
        let read_result = self.wait_timeout(Duration::new(std::i64::MAX as u64, 0));
        match read_result {
            Ok(EventWaitResult::Signaled) => Ok(()),
            Ok(EventWaitResult::TimedOut) => Err(Error::new(WAIT_TIMEOUT)),
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

    /// See `Event::wait_timeout`.
    pub fn wait_timeout(&self, timeout: Duration) -> Result<EventWaitResult> {
        let wait_result = unsafe {
            WaitForSingleObject(
                self.event_handle.as_raw_descriptor(),
                timeout.as_millis() as DWORD,
            )
        };

        // We are using an infinite timeout so we can ignore WAIT_ABANDONED
        match wait_result {
            WAIT_FAILED => errno_result(),
            WAIT_TIMEOUT => Ok(EventWaitResult::TimedOut),
            _ => {
                // Safe because self manages the handle and we know it was valid as it
                // was just successfully waited upon. It is safe to reset a non manual reset event as well.
                match unsafe { ResetEvent(self.event_handle.as_raw_descriptor()) } {
                    0 => errno_result(),
                    _ => Ok(EventWaitResult::Signaled),
                }
            }
        }
    }

    pub fn try_clone(&self) -> Result<PlatformEvent> {
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
        Ok(unsafe { PlatformEvent::from_raw_descriptor(event_clone) })
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

impl AsRawHandle for PlatformEvent {
    fn as_raw_handle(&self) -> RawHandle {
        self.as_raw_descriptor()
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

// PlatformEvent is safe for send & Sync despite containing a raw handle to its
// file mapping object. As long as the instance to PlatformEvent stays alive, this
// pointer will be a valid handle.
unsafe impl Send for PlatformEvent {}
unsafe impl Sync for PlatformEvent {}

#[cfg(test)]
mod tests {
    use winapi::shared::winerror::WAIT_TIMEOUT;
    use winapi::um::winbase::INFINITE;
    use winapi::um::winbase::WAIT_OBJECT_0;

    use super::*;

    #[test]
    fn new() {
        PlatformEvent::new().unwrap();
    }

    #[test]
    fn read_write() {
        let evt = PlatformEvent::new().unwrap();
        evt.signal().unwrap();
        assert_eq!(evt.wait(), Ok(()));
    }

    #[test]
    fn read_write_auto_reset() {
        let evt = PlatformEvent::new_auto_reset().unwrap();
        evt.signal().unwrap();

        // Wait for the notification.
        let result = unsafe { WaitForSingleObject(evt.as_raw_descriptor(), INFINITE) };
        assert_eq!(result, WAIT_OBJECT_0);

        // The notification should have reset since we already received it.
        let result = unsafe { WaitForSingleObject(evt.as_raw_descriptor(), 0) };
        assert_eq!(result, WAIT_TIMEOUT);
    }

    #[test]
    fn read_write_notifies_until_read() {
        let evt = PlatformEvent::new().unwrap();
        evt.signal().unwrap();

        // Wait for the notification.
        let result = unsafe { WaitForSingleObject(evt.as_raw_descriptor(), INFINITE) };
        assert_eq!(result, WAIT_OBJECT_0);

        // The notification should still be active because read wasn't called.
        let result = unsafe { WaitForSingleObject(evt.as_raw_descriptor(), 0) };
        assert_eq!(result, WAIT_OBJECT_0);

        // Read and ensure the notification has cleared.
        evt.wait().expect("Failed to read event.");
        let result = unsafe { WaitForSingleObject(evt.as_raw_descriptor(), 0) };
        assert_eq!(result, WAIT_TIMEOUT);
    }

    #[test]
    fn clone() {
        let evt = PlatformEvent::new().unwrap();
        let evt_clone = evt.try_clone().unwrap();
        evt.signal().unwrap();
        assert_eq!(evt_clone.wait(), Ok(()));
    }

    #[test]
    fn timeout() {
        let evt = PlatformEvent::new().expect("failed to create event");
        assert_eq!(
            evt.wait_timeout(Duration::from_millis(1))
                .expect("failed to read from event with timeout"),
            EventWaitResult::TimedOut
        );
    }
}

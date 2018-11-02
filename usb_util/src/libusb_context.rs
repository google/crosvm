// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std;

use bindings;
use error::{Error, Result};
use libusb_device::LibUsbDevice;
use std::sync::Arc;

pub struct LibUsbContextInner {
    context: *mut bindings::libusb_context,
}

// Safe because libusb_context could be accessed from multiple threads safely.
unsafe impl Send for LibUsbContextInner {}
unsafe impl Sync for LibUsbContextInner {}

impl Drop for LibUsbContextInner {
    fn drop(&mut self) {
        // Safe beacuse 'self.context' points to a valid context allocated by libusb_init.
        unsafe {
            bindings::libusb_exit(self.context);
        }
    }
}

/// Wrapper for libusb_context. The libusb libary initialization/deinitialization
/// is managed by this context.
/// See: http://libusb.sourceforge.net/api-1.0/group__libusb__lib.html
#[derive(Clone)]
pub struct LibUsbContext {
    inner: Arc<LibUsbContextInner>,
}

impl LibUsbContext {
    /// Create a new LibUsbContext.
    pub fn new() -> Result<LibUsbContext> {
        let mut ctx: *mut bindings::libusb_context = std::ptr::null_mut();
        // Safe because '&mut ctx' points to a valid memory (on stack).
        try_libusb!(unsafe { bindings::libusb_init(&mut ctx) });
        Ok(LibUsbContext {
            inner: Arc::new(LibUsbContextInner { context: ctx }),
        })
    }

    /// Returns a list of USB devices currently attached to the system.
    pub fn get_device_iter(&self) -> Result<DeviceIter> {
        let mut list: *mut *mut bindings::libusb_device = std::ptr::null_mut();
        // Safe because 'inner.context' points to a valid context and '&mut list' points to a valid
        // memory.
        try_libusb!(unsafe { bindings::libusb_get_device_list(self.inner.context, &mut list) });

        Ok(DeviceIter {
            context: self.inner.clone(),
            list,
            index: 0,
        })
    }

    /// Check at runtime if the loaded library has a given capability.
    pub fn has_capability(&self, cap: u32) -> bool {
        // Safe because libusb_init is called before this call happens.
        unsafe { bindings::libusb_has_capability(cap) != 0 }
    }

    /// Return an iter of poll fds. Those fds that should be polled to handle libusb events.
    pub fn get_pollfd_iter(&self) -> PollFdIter {
        // Safe because 'inner.context' is inited.
        let list: *mut *const bindings::libusb_pollfd =
            unsafe { bindings::libusb_get_pollfds(self.inner.context) };
        PollFdIter { list, index: 0 }
    }

    /// Handle libusb events in a non block way.
    pub fn handle_event_nonblock(&self) {
        static mut zero_time: bindings::timeval = bindings::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        // Safe because 'inner.context' points to valid context.
        unsafe {
            bindings::libusb_handle_events_timeout_completed(
                self.inner.context,
                &mut zero_time as *mut bindings::timeval,
                std::ptr::null_mut(),
            );
        }
    }
}

/// Iterator for device list.
pub struct DeviceIter {
    context: Arc<LibUsbContextInner>,
    list: *mut *mut bindings::libusb_device,
    index: isize,
}

impl Drop for DeviceIter {
    fn drop(&mut self) {
        // Safe because 'self.list' is inited by a valid pointer from libusb_get_device_list.
        unsafe {
            bindings::libusb_free_device_list(self.list, 1);
        }
    }
}

impl Iterator for DeviceIter {
    type Item = LibUsbDevice;

    fn next(&mut self) -> Option<LibUsbDevice> {
        // Safe becuase 'self.list' is valid, the list is null terminated.
        unsafe {
            let current_ptr = self.list.offset(self.index);
            if (*current_ptr).is_null() {
                return None;
            }
            self.index += 1;
            Some(LibUsbDevice::new(self.context.clone(), *current_ptr))
        }
    }
}

/// Iterator for pollfds.
pub struct PollFdIter {
    list: *mut *const bindings::libusb_pollfd,
    index: isize,
}

impl Drop for PollFdIter {
    fn drop(&mut self) {
        // Safe because 'self.list' points to valid memory of pollfd list.
        unsafe {
            bindings::libusb_free_pollfds(self.list);
        }
    }
}

impl Iterator for PollFdIter {
    type Item = bindings::libusb_pollfd;

    fn next(&mut self) -> Option<bindings::libusb_pollfd> {
        // Safe because 'self.index' never grow out of the null pointer index.
        unsafe {
            let current_ptr = self.list.offset(self.index);
            if (*current_ptr).is_null() {
                return None;
            }

            self.index += 1;
            // Safe because 'current_ptr' is not null.
            Some((**current_ptr).clone())
        }
    }
}

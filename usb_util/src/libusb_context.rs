// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std;
use std::os::raw::{c_short, c_void};
use std::os::unix::io::RawFd;
use std::sync::Arc;

use crate::bindings;
use crate::error::{Error, Result};
use crate::hotplug::{hotplug_cb, UsbHotplugHandler, UsbHotplugHandlerHolder};
use crate::libusb_device::LibUsbDevice;

use sync::Mutex;

pub struct LibUsbContextInner {
    context: *mut bindings::libusb_context,
    pollfd_change_handler: Mutex<Option<Box<PollfdChangeHandlerHolder>>>,
}

// Safe because libusb_context could be accessed from multiple threads safely.
unsafe impl Send for LibUsbContextInner {}
unsafe impl Sync for LibUsbContextInner {}

impl LibUsbContextInner {
    /// Remove the previous registered notifiers.
    pub fn remove_pollfd_notifiers(&self) {
        // Safe because 'self.context' is valid.
        unsafe {
            bindings::libusb_set_pollfd_notifiers(self.context, None, None, std::ptr::null_mut());
        }
    }
}

impl Drop for LibUsbContextInner {
    fn drop(&mut self) {
        // Avoid pollfd change handler call when libusb_exit is called.
        self.remove_pollfd_notifiers();
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
            inner: Arc::new(LibUsbContextInner {
                context: ctx,
                pollfd_change_handler: Mutex::new(None),
            }),
        })
    }

    /// Create a new jailed LibUsbContext.
    #[cfg(feature = "sandboxed-libusb")]
    pub fn new_jailed() -> Result<LibUsbContext> {
        let mut ctx: *mut bindings::libusb_context = std::ptr::null_mut();
        // Safe because '&mut ctx' points to a valid memory (on stack).
        try_libusb!(unsafe { bindings::libusb_init_jailed(&mut ctx) });
        Ok(LibUsbContext {
            inner: Arc::new(LibUsbContextInner {
                context: ctx,
                pollfd_change_handler: Mutex::new(None),
            }),
        })
    }

    /// Build device from File.
    #[cfg(feature = "sandboxed-libusb")]
    pub fn get_device_from_fd(&self, fd: std::fs::File) -> Result<LibUsbDevice> {
        use std::os::unix::io::IntoRawFd;

        let fd = fd.into_raw_fd();
        let mut device: *mut bindings::libusb_device = std::ptr::null_mut();
        // Safe because fd is valid and owned, and '&mut device' points to valid memory.
        try_libusb!(unsafe {
            bindings::libusb_get_device_from_fd(self.inner.context, fd, &mut device)
        });
        unsafe { Ok(LibUsbDevice::new(self.inner.clone(), device)) }
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
    pub fn handle_events_nonblock(&self) {
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

    /// Set a handler that could handle pollfd change events.
    pub fn set_pollfd_notifiers(&self, handler: Box<dyn LibUsbPollfdChangeHandler>) {
        // LibUsbContext is alive when any libusb related function is called. It owns the handler,
        // thus the handler memory is always valid when callback is invoked.
        let holder = Box::new(PollfdChangeHandlerHolder { handler });
        let raw_holder = Box::into_raw(holder);
        unsafe {
            bindings::libusb_set_pollfd_notifiers(
                self.inner.context,
                Some(pollfd_added_cb),
                Some(pollfd_removed_cb),
                raw_holder as *mut c_void,
            );
        }
        // Safe because raw_holder is from Boxed pointer.
        let holder = unsafe { Box::from_raw(raw_holder) };
        *self.inner.pollfd_change_handler.lock() = Some(holder);
    }

    /// Remove the previous registered notifiers.
    pub fn remove_pollfd_notifiers(&self) {
        self.inner.remove_pollfd_notifiers();
    }

    /// Set a callback that could handle hotplug events. Currently, this function listen to hotplug
    /// event of all devices.
    pub fn set_hotplug_cb<H: UsbHotplugHandler + Sized>(&self, handler: H) -> Result<()> {
        let event = bindings::LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED
            | bindings::LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT;
        let holder = UsbHotplugHandlerHolder::new(self.inner.clone(), handler);
        let raw_holder = Box::into_raw(holder);
        // Safe becuase hotpulg cb is a vaild c function and raw_holder points to memory for that
        // function argument.
        try_libusb!(unsafe {
            bindings::libusb_hotplug_register_callback(
                self.inner.context,
                event,
                bindings::LIBUSB_HOTPLUG_NO_FLAGS,
                bindings::LIBUSB_HOTPLUG_MATCH_ANY,
                bindings::LIBUSB_HOTPLUG_MATCH_ANY,
                bindings::LIBUSB_HOTPLUG_MATCH_ANY,
                Some(hotplug_cb),
                raw_holder as *mut c_void,
                std::ptr::null_mut(),
            )
        });
        Ok(())
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
            // Safe because '*current_ptr' is not null.
            Some(**current_ptr)
        }
    }
}

/// Trait for handler that handles Pollfd Change events.
pub trait LibUsbPollfdChangeHandler: Send + Sync + 'static {
    fn add_poll_fd(&self, fd: RawFd, events: c_short);
    fn remove_poll_fd(&self, fd: RawFd);
}

// This struct owns LibUsbPollfdChangeHandler. We need it because it's not possible to cast void
// pointer to trait pointer.
struct PollfdChangeHandlerHolder {
    handler: Box<dyn LibUsbPollfdChangeHandler>,
}

// This function is safe when user_data points to valid PollfdChangeHandlerHolder.
unsafe extern "C" fn pollfd_added_cb(fd: RawFd, events: c_short, user_data: *mut c_void) {
    // Safe because user_data was casted from holder.
    let keeper = &*(user_data as *mut PollfdChangeHandlerHolder);
    keeper.handler.add_poll_fd(fd, events);
}

// This function is safe when user_data points to valid PollfdChangeHandlerHolder.
unsafe extern "C" fn pollfd_removed_cb(fd: RawFd, user_data: *mut c_void) {
    // Safe because user_data was casted from holder.
    let keeper = &*(user_data as *mut PollfdChangeHandlerHolder);
    keeper.handler.remove_poll_fd(fd);
}

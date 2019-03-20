// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::raw::c_int;
use std::sync::Arc;

use crate::bindings;
use crate::error::{Error, Result};
use crate::libusb_context::LibUsbContextInner;
use crate::usb_transfer::{UsbTransfer, UsbTransferBuffer};

/// DeviceHandle wraps libusb_device_handle.
pub struct DeviceHandle {
    _context: Arc<LibUsbContextInner>,
    handle: *mut bindings::libusb_device_handle,
}

unsafe impl Send for DeviceHandle {}

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        // Safe because self.handle is a valid pointer to libusb_device_handle.
        unsafe {
            bindings::libusb_close(self.handle);
        }
    }
}

impl DeviceHandle {
    /// Create a new DeviceHande. 'handle' should be a valid pointer to libusb_device_handle.
    pub unsafe fn new(
        ctx: Arc<LibUsbContextInner>,
        handle: *mut bindings::libusb_device_handle,
    ) -> DeviceHandle {
        DeviceHandle {
            _context: ctx,
            handle,
        }
    }

    /// Reset this usb device.
    pub fn reset(&self) -> Result<()> {
        // Safe because 'self.handle' is a valid pointer to device handle.
        try_libusb!(unsafe { bindings::libusb_reset_device(self.handle) });
        Ok(())
    }
    /// Get bConfigurationValue of the currently active configuration.
    pub fn get_active_configuration(&self) -> Result<i32> {
        let mut config: c_int = 0;
        // Safe because 'self.handle' is a valid pointer to device handle and '&mut config' is a
        // valid output location.
        try_libusb!(unsafe { bindings::libusb_get_configuration(self.handle, &mut config) });
        Ok(config as i32)
    }

    /// Set active configuration for a device.
    pub fn set_active_configuration(&mut self, config: i32) -> Result<()> {
        // Safe because 'self.handle' is a valid pointer to device handle.
        try_libusb!(unsafe { bindings::libusb_set_configuration(self.handle, config as c_int) });
        Ok(())
    }

    /// Claim an interface on this deivce handle.
    pub fn claim_interface(&self, interface_number: i32) -> Result<()> {
        // Safe because 'self.handle' is a valid pointer to device handle.
        try_libusb!(unsafe { bindings::libusb_claim_interface(self.handle, interface_number) });
        Ok(())
    }

    /// Release an interface previously claimed with libusb_claim_interface.
    pub fn release_interface(&self, interface_number: i32) -> Result<()> {
        // Safe because 'self.handle' is a valid pointer to device handle.
        try_libusb!(unsafe { bindings::libusb_release_interface(self.handle, interface_number) });
        Ok(())
    }

    /// Perform a USB port reset to reinitialize a device.
    pub fn reset_device(&self) -> Result<()> {
        // Safe because 'self.handle' is a valid pointer to device handle.
        try_libusb!(unsafe { bindings::libusb_reset_device(self.handle) });
        Ok(())
    }

    /// Determine if a kernel driver is active on an interface.
    pub fn kernel_driver_active(&self, interface_number: i32) -> Result<bool> {
        // Safe because 'self.handle' is a valid pointer to device handle.
        let v = try_libusb!(unsafe {
            bindings::libusb_kernel_driver_active(self.handle, interface_number)
        });
        Ok(v != 0)
    }

    /// Detach a kernel driver from an interface.
    pub fn detach_kernel_driver(&self, interface_number: i32) -> Result<()> {
        // Safe because 'self.handle' is a valid pointer to device handle.
        try_libusb!(unsafe {
            bindings::libusb_detach_kernel_driver(self.handle, interface_number)
        });
        Ok(())
    }

    /// Re-attach an interfae's kernel driver, which was previously detached using
    /// detach_kernel_driver.
    pub fn attach_kernel_driver(&self, interface_number: i32) -> Result<()> {
        // Safe because 'self.handle' is a valid pointer to device handle.
        try_libusb!(unsafe {
            bindings::libusb_attach_kernel_driver(self.handle, interface_number)
        });
        Ok(())
    }

    /// Active an alternate setting for an interface.
    pub fn set_interface_alt_setting(
        &self,
        interface_number: i32,
        alternative_setting: i32,
    ) -> Result<()> {
        // Safe because 'self.handle' is a valid pointer to device handle.
        try_libusb!(unsafe {
            bindings::libusb_set_interface_alt_setting(
                self.handle,
                interface_number,
                alternative_setting,
            )
        });
        Ok(())
    }

    /// Clear the halt/stall condition for an endpoint.
    pub fn clear_halt(&self, endpoint: u8) -> Result<()> {
        // Safe because 'self.handle' is a valid pointer to device handle.
        try_libusb!(unsafe { bindings::libusb_clear_halt(self.handle, endpoint) });
        Ok(())
    }

    /// Libusb asynchronous I/O interface has a 5 step process. It gives lots of
    /// flexibility but makes it hard to manage object life cycle and easy to
    /// write unsafe code. We wrap this interface to a simple "transfer" and "cancel"
    /// interface. Resubmission is not supported and deallocation is handled safely
    /// here.
    pub fn submit_async_transfer<T: UsbTransferBuffer>(
        &self,
        transfer: UsbTransfer<T>,
    ) -> Result<()> {
        unsafe { transfer.submit(self.handle) }
    }
}

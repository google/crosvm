// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ops::Deref;

use crate::bindings::{self, libusb_config_descriptor};
use crate::interface_descriptor::InterfaceDescriptor;

/// ConfigDescriptor wraps libusb_config_descriptor.
pub struct ConfigDescriptor {
    descriptor: *mut libusb_config_descriptor,
}

impl Drop for ConfigDescriptor {
    // Free configuration descriptor.
    // Safe because 'self' is intialized with a valid libusb_config_descriptor from libusb
    // functions.
    fn drop(&mut self) {
        unsafe {
            bindings::libusb_free_config_descriptor(self.descriptor);
        }
    }
}

impl ConfigDescriptor {
    /// Build ConfigDescriptor. 'descriptor' should be a valid pointer from
    /// libusb_config_descriptor. This function will panic if it's null.
    pub unsafe fn new(descriptor: *mut libusb_config_descriptor) -> ConfigDescriptor {
        assert!(!descriptor.is_null());
        ConfigDescriptor { descriptor }
    }

    /// Get interface by number and alt setting.
    pub fn get_interface_descriptor(
        &self,
        interface_num: u8,
        alt_setting: i32,
    ) -> Option<InterfaceDescriptor> {
        let config_descriptor = self.deref();
        if interface_num >= config_descriptor.bNumInterfaces {
            return None;
        }
        // Safe because interface num is checked.
        let interface = unsafe { &*(config_descriptor.interface.offset(interface_num as isize)) };

        if alt_setting >= interface.num_altsetting {
            return None;
        }
        // Safe because setting num is checked.
        unsafe {
            Some(InterfaceDescriptor::new(
                &*(interface.altsetting.offset(alt_setting as isize)),
            ))
        }
    }
}

impl Deref for ConfigDescriptor {
    type Target = libusb_config_descriptor;

    fn deref(&self) -> &libusb_config_descriptor {
        // Safe because 'self.descriptor' is valid.
        unsafe { &*(self.descriptor) }
    }
}

// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use bindings;
use bindings::libusb_config_descriptor;

/// ConfigDescriptor wraps libusb_config_descriptor.
/// TODO(jkwang) Add utility functions to make ConfigDescriptor actually useful.
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
}

// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ops::Deref;

use crate::bindings::libusb_interface_descriptor;
use crate::endpoint_descriptor::EndpointDescriptor;

/// InterfaceDescriptor wraps libusb_interface_descriptor.
pub struct InterfaceDescriptor<'a>(&'a libusb_interface_descriptor);

impl<'a> InterfaceDescriptor<'a> {
    /// Create a new Interface descriptor.
    pub fn new(descriptor: &'a libusb_interface_descriptor) -> InterfaceDescriptor<'a> {
        InterfaceDescriptor(descriptor)
    }

    /// Get endpoint descriptor at index.
    pub fn endpoint_descriptor(&self, ep_idx: u8) -> Option<EndpointDescriptor> {
        if ep_idx >= self.0.bNumEndpoints {
            return None;
        }

        // Safe because idx is checked.
        unsafe {
            Some(EndpointDescriptor::new(
                &*(self.0.endpoint.offset(ep_idx as isize)),
            ))
        }
    }
}

impl<'a> Deref for InterfaceDescriptor<'a> {
    type Target = libusb_interface_descriptor;

    fn deref(&self) -> &libusb_interface_descriptor {
        self.0
    }
}

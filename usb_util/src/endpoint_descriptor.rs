// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ops::Deref;

use crate::bindings::libusb_endpoint_descriptor;
use crate::types::{EndpointDirection, EndpointType};

/// EndpointDescriptor wraps libusb_endpoint_descriptor.
pub struct EndpointDescriptor<'a>(&'a libusb_endpoint_descriptor);

const ENDPOINT_DESCRIPTOR_DIRECTION_MASK: u8 = 1 << 7;
const ENDPOINT_DESCRIPTOR_NUMBER_MASK: u8 = 0xf;
const ENDPOINT_DESCRIPTOR_ATTRIBUTES_TYPE_MASK: u8 = 0x3;

impl<'a> EndpointDescriptor<'a> {
    // Create new endpoint descriptor.
    pub fn new(descriptor: &libusb_endpoint_descriptor) -> EndpointDescriptor {
        EndpointDescriptor(descriptor)
    }

    // Get direction of this endpoint.
    pub fn get_direction(&self) -> EndpointDirection {
        let direction = self.0.bEndpointAddress & ENDPOINT_DESCRIPTOR_DIRECTION_MASK;
        if direction > 0 {
            EndpointDirection::DeviceToHost
        } else {
            EndpointDirection::HostToDevice
        }
    }

    // Get endpoint number.
    pub fn get_endpoint_number(&self) -> u8 {
        self.0.bEndpointAddress & ENDPOINT_DESCRIPTOR_NUMBER_MASK
    }

    // Get endpoint type.
    pub fn get_endpoint_type(&self) -> Option<EndpointType> {
        let ep_type = self.0.bmAttributes & ENDPOINT_DESCRIPTOR_ATTRIBUTES_TYPE_MASK;
        match ep_type {
            0 => Some(EndpointType::Control),
            1 => Some(EndpointType::Isochronous),
            2 => Some(EndpointType::Bulk),
            3 => Some(EndpointType::Interrupt),
            _ => None,
        }
    }
}

impl<'a> Deref for EndpointDescriptor<'a> {
    type Target = libusb_endpoint_descriptor;

    fn deref(&self) -> &libusb_endpoint_descriptor {
        self.0
    }
}

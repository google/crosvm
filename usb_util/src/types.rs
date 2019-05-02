// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use assertions::const_assert;
use data_model::DataInit;

use std::mem::size_of;

use crate::bindings;

/// Speed of usb device. See usb spec for more details.
#[derive(Debug)]
pub enum Speed {
    /// The OS doesn't report or know the device speed.
    Unknown,
    /// The device is operating at low speed (1.5MBit/s).
    Low,
    /// The device is operating at full speed (12MBit/s).
    Full,
    /// The device is operating at high speed (480MBit/s).
    High,
    /// The device is operating at super speed (5000MBit/s).
    Super,
}

impl From<bindings::libusb_speed> for Speed {
    fn from(speed: bindings::libusb_speed) -> Speed {
        match speed {
            bindings::LIBUSB_SPEED_LOW => Speed::Low,
            bindings::LIBUSB_SPEED_FULL => Speed::Full,
            bindings::LIBUSB_SPEED_HIGH => Speed::High,
            bindings::LIBUSB_SPEED_SUPER => Speed::Super,
            _ => Speed::Unknown,
        }
    }
}

/// Endpoint types.
#[derive(PartialEq)]
pub enum EndpointType {
    Control,
    Isochronous,
    Bulk,
    Interrupt,
}

/// Endpoint Directions.
#[derive(PartialEq, Clone, Copy)]
pub enum EndpointDirection {
    HostToDevice = 0,
    DeviceToHost = 1,
}
/// Endpoint direction offset.
pub const ENDPOINT_DIRECTION_OFFSET: u8 = 7;

/// Offset of data phase transfer direction.
pub const DATA_PHASE_DIRECTION_OFFSET: u8 = 7;
/// Bit mask of data phase transfer direction.
pub const DATA_PHASE_DIRECTION: u8 = 1u8 << DATA_PHASE_DIRECTION_OFFSET;
// Types of data phase transfer directions.
#[derive(Copy, Clone, PartialEq)]
pub enum ControlRequestDataPhaseTransferDirection {
    HostToDevice = 0,
    DeviceToHost = 1,
}

/// Offset of control request type.
pub const CONTROL_REQUEST_TYPE_OFFSET: u8 = 5;
/// Bit mask of control request type.
pub const CONTROL_REQUEST_TYPE: u8 = 0b11 << CONTROL_REQUEST_TYPE_OFFSET;
/// Request types.
#[derive(PartialEq)]
pub enum ControlRequestType {
    Standard = 0,
    Class = 1,
    Vendor = 2,
    Reserved = 3,
}

/// Recipient type bits.
pub const REQUEST_RECIPIENT_TYPE: u8 = 0b1111;
/// Recipient type of control request.
#[derive(PartialEq)]
pub enum ControlRequestRecipient {
    Device = 0,
    Interface = 1,
    Endpoint = 2,
    Other = 3,
    Reserved,
}

/// Standard request defined in usb spec.
#[derive(PartialEq)]
pub enum StandardControlRequest {
    GetStatus = 0x00,
    ClearFeature = 0x01,
    SetFeature = 0x03,
    SetAddress = 0x05,
    GetDescriptor = 0x06,
    SetDescriptor = 0x07,
    GetConfiguration = 0x08,
    SetConfiguration = 0x09,
    GetInterface = 0x0a,
    SetInterface = 0x11,
    SynchFrame = 0x12,
}

/// RequestSetup is first part of control transfer buffer.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct UsbRequestSetup {
    // USB Device Request. USB spec. rev. 2.0 9.3
    pub request_type: u8, // bmRequestType
    pub request: u8,      // bRequest
    pub value: u16,       // wValue
    pub index: u16,       // wIndex
    pub length: u16,      // wLength
}

fn _assert() {
    const_assert!(size_of::<UsbRequestSetup>() == 8);
}

unsafe impl DataInit for UsbRequestSetup {}

impl UsbRequestSetup {
    pub fn new(
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        length: u16,
    ) -> UsbRequestSetup {
        UsbRequestSetup {
            request_type,
            request,
            value,
            index,
            length,
        }
    }

    /// Get type of request.
    pub fn get_type(&self) -> ControlRequestType {
        let ty = (self.request_type & CONTROL_REQUEST_TYPE) >> CONTROL_REQUEST_TYPE_OFFSET;
        match ty {
            0 => ControlRequestType::Standard,
            1 => ControlRequestType::Class,
            2 => ControlRequestType::Vendor,
            _ => ControlRequestType::Reserved,
        }
    }

    /// Get request direction.
    pub fn get_direction(&self) -> ControlRequestDataPhaseTransferDirection {
        let dir = (self.request_type & DATA_PHASE_DIRECTION) >> DATA_PHASE_DIRECTION_OFFSET;
        match dir {
            0 => ControlRequestDataPhaseTransferDirection::HostToDevice,
            _ => ControlRequestDataPhaseTransferDirection::DeviceToHost,
        }
    }

    /// Get recipient of this control transfer.
    pub fn get_recipient(&self) -> ControlRequestRecipient {
        let recipient = self.request_type & REQUEST_RECIPIENT_TYPE;
        match recipient {
            0 => ControlRequestRecipient::Device,
            1 => ControlRequestRecipient::Interface,
            2 => ControlRequestRecipient::Endpoint,
            3 => ControlRequestRecipient::Other,
            _ => ControlRequestRecipient::Reserved,
        }
    }

    /// Return the type of standard control request.
    pub fn get_standard_request(&self) -> Option<StandardControlRequest> {
        if self.get_type() != ControlRequestType::Standard {
            return None;
        }
        match self.request {
            0x00 => Some(StandardControlRequest::GetStatus),
            0x01 => Some(StandardControlRequest::ClearFeature),
            0x03 => Some(StandardControlRequest::SetFeature),
            0x05 => Some(StandardControlRequest::SetAddress),
            0x06 => Some(StandardControlRequest::GetDescriptor),
            0x07 => Some(StandardControlRequest::SetDescriptor),
            0x08 => Some(StandardControlRequest::GetConfiguration),
            0x09 => Some(StandardControlRequest::SetConfiguration),
            0x0a => Some(StandardControlRequest::GetInterface),
            0x11 => Some(StandardControlRequest::SetInterface),
            0x12 => Some(StandardControlRequest::SynchFrame),
            _ => None,
        }
    }
}

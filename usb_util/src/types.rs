// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem::size_of;

use static_assertions::const_assert;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

/// Standard USB descriptor types.
pub enum DescriptorType {
    Device = 0x01,
    Configuration = 0x02,
    Interface = 0x04,
    Endpoint = 0x05,
}

/// Trait describing USB descriptors.
pub trait Descriptor {
    /// Get the expected bDescriptorType value for this type of descriptor.
    fn descriptor_type() -> DescriptorType;
}

/// Standard USB descriptor header common to all descriptor types.
#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, Default, FromZeroes, FromBytes, AsBytes)]
#[repr(C, packed)]
pub struct DescriptorHeader {
    pub bLength: u8,
    pub bDescriptorType: u8,
}

fn _assert_descriptor_header() {
    const_assert!(size_of::<DescriptorHeader>() == 2);
}

/// Standard USB device descriptor as defined in USB 2.0 chapter 9,
/// not including the standard header.
#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, Default, FromZeroes, FromBytes, AsBytes)]
#[repr(C, packed)]
pub struct DeviceDescriptor {
    pub bcdUSB: u16,
    pub bDeviceClass: u8,
    pub bDeviceSubClass: u8,
    pub bDeviceProtocol: u8,
    pub bMaxPacketSize0: u8,
    pub idVendor: u16,
    pub idProduct: u16,
    pub bcdDevice: u16,
    pub iManufacturer: u8,
    pub iProduct: u8,
    pub iSerialNumber: u8,
    pub bNumConfigurations: u8,
}

impl Descriptor for DeviceDescriptor {
    fn descriptor_type() -> DescriptorType {
        DescriptorType::Device
    }
}

fn _assert_device_descriptor() {
    const_assert!(size_of::<DeviceDescriptor>() == 18 - 2);
}

/// Standard USB configuration descriptor as defined in USB 2.0 chapter 9,
/// not including the standard header.
#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, Default, FromZeroes, FromBytes, AsBytes)]
#[repr(C, packed)]
pub struct ConfigDescriptor {
    pub wTotalLength: u16,
    pub bNumInterfaces: u8,
    pub bConfigurationValue: u8,
    pub iConfiguration: u8,
    pub bmAttributes: u8,
    pub bMaxPower: u8,
}

impl Descriptor for ConfigDescriptor {
    fn descriptor_type() -> DescriptorType {
        DescriptorType::Configuration
    }
}

fn _assert_config_descriptor() {
    const_assert!(size_of::<ConfigDescriptor>() == 9 - 2);
}

impl ConfigDescriptor {
    pub fn num_interfaces(&self) -> u8 {
        self.bNumInterfaces
    }
}

/// Standard USB interface descriptor as defined in USB 2.0 chapter 9,
/// not including the standard header.
#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, Default, FromZeroes, FromBytes, AsBytes)]
#[repr(C, packed)]
pub struct InterfaceDescriptor {
    pub bInterfaceNumber: u8,
    pub bAlternateSetting: u8,
    pub bNumEndpoints: u8,
    pub bInterfaceClass: u8,
    pub bInterfaceSubClass: u8,
    pub bInterfaceProtocol: u8,
    pub iInterface: u8,
}

impl Descriptor for InterfaceDescriptor {
    fn descriptor_type() -> DescriptorType {
        DescriptorType::Interface
    }
}

fn _assert_interface_descriptor() {
    const_assert!(size_of::<InterfaceDescriptor>() == 9 - 2);
}

/// Standard USB endpoint descriptor as defined in USB 2.0 chapter 9,
/// not including the standard header.
#[allow(non_snake_case)]
#[derive(Copy, Clone, Debug, Default, FromZeroes, FromBytes, AsBytes)]
#[repr(C, packed)]
pub struct EndpointDescriptor {
    pub bEndpointAddress: u8,
    pub bmAttributes: u8,
    pub wMaxPacketSize: u16,
    pub bInterval: u8,
}

impl Descriptor for EndpointDescriptor {
    fn descriptor_type() -> DescriptorType {
        DescriptorType::Endpoint
    }
}

fn _assert_endpoint_descriptor() {
    const_assert!(size_of::<EndpointDescriptor>() == 7 - 2);
}

const ENDPOINT_DESCRIPTOR_DIRECTION_MASK: u8 = 1 << 7;
const ENDPOINT_DESCRIPTOR_NUMBER_MASK: u8 = 0xf;
const ENDPOINT_DESCRIPTOR_ATTRIBUTES_TYPE_MASK: u8 = 0x3;

/// Endpoint types.
#[derive(PartialEq, Eq)]
pub enum EndpointType {
    Control,
    Isochronous,
    Bulk,
    Interrupt,
}

/// Endpoint Directions.
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum EndpointDirection {
    HostToDevice = 0,
    DeviceToHost = 1,
}
/// Endpoint direction offset.
pub const ENDPOINT_DIRECTION_OFFSET: u8 = 7;

impl EndpointDescriptor {
    // Get direction of this endpoint.
    pub fn get_direction(&self) -> EndpointDirection {
        let direction = self.bEndpointAddress & ENDPOINT_DESCRIPTOR_DIRECTION_MASK;
        if direction != 0 {
            EndpointDirection::DeviceToHost
        } else {
            EndpointDirection::HostToDevice
        }
    }

    // Get endpoint number.
    pub fn get_endpoint_number(&self) -> u8 {
        self.bEndpointAddress & ENDPOINT_DESCRIPTOR_NUMBER_MASK
    }

    // Get endpoint type.
    pub fn get_endpoint_type(&self) -> Option<EndpointType> {
        let ep_type = self.bmAttributes & ENDPOINT_DESCRIPTOR_ATTRIBUTES_TYPE_MASK;
        match ep_type {
            0 => Some(EndpointType::Control),
            1 => Some(EndpointType::Isochronous),
            2 => Some(EndpointType::Bulk),
            3 => Some(EndpointType::Interrupt),
            _ => None,
        }
    }
}

/// Offset of data phase transfer direction.
pub const DATA_PHASE_DIRECTION_OFFSET: u8 = 7;
/// Bit mask of data phase transfer direction.
pub const DATA_PHASE_DIRECTION: u8 = 1u8 << DATA_PHASE_DIRECTION_OFFSET;
// Types of data phase transfer directions.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum ControlRequestDataPhaseTransferDirection {
    HostToDevice = 0,
    DeviceToHost = 1,
}

/// Offset of control request type.
pub const CONTROL_REQUEST_TYPE_OFFSET: u8 = 5;
/// Bit mask of control request type.
pub const CONTROL_REQUEST_TYPE: u8 = 0b11 << CONTROL_REQUEST_TYPE_OFFSET;
/// Request types.
#[derive(PartialEq, Eq)]
pub enum ControlRequestType {
    Standard = 0,
    Class = 1,
    Vendor = 2,
    Reserved = 3,
}

/// Recipient type bits.
pub const REQUEST_RECIPIENT_TYPE: u8 = 0b1111;
/// Recipient type of control request.
#[derive(PartialEq, Eq)]
pub enum ControlRequestRecipient {
    Device = 0,
    Interface = 1,
    Endpoint = 2,
    Other = 3,
    Reserved,
}

/// Standard request defined in usb spec.
#[derive(PartialEq, Eq)]
pub enum StandardControlRequest {
    GetStatus = 0,
    ClearFeature = 1,
    SetFeature = 3,
    SetAddress = 5,
    GetDescriptor = 6,
    SetDescriptor = 7,
    GetConfiguration = 8,
    SetConfiguration = 9,
    GetInterface = 10,
    SetInterface = 11,
    SynchFrame = 12,
}

/// RequestSetup is first part of control transfer buffer.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, FromZeroes, FromBytes, AsBytes)]
pub struct UsbRequestSetup {
    // USB Device Request. USB spec. rev. 2.0 9.3
    pub request_type: u8, // bmRequestType
    pub request: u8,      // bRequest
    pub value: u16,       // wValue
    pub index: u16,       // wIndex
    pub length: u16,      // wLength
}

fn _assert_usb_request_setup() {
    const_assert!(size_of::<UsbRequestSetup>() == 8);
}

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
            // Defined in USB 2.0 Specification Table 9-4
            0 => Some(StandardControlRequest::GetStatus),
            1 => Some(StandardControlRequest::ClearFeature),
            3 => Some(StandardControlRequest::SetFeature),
            5 => Some(StandardControlRequest::SetAddress),
            6 => Some(StandardControlRequest::GetDescriptor),
            7 => Some(StandardControlRequest::SetDescriptor),
            8 => Some(StandardControlRequest::GetConfiguration),
            9 => Some(StandardControlRequest::SetConfiguration),
            10 => Some(StandardControlRequest::GetInterface),
            11 => Some(StandardControlRequest::SetInterface),
            12 => Some(StandardControlRequest::SynchFrame),
            _ => None,
        }
    }
}

/// Construct a bmRequestType value for a control request.
pub fn control_request_type(
    type_: ControlRequestType,
    dir: ControlRequestDataPhaseTransferDirection,
    recipient: ControlRequestRecipient,
) -> u8 {
    ((type_ as u8) << CONTROL_REQUEST_TYPE_OFFSET)
        | ((dir as u8) << DATA_PHASE_DIRECTION_OFFSET)
        | (recipient as u8)
}

/// USB device speed
pub enum DeviceSpeed {
    Full,
    Low,
    High,
    Super,
    SuperPlus,
}

#[cfg(test)]
#[allow(clippy::unusual_byte_groupings)]
mod tests {
    use super::*;

    #[test]
    fn control_request_types() {
        assert_eq!(
            control_request_type(
                ControlRequestType::Standard,
                ControlRequestDataPhaseTransferDirection::HostToDevice,
                ControlRequestRecipient::Device
            ),
            0b0_00_00000
        );
        assert_eq!(
            control_request_type(
                ControlRequestType::Standard,
                ControlRequestDataPhaseTransferDirection::DeviceToHost,
                ControlRequestRecipient::Device
            ),
            0b1_00_00000
        );
        assert_eq!(
            control_request_type(
                ControlRequestType::Standard,
                ControlRequestDataPhaseTransferDirection::HostToDevice,
                ControlRequestRecipient::Interface
            ),
            0b0_00_00001
        );
        assert_eq!(
            control_request_type(
                ControlRequestType::Class,
                ControlRequestDataPhaseTransferDirection::HostToDevice,
                ControlRequestRecipient::Device
            ),
            0b0_01_00000
        );
    }
}

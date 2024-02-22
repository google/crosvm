// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use usb_util::DescriptorType;

// How long it takes for the security key to become inactive and time out all previously pending
// transactions since last activity.
pub const TRANSACTION_TIMEOUT_MILLIS: u64 = 120_000;

// How long to wait before timing out and canceling a USB transfer from the guest if the host
// security key is unresponsive.
pub const USB_TRANSFER_TIMEOUT_MILLIS: u64 = 5_000;

// 5ms is the default USB interrupt polling rate according to specs.
pub const USB_POLL_RATE_MILLIS: u64 = 5;

// Some applications expect a very short RTT when handling packets between host key and guest, half
// a millisecond seems like a decent compromise.
pub const PACKET_POLL_RATE_NANOS: u64 = 50_000;

// Total max number of transactions we can hold in our key. Any more transactions will push older
// transactions away from the stack.
pub const MAX_TRANSACTIONS: usize = 4;

// Max number of incoming packets still to be processed by the guest
pub const U2FHID_MAX_IN_PENDING: usize = 32;

pub const U2FHID_PACKET_SIZE: usize = 64;
pub const PACKET_INIT_HEADER_SIZE: usize = 7;
pub const PACKET_CONT_HEADER_SIZE: usize = 5;
pub const PACKET_INIT_DATA_SIZE: usize = U2FHID_PACKET_SIZE - PACKET_INIT_HEADER_SIZE;
pub const PACKET_CONT_DATA_SIZE: usize = U2FHID_PACKET_SIZE - PACKET_CONT_HEADER_SIZE;
pub const BROADCAST_CID: u32 = 0xFFFFFFFF;

pub const NONCE_SIZE: usize = 8;
pub const EMPTY_NONCE: [u8; NONCE_SIZE] = [0u8; NONCE_SIZE];

// It's a valid init packet only if the 7th bit of the cmd field is set
pub const PACKET_INIT_VALID_CMD: u8 = 0b1000_0000;
pub const U2FHID_ERROR_CMD: u8 = 0xBF;

pub const U2FHID_CONTROL_ENDPOINT: u8 = 0x00;
pub const U2FHID_IN_ENDPOINT: u8 = 0x81;
pub const U2FHID_OUT_ENDPOINT: u8 = 0x01;

// Generic HID commands
pub const HID_GET_IDLE: u8 = 0x02;
pub const HID_SET_IDLE: u8 = 0x0A;
pub const HID_GET_REPORT_DESC: u8 = 0x22;

pub const HID_MAX_DESCRIPTOR_SIZE: usize = 4096;

// Descriptor data taken from: https://github.com/gl-sergei/u2f-token/blob/master/src/usb-hid.c
// With minor modifications for our own PID and VID and other strings
pub const U2FHID_DEVICE_DESC: &[u8] = &[
    18,
    DescriptorType::Device as u8,
    0x10,
    0x01,
    0x00,
    0x00,
    0x00,
    0x40,
    // Google Vendor ID
    0xd1,
    0x18,
    // Unique Product ID
    0xd0,
    0xf1,
    0x00,
    0x01,
    0,
    0,
    0,
    1,
];

pub const HID_REPORT_DESC_HEADER: &[u8] = &[
    0x06, 0xd0, 0xf1, // Usage Page (FIDO)
    0x09, 0x01, // Usage (FIDO)
];

pub const U2FHID_CONFIG_DESC: &[u8] = &[
    9,
    DescriptorType::Configuration as u8,
    /* Configuration Descriptor. */
    41,
    0x00, /* wTotalLength. */
    0x01, /* bNumInterfaces. */
    0x01, /* bConfigurationValue. */
    0,    /* iConfiguration. */
    0x80, /* bmAttributes. */
    15,   /* bMaxPower (100mA). */
    /* Interface Descriptor. */
    9, /* bLength: Interface Descriptor size */
    DescriptorType::Interface as u8,
    0,    /* bInterfaceNumber: Number of Interface */
    0x00, /* bAlternateSetting: Alternate setting */
    0x02, /* bNumEndpoints: Two endpoints used */
    0x03, /* bInterfaceClass: HID */
    0x00, /* bInterfaceSubClass: no boot */
    0x00, /* bInterfaceProtocol: 0=none */
    0x00, /* iInterface */
    /* HID Descriptor. */
    9,    /* bLength: HID Descriptor size */
    0x21, /* bDescriptorType: HID */
    0x10,
    0x01, /* bcdHID: HID Class Spec release number */
    0x00, /* bCountryCode: Hardware target country */
    0x01, /* bNumDescriptors: Number of HID class descriptors to follow */
    0x22, /* bDescriptorType */
    0x22,
    0, /* wItemLength: Total length of Report descriptor */
    /* Endpoint IN1 Descriptor */
    7, /* bLength: Endpoint Descriptor size */
    DescriptorType::Endpoint as u8,
    0x81, /* bEndpointAddress: (IN1) */
    0x03, /* bmAttributes: Interrupt */
    0x40,
    0x00, /* wMaxPacketSize: 64 */
    0x05, /* bInterval (5ms) */
    /* Endpoint OUT1 Descriptor */
    7, /* bLength: Endpoint Descriptor size */
    DescriptorType::Endpoint as u8,
    0x01, /* bEndpointAddress: (OUT1) */
    0x03, /* bmAttributes: Interrupt */
    0x40,
    0x00, /* wMaxPacketSize: 64 */
    0x05, /* bInterval (5ms) */
];

pub const HID_REPORT_DESC: &[u8] = &[
    0x06, 0xd0, 0xf1, /* USAGE_PAGE (FIDO Alliance) */
    0x09, 0x01, /* USAGE (Keyboard) */
    0xa1, 0x01, /* COLLECTION (Application) */
    0x09, 0x20, /* USAGE (Input report data) */
    0x15, 0x00, /* LOGICAL_MINIMUM (0) */
    0x26, 0xff, 0x00, /* LOGICAL_MAXIMUM (255) */
    0x75, 0x08, /* REPORT_SIZE (8) */
    0x95, 0x40, /* REPORT_COUNT (64) */
    0x81, 0x02, /* INPUT (Data,Var,Abs); Modifier byte */
    0x09, 0x21, /* USAGE (Output report data) */
    0x15, 0x00, /* LOGICAL_MINIMUM (0) */
    0x26, 0xff, 0x00, /* LOGICAL_MAXIMUM (255) */
    0x75, 0x08, /* REPORT_SIZE (8) */
    0x95, 0x40, /* REPORT_COUNT (64) */
    0x91, 0x02, /* OUTPUT (Data,Var,Abs); Modifier byte */
    0xc0, /* END_COLLECTION */
];

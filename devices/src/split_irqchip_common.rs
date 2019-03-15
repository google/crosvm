// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Common constants and types used for Split IRQ chip devices (e.g. PIC, PIT, IOAPIC).

use bit_field::*;

#[bitfield]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DestinationMode {
    Physical = 0,
    Logical = 1,
}

#[bitfield]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TriggerMode {
    Edge = 0,
    Level = 1,
}

#[derive(Clone, Copy, PartialEq)]
pub enum DeliveryMode {
    DeliveryModeFixed = 0b000,
    DeliveryModeLowest = 0b001,
    DeliveryModeSMI = 0b010,        // System management interrupt
    DeliveryModeRemoteRead = 0b011, // This is no longer supported by intel.
    DeliveryModeNMI = 0b100,        // Non maskable interrupt
    DeliveryModeInit = 0b101,
    DeliveryModeStartup = 0b110,
    DeliveryModeExternal = 0b111,
}

#[bitfield]
#[derive(Clone, Copy, PartialEq)]
pub struct MsiAddressMessageNonRemappable {
    reserved: BitField2,
    #[bits = 1]
    destination_mode: DestinationMode,
    redirection_hint: BitField1,
    reserved_2: BitField8,
    destination_id: BitField8,
    // According to Intel's implementation of MSI, these bits must always be 0xfee.
    always_0xfee: BitField12,
}

#[bitfield]
#[derive(Clone, Copy, PartialEq)]
pub struct MsiAddressMessageRemappable {
    reserved: BitField2,
    handle_hi: BitField1, // Bit 15 of handle
    shv: BitField1,
    interrupt_format: BitField1,
    handle_low: BitField15, // Bits 0-14 of handle.
    // According to Intel's implementation of MSI, these bits must always be 0xfee.
    always_0xfee: BitField12,
}

#[derive(Clone, Copy, PartialEq)]
pub enum MsiAddressMessage {
    NonRemappable(MsiAddressMessageNonRemappable),
    Remappable(MsiAddressMessageRemappable),
}

#[bitfield]
#[derive(Clone, Copy, PartialEq)]
struct MsiDataMessage {
    vector: BitField8,
    delivery_mode: BitField3,
    reserved: BitField3,
    level: BitField1,
    #[bits = 1]
    trigger: TriggerMode,
    reserved2: BitField16,
}

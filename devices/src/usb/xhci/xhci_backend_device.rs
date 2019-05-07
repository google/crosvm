// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::xhci_transfer::XhciTransfer;

/// Address of this usb device, as in Set Address standard usb device request.
pub type UsbDeviceAddress = u32;

/// The type USB device provided by the backend device.
#[derive(PartialEq, Eq)]
pub enum BackendType {
    Usb2,
    Usb3,
}

/// Xhci backend device is a virtual device connected to xHCI controller. It handles xhci transfers.
pub trait XhciBackendDevice: Send {
    /// Returns the type of USB device provided by this device.
    fn get_backend_type(&self) -> BackendType;
    /// Returns host bus number of this device.
    fn host_bus(&self) -> u8;
    /// Returns host address of this device.
    fn host_address(&self) -> u8;
    /// Get vendor id of this device.
    fn get_vid(&self) -> u16;
    /// Get product id of this device.
    fn get_pid(&self) -> u16;
    /// Submit a xhci transfer to backend.
    fn submit_transfer(&mut self, transfer: XhciTransfer) -> std::result::Result<(), ()>;
    /// Set address of this backend.
    fn set_address(&mut self, address: UsbDeviceAddress);
    /// Reset the backend device.
    fn reset(&mut self) -> std::result::Result<(), ()>;
}

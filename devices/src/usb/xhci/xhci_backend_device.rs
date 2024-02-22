// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use usb_util::DeviceSpeed;

use crate::usb::backend::error::Result;

/// Address of this usb device, as in Set Address standard usb device request.
pub type UsbDeviceAddress = u32;

/// The type USB device provided by the backend device.
#[derive(PartialEq, Eq)]
pub enum BackendType {
    Usb2,
    Usb3,
}

/// Xhci backend device is a virtual device connected to xHCI controller. It handles xhci transfers.
pub trait XhciBackendDevice: Send + Sync {
    /// Returns the type of USB device provided by this device.
    fn get_backend_type(&self) -> BackendType;
    /// Get vendor id of this device.
    fn get_vid(&self) -> u16;
    /// Get product id of this device.
    fn get_pid(&self) -> u16;
    /// Set address of this backend.
    fn set_address(&mut self, address: UsbDeviceAddress);
    /// Reset the backend device.
    fn reset(&mut self) -> Result<()>;
    /// Get speed of this device.
    fn get_speed(&self) -> Option<DeviceSpeed>;
    /// Allocate streams for the endpoint
    fn alloc_streams(&self, ep: u8, num_streams: u16) -> Result<()>;
    /// Free streams for the endpoint
    fn free_streams(&self, ep: u8) -> Result<()>;
    /// Stop the backend device, allowing it to execute cleanup routines.
    fn stop(&mut self);
}

// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::sync::Arc;

use sync::Mutex;
use usb_util::Device;

use crate::usb::backend::device::BackendDeviceType;
use crate::usb::backend::device::DeviceState;
use crate::usb::backend::error::Error;
use crate::usb::backend::error::Result;
use crate::usb::backend::host_backend::host_device::HostDevice;
use crate::usb::backend::utils::UsbUtilEventHandler;
use crate::utils::EventHandler;

/// Attaches a host device to the backend. This creates a host USB device object by opening a
/// usbdevfs file and returns a pair of the device and its fd event handler.
pub fn attach_host_backend_device(
    usb_file: File,
    device_state: DeviceState,
) -> Result<(Arc<Mutex<BackendDeviceType>>, Arc<dyn EventHandler>)> {
    let device = Device::new(usb_file).map_err(Error::CreateHostUsbDevice)?;
    let host_device = HostDevice::new(Arc::new(Mutex::new(device)), device_state)?;
    let device_impl = BackendDeviceType::HostDevice(host_device);
    let arc_mutex_device = Arc::new(Mutex::new(device_impl));

    let event_handler: Arc<dyn EventHandler> = Arc::new(UsbUtilEventHandler {
        device: arc_mutex_device.clone(),
    });

    Ok((arc_mutex_device, event_handler))
}

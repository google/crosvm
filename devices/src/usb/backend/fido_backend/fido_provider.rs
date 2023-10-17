// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::sync::Arc;

use sync::Mutex;

use crate::usb::backend::device::BackendDeviceType;
use crate::usb::backend::device::DeviceState;
use crate::usb::backend::error::Result;
use crate::usb::backend::fido_backend::fido_passthrough::FidoPassthroughDevice;
use crate::usb::backend::utils::UsbUtilEventHandler;
use crate::utils::EventHandler;
use crate::utils::EventLoop;

/// Utility function to attach a security key device to the backend provider. It initializes a
/// `FidoPassthroughDevice` and returns it with its `EventHandler` to the backend.
pub fn attach_security_key(
    _hidraw: File,
    event_loop: Arc<EventLoop>,
    device_state: DeviceState,
) -> Result<(Arc<Mutex<BackendDeviceType>>, Arc<dyn EventHandler>)> {
    // TODO: Create low-level FidoDevice and read hidraw file
    let passthrough_device = FidoPassthroughDevice::new(device_state, event_loop);
    let device_impl = BackendDeviceType::FidoDevice(passthrough_device);
    let arc_mutex_device = Arc::new(Mutex::new(device_impl));

    let event_handler: Arc<dyn EventHandler> = Arc::new(UsbUtilEventHandler {
        device: arc_mutex_device.clone(),
    });

    Ok((arc_mutex_device, event_handler))
}

// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::sync::Arc;

use anyhow::Context;
use sync::Mutex;
use usb_util::Device;

use crate::usb::backend::error::*;
use crate::utils::EventHandler;

struct UsbUtilEventHandler {
    device: Arc<Mutex<Device>>,
}

impl EventHandler for UsbUtilEventHandler {
    fn on_event(&self) -> anyhow::Result<()> {
        self.device
            .lock()
            .poll_transfers()
            .context("UsbUtilEventHandler poll_transfers failed")
    }
}

/// Attaches a host device to the backend. This creates a host USB device object by opening a
/// usbdevfs file and returns a pair of the device and its fd event handler.
pub fn attach_host_backend_device(
    usb_file: File,
) -> Result<(Arc<Mutex<Device>>, Arc<dyn EventHandler>)> {
    let device = Device::new(usb_file).map_err(Error::CreateHostUsbDevice)?;
    let arc_mutex_device = Arc::new(Mutex::new(device));

    let event_handler: Arc<dyn EventHandler> = Arc::new(UsbUtilEventHandler {
        device: arc_mutex_device.clone(),
    });

    Ok((arc_mutex_device, event_handler))
}

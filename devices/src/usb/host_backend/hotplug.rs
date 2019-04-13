// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use crate::usb::xhci::usb_hub::UsbHub;
use sys_util::error;
use usb_util::hotplug::{HotplugEvent, UsbHotplugHandler};
use usb_util::libusb_device::LibUsbDevice;

pub struct HotplugHandler {
    hub: Arc<UsbHub>,
}

impl HotplugHandler {
    pub fn new(hub: Arc<UsbHub>) -> Self {
        HotplugHandler { hub }
    }
}

impl UsbHotplugHandler for HotplugHandler {
    fn hotplug_event(&self, device: LibUsbDevice, event: HotplugEvent) {
        if event != HotplugEvent::DeviceLeft {
            return;
        }

        let bus = device.get_bus_number();
        let address = device.get_address();
        let descriptor = match device.get_device_descriptor() {
            Ok(d) => d,
            Err(e) => {
                error!("cannot get device descriptor: {:?}", e);
                return;
            }
        };
        let vid = descriptor.idVendor;
        let pid = descriptor.idProduct;

        if let Err(e) = self.hub.try_detach(bus, address, vid, pid) {
            error!("device left event triggered failed detach from hub: {}", e);
            return;
        }
    }
}

// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::raw::{c_int, c_void};
use std::sync::Arc;

use crate::bindings;
use crate::libusb_context::LibUsbContextInner;
use crate::libusb_device::LibUsbDevice;

#[derive(PartialEq)]
pub enum HotplugEvent {
    DeviceArrived,
    DeviceLeft,
}

impl HotplugEvent {
    /// Create a new HotplugEvent from raw libusb_hotplug_event.
    pub fn new(event: bindings::libusb_hotplug_event) -> Self {
        match event {
            bindings::LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED => HotplugEvent::DeviceArrived,
            bindings::LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT => HotplugEvent::DeviceLeft,
            _ => {
                // TODO(jkwang) handle this with option.
                // libusb_hotplug_event is a C enum.
                panic!("Invaild libusb_hotplug_event");
            }
        }
    }
}

pub trait UsbHotplugHandler: Send + Sync + 'static {
    fn hotplug_event(&self, device: LibUsbDevice, event: HotplugEvent);
}

/// UsbHotplugHandlerHolder owns UsbHotplugHandler and LibUsbContext. It will be passed as
/// user_data to libusb_hotplug_register_callback.
pub struct UsbHotplugHandlerHolder {
    context: Arc<LibUsbContextInner>,
    handler: Box<dyn UsbHotplugHandler>,
}

impl UsbHotplugHandlerHolder {
    /// Create UsbHotplugHandlerHodler from context and handler.
    pub fn new<H: UsbHotplugHandler>(
        context: Arc<LibUsbContextInner>,
        handler: H,
    ) -> Box<UsbHotplugHandlerHolder> {
        let holder = UsbHotplugHandlerHolder {
            context,
            handler: Box::new(handler),
        };
        Box::new(holder)
    }
}

/// This function is safe when:
///     libusb_device is allocated by libusb
///     user_data points to valid UsbHotPlugHandlerHolder released from Box.
///
/// Do not invoke this function. It should only be used as a callback for
/// libusb_hotplug_register_callback.
pub unsafe extern "C" fn hotplug_cb(
    _: *mut bindings::libusb_context,
    device: *mut bindings::libusb_device,
    event: bindings::libusb_hotplug_event,
    user_data: *mut c_void,
) -> c_int {
    // Safe because user_data was casted from holder.
    let holder = &*(user_data as *mut UsbHotplugHandlerHolder);
    let device = LibUsbDevice::new(holder.context.clone(), device);
    let event = HotplugEvent::new(event);
    holder.handler.hotplug_event(device, event);
    // The handler should always succeed.
    bindings::LIBUSB_SUCCESS
}

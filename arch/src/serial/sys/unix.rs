// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use base::RawDescriptor;
use devices::serial_device::SerialParameters;
use devices::Bus;
use devices::BusDevice;
use devices::ProxyDevice;
use devices::Serial;
use minijail::Minijail;
use sync::Mutex;

use crate::serial::SERIAL_ADDR;
use crate::DeviceRegistrationError;

pub fn add_serial_device(
    com_num: usize,
    com: Serial,
    _serial_parameters: &SerialParameters,
    serial_jail: Option<Minijail>,
    preserved_descriptors: Vec<RawDescriptor>,
    io_bus: &Bus,
    #[cfg(feature = "swap")] swap_controller: &mut Option<swap::SwapController>,
) -> std::result::Result<(), DeviceRegistrationError> {
    let com: Arc<Mutex<dyn BusDevice>> = if let Some(serial_jail) = serial_jail {
        Arc::new(Mutex::new(
            ProxyDevice::new(
                com,
                serial_jail,
                preserved_descriptors,
                #[cfg(feature = "swap")]
                swap_controller,
            )
            .map_err(DeviceRegistrationError::ProxyDeviceCreation)?,
        ))
    } else {
        Arc::new(Mutex::new(com))
    };
    io_bus.insert(com, SERIAL_ADDR[com_num], 0x8).unwrap();
    Ok(())
}

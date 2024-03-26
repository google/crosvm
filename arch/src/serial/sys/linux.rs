// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use base::RawDescriptor;
use devices::serial_device::SerialParameters;
use devices::BusDevice;
use devices::ProxyDevice;
use devices::Serial;
use minijail::Minijail;
use sync::Mutex;

use crate::DeviceRegistrationError;

pub fn add_serial_device(
    com: Serial,
    _serial_parameters: &SerialParameters,
    serial_jail: Option<Minijail>,
    preserved_descriptors: Vec<RawDescriptor>,
    #[cfg(feature = "swap")] swap_controller: &mut Option<swap::SwapController>,
) -> std::result::Result<Arc<Mutex<dyn BusDevice>>, DeviceRegistrationError> {
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
    Ok(com)
}

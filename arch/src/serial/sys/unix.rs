// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use base::RawDescriptor;
use devices::serial_device::SerialParameters;
use devices::BusDevice;
#[cfg(any(target_os = "android", target_os = "linux"))]
use devices::ProxyDevice;
use devices::Serial;
#[cfg(any(target_os = "android", target_os = "linux"))]
use minijail::Minijail;
#[cfg(target_os = "macos")]
use jail::FakeMinijailStub as Minijail;
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
        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
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
        }
        #[cfg(target_os = "macos")]
        {
            // macOS uses FakeMinijailStub, so this branch should never be reached.
            // If it is, just wrap the device directly.
            let _ = serial_jail;
            let _ = preserved_descriptors;
            Arc::new(Mutex::new(com))
        }
    } else {
        Arc::new(Mutex::new(com))
    };
    Ok(com)
}

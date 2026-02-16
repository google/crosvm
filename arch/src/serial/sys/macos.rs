// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use base::RawDescriptor;
use devices::serial_device::SerialParameters;
use devices::BusDevice;
use devices::Serial;
use jail::FakeMinijailStub as Minijail;
use sync::Mutex;

use crate::DeviceRegistrationError;

pub fn add_serial_device(
    com: Serial,
    _serial_parameters: &SerialParameters,
    _serial_jail: Option<Minijail>,
    _preserved_descriptors: Vec<RawDescriptor>,
    #[cfg(feature = "swap")] _swap_controller: &mut Option<swap::SwapController>,
) -> std::result::Result<Arc<Mutex<dyn BusDevice>>, DeviceRegistrationError> {
    // macOS does not support jailing, so just wrap the device directly.
    Ok(Arc::new(Mutex::new(com)))
}

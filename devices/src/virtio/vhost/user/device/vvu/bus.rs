// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides utilities to bind and open a VFIO PCI device.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use sync::Mutex;

use crate::vfio::VfioContainer;
use crate::vfio::VfioDevice;

/// Opens device with given sysfs path as `VfioDevice`.
pub fn open_vfio_device<P: AsRef<Path>>(vfio_path: &P) -> Result<VfioDevice> {
    let vfio_container = Arc::new(Mutex::new(VfioContainer::new()?));
    VfioDevice::new(vfio_path, vfio_container).context("failed to create VFIO device")
}

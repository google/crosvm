// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides utilities to bind and open a VFIO PCI device.

use std::sync::Arc;

use anyhow::{Context, Result};
use sync::Mutex;

use crate::pci::PciAddress;
use crate::vfio::{VfioContainer, VfioDevice};

/// Opens the PCI device as `VfioDevice`.
pub fn open_vfio_device(pci_address: PciAddress) -> Result<VfioDevice> {
    // Convert the PCI address to "DDDD:bb:dd.f" format.
    let addr_str = pci_address.to_string();
    let vfio_path = format!("/sys/bus/pci/devices/{}", &addr_str);
    let vfio_container = Arc::new(Mutex::new(VfioContainer::new()?));
    VfioDevice::new(&vfio_path, vfio_container).context("failed to create VFIO device")
}

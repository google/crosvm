// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides utilities to bind and open a VFIO PCI device.

use std::fs::write;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use sync::Mutex;

use crate::pci::PciAddress;
use crate::vfio::{VfioContainer, VfioDevice};

/// Opens the PCI device as `VfioDevice`.
pub fn open_vfio_device(pci_address: PciAddress) -> Result<VfioDevice> {
    // Convert the PCI address to "DDDD:bb:dd.f" format.
    let addr_str = pci_address.to_string();

    // Unbind virtio-pci from the device.
    write("/sys/bus/pci/drivers/virtio-pci/unbind", &addr_str)
        .context("failed to unbind as virtio-pci device")?;

    // Set "vfio-pci" for the driver so the device can be bound to our vfio driver.
    write(
        format!("/sys/bus/pci/devices/{}/driver_override", &addr_str),
        "vfio-pci\n",
    )
    .context("failed to override driver")?;

    // Bind the device to the driver.
    write("/sys/bus/pci/drivers/vfio-pci/bind", &addr_str).context("failed to bind VFIO device")?;

    // Write the empty string to driver_override to return the device to standard matching rules
    // binding. Note that this operation won't unbind the current driver or load a new driver.
    write(
        format!("/sys/bus/pci/devices/{}/driver_override", &addr_str),
        "",
    )
    .context("failed to clear driver_override")?;

    let vfio_path = format!("/sys/bus/pci/devices/{}", &addr_str);
    let vfio_container = Arc::new(Mutex::new(VfioContainer::new()?));
    let vfio = VfioDevice::new(&vfio_path, vfio_container)
        .map_err(|e| anyhow!("failed to create VFIO device: {}", e))?;
    Ok(vfio)
}

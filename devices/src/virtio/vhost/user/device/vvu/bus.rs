// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides utilities to bind and open a VFIO PCI device.

#![allow(dead_code)]

use std::fs::write;
use std::sync::Arc;

use anyhow::{anyhow, bail, ensure, Context, Result};
use sync::Mutex;

use crate::vfio::{VfioContainer, VfioDevice};

#[derive(PartialEq, Eq, Debug)]
pub struct PciSlot {
    domain: u16,
    bus: u8,
    slot: u8,
    func: u8,
}

impl std::fmt::Display for PciSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:04x}:{:02x}:{:02x}.{}",
            self.domain, self.bus, self.slot, self.func
        )
    }
}

impl PciSlot {
    /// Creates a new `PciSlot` instance by parsing the given string which is of the form of
    /// `<domain>:<bus>:<slot>.<func>`, which is same as ones that
    /// [`lspci -s`](https://man7.org/linux/man-pages/man8/lspci.8.html) expects but we don't
    /// allow omitting 0s.
    pub fn new(s: &str) -> Result<Self> {
        let v: Vec<_> = s.split('.').collect();
        if v.len() != 2 {
            bail!("PCI slot must be specified like <domain>:<bus>:<slot>.<func>, but the number of '.' is incorrect: {}", s);
        }
        let func = u8::from_str_radix(v[1], 16).context("failed to parse func")?;

        let v2: Vec<_> = v[0].split(':').collect();
        if v2.len() != 3 {
            bail!("PCI slot must be specified like <domain>:<bus>:<slot>.<func>, but the number of ':' is incorrect: {}", s);
        }

        let domain = u16::from_str_radix(v2[0], 16).context("failed to parse domain")?;
        let bus = u8::from_str_radix(v2[1], 16).context("failed to parse bus")?;
        let slot = u8::from_str_radix(v2[2], 16).context("failed to parse slot")?;

        let pci_slot = Self {
            domain,
            bus,
            slot,
            func,
        };

        pci_slot.validate()?;
        Ok(pci_slot)
    }

    fn validate(&self) -> Result<()> {
        // domains (0 to ffff), bus (0 to ff), slot (0 to 1f) and function (0 to 7).
        ensure!(
            self.slot <= 0x1f,
            "slot must be in [0x00, 0x1f] but 0x{:x}",
            self.slot
        );
        ensure!(self.func <= 7, "func must be in [0, 7] but {}", self.func);
        Ok(())
    }

    /// Opens the PCI device as `VfioDevice`.
    pub fn open(&self) -> Result<VfioDevice> {
        // Unbind virtio-pci from the device.
        write("/sys/bus/pci/drivers/virtio-pci/unbind", self.to_string())
            .context("failed to unbind as virtio-pci device")?;

        // Set "vfio-pci" for the driver so the device can be bound to our vfio driver.
        write(
            format!("/sys/bus/pci/devices/{}/driver_override", self),
            "vfio-pci\n",
        )
        .context("failed to override driver")?;

        // Bind the device to the driver.
        write("/sys/bus/pci/drivers/vfio-pci/bind", self.to_string())
            .context("failed to bind VFIO device")?;

        // Write the empty string to driver_override to return the device to standard matching rules
        // binding. Note that this operation won't unbind the current driver or load a new driver.
        write(format!("/sys/bus/pci/devices/{}/driver_override", self), "")
            .context("failed to clear driver_override")?;

        let vfio_path = format!("/sys/bus/pci/devices/{}", self.to_string());
        // TODO(b/202151642): Use `VfioContainer::new()` once virtio-iommu for VFIO is implemented.
        let vfio_container = Arc::new(Mutex::new(VfioContainer::new_noiommu()?));
        let vfio = VfioDevice::new(&vfio_path, vfio_container)
            .map_err(|e| anyhow!("failed to create VFIO device: {}", e))?;
        Ok(vfio)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pci_slot_new() {
        assert_eq!(
            PciSlot::new("abcd:ef:12.3").unwrap(),
            PciSlot {
                domain: 0xabcd,
                bus: 0xef,
                slot: 0x12,
                func: 0x3,
            }
        );

        // 'ff' is too big for slot.
        assert!(PciSlot::new("ffff:ff:ff.0").is_err());
    }
}

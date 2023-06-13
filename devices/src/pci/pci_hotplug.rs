// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Trait definitions for PCI hotplug.

#![deny(missing_docs)]

use crate::PciAddress;
use crate::PciDevice;
use crate::PciDeviceError;

pub type Result<T> = std::result::Result<T, PciDeviceError>;

/// Additional requirements for a PciDevice to support hotplug.
/// A hotplug device can be configured without access to the SystemAllocator.
pub trait HotPluggable: PciDevice {
    /// Sets PciAddress to pci_addr. Replaces allocate_address.
    fn set_pci_address(&mut self, pci_addr: PciAddress) -> Result<()>;

    /// Configures IO BAR layout without memory alloc. Replaces allocate_io_bars.
    fn configure_io_bars(&mut self) -> Result<()>;

    /// Configure device BAR layout without memory alloc. Replaces allocate_device_bars.
    fn configure_device_bars(&mut self) -> Result<()>;
}

impl<T: HotPluggable + ?Sized> HotPluggable for Box<T> {
    fn set_pci_address(&mut self, pci_addr: PciAddress) -> Result<()> {
        (**self).set_pci_address(pci_addr)
    }

    fn configure_io_bars(&mut self) -> Result<()> {
        (**self).configure_io_bars()
    }

    fn configure_device_bars(&mut self) -> Result<()> {
        (**self).configure_device_bars()
    }
}

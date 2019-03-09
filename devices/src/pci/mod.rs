// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements pci devices and busses.

mod ac97;
mod ac97_bus_master;
mod ac97_mixer;
mod ac97_regs;
mod pci_configuration;
mod pci_device;
mod pci_root;

pub use self::ac97::Ac97Dev;
pub use self::pci_configuration::{
    PciBarConfiguration, PciBarPrefetchable, PciBarRegionType, PciCapability, PciCapabilityID,
    PciClassCode, PciConfiguration, PciHeaderType, PciProgrammingInterface, PciSerialBusSubClass,
    PciSubclass,
};
pub use self::pci_device::Error as PciDeviceError;
pub use self::pci_device::PciDevice;
pub use self::pci_root::{PciConfigIo, PciConfigMmio, PciRoot};

/// PCI has four interrupt pins A->D.
#[derive(Copy, Clone)]
pub enum PciInterruptPin {
    IntA,
    IntB,
    IntC,
    IntD,
}

impl PciInterruptPin {
    pub fn to_mask(self) -> u32 {
        self as u32
    }
}

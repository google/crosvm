// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements pci devices and busses.

#[cfg(feature = "audio")]
mod ac97;
#[cfg(feature = "audio")]
mod ac97_bus_master;
#[cfg(feature = "audio")]
mod ac97_mixer;
#[cfg(feature = "audio")]
mod ac97_regs;
mod msix;
mod pci_configuration;
mod pci_device;
mod pci_root;
mod vfio_pci;

#[cfg(feature = "audio")]
pub use self::ac97::{Ac97Backend, Ac97Dev, Ac97Parameters};
pub use self::msix::{MsixCap, MsixConfig, MsixStatus};
pub use self::pci_configuration::{
    PciBarConfiguration, PciBarPrefetchable, PciBarRegionType, PciCapability, PciCapabilityID,
    PciClassCode, PciConfiguration, PciDisplaySubclass, PciHeaderType, PciProgrammingInterface,
    PciSerialBusSubClass, PciSubclass,
};
pub use self::pci_device::Error as PciDeviceError;
pub use self::pci_device::PciDevice;
pub use self::pci_root::{PciAddress, PciConfigIo, PciConfigMmio, PciRoot};
pub use self::vfio_pci::VfioPciDevice;

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

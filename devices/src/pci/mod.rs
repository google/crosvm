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
mod coiommu;
mod msix;
mod pci_address;
mod pci_configuration;
mod pci_device;
mod pci_root;
mod pcie;
mod pvpanic;
mod stub;
mod vfio_pci;

#[cfg(feature = "audio")]
pub use self::ac97::{Ac97Backend, Ac97Dev, Ac97Parameters};
pub use self::coiommu::{CoIommuDev, CoIommuParameters, CoIommuUnpinPolicy};
pub use self::msix::{MsixCap, MsixConfig, MsixStatus};
pub use self::pci_address::Error as PciAddressError;
pub use self::pci_address::PciAddress;
pub use self::pci_configuration::{
    PciBarConfiguration, PciBarIndex, PciBarPrefetchable, PciBarRegionType, PciCapability,
    PciCapabilityID, PciClassCode, PciConfiguration, PciDisplaySubclass, PciHeaderType,
    PciProgrammingInterface, PciSerialBusSubClass, PciSubclass, CAPABILITY_LIST_HEAD_OFFSET,
};
pub use self::pci_device::{BarRange, Error as PciDeviceError, PciDevice};
pub use self::pci_root::{PciConfigIo, PciConfigMmio, PciRoot, PciVirtualConfigMmio};
pub use self::pcie::{PciBridge, PcieHostRootPort, PcieRootPort};
pub use self::pvpanic::{PvPanicCode, PvPanicPciDevice};
pub use self::stub::{StubPciDevice, StubPciParameters};
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

pub const PCI_VENDOR_ID_INTEL: u16 = 0x8086;
pub const PCI_VENDOR_ID_REDHAT: u16 = 0x1b36;

/// A wrapper structure for pci device and vendor id.
#[derive(Copy, Clone)]
pub struct PciId {
    vendor_id: u16,
    device_id: u16,
}

impl PciId {
    pub fn new(vendor_id: u16, device_id: u16) -> Self {
        Self {
            vendor_id,
            device_id,
        }
    }
}

impl From<PciId> for u32 {
    fn from(pci_id: PciId) -> Self {
        // vendor ID is the lower 16 bits and device id is the upper 16 bits
        pci_id.vendor_id as u32 | (pci_id.device_id as u32) << 16
    }
}

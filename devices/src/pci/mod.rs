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
#[cfg(unix)]
mod coiommu;
mod msi;
mod msix;
mod pci_address;
mod pci_configuration;
mod pci_device;
mod pci_root;
#[cfg(unix)]
mod pcie;
mod pvpanic;
mod stub;
#[cfg(unix)]
mod vfio_pci;

use libc::EINVAL;

#[cfg(feature = "audio")]
pub use self::ac97::{Ac97Backend, Ac97Dev, Ac97Parameters};
#[cfg(unix)]
pub use self::coiommu::{CoIommuDev, CoIommuParameters, CoIommuUnpinPolicy};
pub use self::msi::MsiConfig;
pub use self::msix::{MsixCap, MsixConfig, MsixStatus};
pub use self::pci_address::Error as PciAddressError;
pub use self::pci_address::PciAddress;
pub use self::pci_configuration::{
    PciBarConfiguration, PciBarIndex, PciBarPrefetchable, PciBarRegionType, PciCapability,
    PciCapabilityID, PciClassCode, PciConfiguration, PciDisplaySubclass, PciHeaderType,
    PciProgrammingInterface, PciSerialBusSubClass, PciSubclass, CAPABILITY_LIST_HEAD_OFFSET,
};
pub use self::pci_device::{BarRange, Error as PciDeviceError, PciBus, PciDevice};
pub use self::pci_root::{PciConfigIo, PciConfigMmio, PciRoot, PciVirtualConfigMmio};
#[cfg(unix)]
pub use self::pcie::{PciBridge, PcieHostPort, PcieRootPort};
pub use self::pvpanic::{PvPanicCode, PvPanicPciDevice};
pub use self::stub::{StubPciDevice, StubPciParameters};
#[cfg(unix)]
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

#[repr(u16)]
#[derive(Debug, Clone, PartialEq)]
pub enum CrosvmDeviceId {
    Pit = 1,
    Pic = 2,
    Ioapic = 3,
    Serial = 4,
    Cmos = 5,
    I8042 = 6,
    Pl030 = 7,
    ACPIPMResource = 8,
    GoldfishBattery = 9,
    DebugConsole = 10,
    ProxyDevice = 11,
    VfioPlatformDevice = 12,
    DirectGsi = 13,
    DirectIo = 14,
    DirectMmio = 15,
    UserspaceIrqChip = 16,
}

impl TryFrom<u16> for CrosvmDeviceId {
    type Error = base::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(CrosvmDeviceId::Pit),
            2 => Ok(CrosvmDeviceId::Pic),
            3 => Ok(CrosvmDeviceId::Ioapic),
            4 => Ok(CrosvmDeviceId::Serial),
            5 => Ok(CrosvmDeviceId::Cmos),
            6 => Ok(CrosvmDeviceId::I8042),
            7 => Ok(CrosvmDeviceId::Pl030),
            8 => Ok(CrosvmDeviceId::ACPIPMResource),
            9 => Ok(CrosvmDeviceId::GoldfishBattery),
            10 => Ok(CrosvmDeviceId::DebugConsole),
            11 => Ok(CrosvmDeviceId::ProxyDevice),
            12 => Ok(CrosvmDeviceId::VfioPlatformDevice),
            13 => Ok(CrosvmDeviceId::DirectGsi),
            14 => Ok(CrosvmDeviceId::DirectMmio),
            15 => Ok(CrosvmDeviceId::DirectIo),
            16 => Ok(CrosvmDeviceId::UserspaceIrqChip),
            _ => Err(base::Error::new(EINVAL)),
        }
    }
}

/// A wrapper structure for pci device and vendor id.
#[derive(Debug, Copy, Clone, PartialEq)]
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

impl From<u32> for PciId {
    fn from(value: u32) -> Self {
        let vendor_id = (value & 0xFFFF) as u16;
        let device_id = (value >> 16) as u16;
        Self::new(vendor_id, device_id)
    }
}

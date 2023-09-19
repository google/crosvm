// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements pci devices and busses.

mod acpi;
#[cfg(any(target_os = "android", target_os = "linux"))]
mod coiommu;
mod msi;
mod msix;
mod pci_address;
mod pci_configuration;
mod pci_device;
#[cfg(feature = "pci-hotplug")]
mod pci_hotplug;
mod pci_root;
#[cfg(any(target_os = "android", target_os = "linux"))]
mod pcie;
pub mod pm;
mod pvpanic;
mod stub;
#[cfg(any(target_os = "android", target_os = "linux"))]
mod vfio_pci;

use libc::EINVAL;
use serde::Deserialize;
use serde::Serialize;

pub use self::acpi::DeviceVcfgRegister;
pub use self::acpi::DsmMethod;
pub use self::acpi::GpeScope;
pub use self::acpi::PowerResourceMethod;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use self::coiommu::CoIommuDev;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use self::coiommu::CoIommuParameters;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use self::coiommu::CoIommuUnpinPolicy;
pub use self::msi::MsiConfig;
pub use self::msix::MsixCap;
pub use self::msix::MsixConfig;
pub use self::msix::MsixStatus;
pub use self::pci_address::Error as PciAddressError;
pub use self::pci_address::PciAddress;
pub use self::pci_configuration::PciBarConfiguration;
pub use self::pci_configuration::PciBarIndex;
pub use self::pci_configuration::PciBarPrefetchable;
pub use self::pci_configuration::PciBarRegionType;
pub use self::pci_configuration::PciBaseSystemPeripheralSubclass;
pub use self::pci_configuration::PciCapability;
pub use self::pci_configuration::PciCapabilityID;
pub use self::pci_configuration::PciClassCode;
pub use self::pci_configuration::PciConfiguration;
pub use self::pci_configuration::PciDisplaySubclass;
pub use self::pci_configuration::PciHeaderType;
pub use self::pci_configuration::PciInputDeviceSubclass;
pub use self::pci_configuration::PciMassStorageSubclass;
pub use self::pci_configuration::PciMultimediaSubclass;
pub use self::pci_configuration::PciNetworkControllerSubclass;
pub use self::pci_configuration::PciProgrammingInterface;
pub use self::pci_configuration::PciSerialBusSubClass;
pub use self::pci_configuration::PciSimpleCommunicationControllerSubclass;
pub use self::pci_configuration::PciSubclass;
pub use self::pci_configuration::PciWirelessControllerSubclass;
pub use self::pci_configuration::CAPABILITY_LIST_HEAD_OFFSET;
pub use self::pci_device::BarRange;
pub use self::pci_device::Error as PciDeviceError;
pub use self::pci_device::IoEventError as PciIoEventError;
pub use self::pci_device::PciBus;
pub use self::pci_device::PciDevice;
pub use self::pci_device::PreferredIrq;
#[cfg(feature = "pci-hotplug")]
pub use self::pci_hotplug::HotPluggable;
#[cfg(feature = "pci-hotplug")]
pub use self::pci_hotplug::IntxParameter;
#[cfg(feature = "pci-hotplug")]
pub use self::pci_hotplug::NetResourceCarrier;
#[cfg(feature = "pci-hotplug")]
pub use self::pci_hotplug::ResourceCarrier;
pub use self::pci_root::PciConfigIo;
pub use self::pci_root::PciConfigMmio;
pub use self::pci_root::PciMmioMapper;
pub use self::pci_root::PciRoot;
pub use self::pci_root::PciRootCommand;
pub use self::pci_root::PciVirtualConfigMmio;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use self::pcie::PciBridge;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use self::pcie::PcieDownstreamPort;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use self::pcie::PcieHostPort;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use self::pcie::PcieRootPort;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use self::pcie::PcieUpstreamPort;
pub use self::pvpanic::PvPanicCode;
pub use self::pvpanic::PvPanicPciDevice;
pub use self::stub::StubPciDevice;
pub use self::stub::StubPciParameters;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use self::vfio_pci::VfioPciDevice;

/// PCI has four interrupt pins A->D.
#[derive(Copy, Clone, Ord, PartialOrd, PartialEq, Eq, Serialize, Deserialize)]
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

// VCFG
pub const PCI_VCFG_PM: usize = 0x0;
pub const PCI_VCFG_DSM: usize = 0x1;
pub const PCI_VCFG_NOTY: usize = 0x2;

pub const PCI_VENDOR_ID_INTEL: u16 = 0x8086;
pub const PCI_VENDOR_ID_REDHAT: u16 = 0x1b36;

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    VmWatchdog = 17,
    Pflash = 18,
    VirtioMmio = 19,
    AcAdapter = 20,
    VirtualPmc = 21,
    VirtCpufreq = 22,
    FwCfg = 23,
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
            17 => Ok(CrosvmDeviceId::VmWatchdog),
            18 => Ok(CrosvmDeviceId::Pflash),
            19 => Ok(CrosvmDeviceId::VirtioMmio),
            20 => Ok(CrosvmDeviceId::AcAdapter),
            21 => Ok(CrosvmDeviceId::VirtualPmc),
            _ => Err(base::Error::new(EINVAL)),
        }
    }
}

/// A wrapper structure for pci device and vendor id.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

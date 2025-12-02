// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements pci devices and busses.

mod acpi;
#[cfg(any(target_os = "android", target_os = "linux"))]
mod coiommu;
mod msi;
mod msix;
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

pub use resources::PciAddress;
pub use resources::PciAddressError;
use serde::Deserialize;
use serde::Serialize;

pub use self::acpi::GpeScope;
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
pub use self::pci_device::BarRange;
pub use self::pci_device::Error as PciDeviceError;
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

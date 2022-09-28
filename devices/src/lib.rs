// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg_attr(windows, allow(unused))]

//! Emulates virtual and hardware devices.

pub mod acpi;
pub mod bat;
mod bus;
#[cfg(feature = "stats")]
mod bus_stats;
mod cmos;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod debugcon;
#[cfg(feature = "direct")]
pub mod direct_io;
#[cfg(feature = "direct")]
pub mod direct_irq;
mod i8042;
mod irq_event;
pub mod irqchip;
mod pci;
pub mod pl030;
#[cfg(feature = "usb")]
#[macro_use]
mod register_space;
mod serial;
pub mod serial_device;
#[cfg(feature = "tpm")]
mod software_tpm;
mod sys;
pub mod virtio;
#[cfg(all(feature = "vtpm", target_arch = "x86_64"))]
mod vtpm_proxy;

cfg_if::cfg_if! {
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        mod pit;
        pub use self::pit::{Pit, PitError};
        pub mod tsc;
    }
}

pub use self::acpi::ACPIPMFixedEvent;
pub use self::acpi::ACPIPMResource;
pub use self::bat::BatteryError;
pub use self::bat::GoldfishBattery;
pub use self::bus::Bus;
pub use self::bus::BusAccessInfo;
pub use self::bus::BusDevice;
pub use self::bus::BusDeviceObj;
pub use self::bus::BusDeviceSync;
pub use self::bus::BusRange;
pub use self::bus::BusResumeDevice;
pub use self::bus::BusType;
pub use self::bus::Error as BusError;
pub use self::bus::HostHotPlugKey;
pub use self::bus::HotPlugBus;
#[cfg(feature = "stats")]
pub use self::bus_stats::BusStatistics;
pub use self::cmos::Cmos;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use self::debugcon::Debugcon;
#[cfg(feature = "direct")]
pub use self::direct_io::DirectIo;
#[cfg(feature = "direct")]
pub use self::direct_io::DirectMmio;
#[cfg(feature = "direct")]
pub use self::direct_irq::DirectIrq;
#[cfg(feature = "direct")]
pub use self::direct_irq::DirectIrqError;
pub use self::i8042::I8042Device;
pub use self::irq_event::IrqEdgeEvent;
pub use self::irq_event::IrqLevelEvent;
pub use self::irqchip::*;
pub use self::pci::BarRange;
pub use self::pci::CrosvmDeviceId;
pub use self::pci::PciAddress;
pub use self::pci::PciAddressError;
pub use self::pci::PciBus;
pub use self::pci::PciClassCode;
pub use self::pci::PciConfigIo;
pub use self::pci::PciConfigMmio;
pub use self::pci::PciDevice;
pub use self::pci::PciDeviceError;
pub use self::pci::PciInterruptPin;
pub use self::pci::PciRoot;
pub use self::pci::PciRootCommand;
pub use self::pci::PciVirtualConfigMmio;
pub use self::pci::PreferredIrq;
pub use self::pci::StubPciDevice;
pub use self::pci::StubPciParameters;
pub use self::pl030::Pl030;
pub use self::serial::Serial;
pub use self::serial_device::Error as SerialError;
pub use self::serial_device::SerialDevice;
pub use self::serial_device::SerialHardware;
pub use self::serial_device::SerialParameters;
pub use self::serial_device::SerialType;
#[cfg(feature = "tpm")]
pub use self::software_tpm::SoftwareTpm;
pub use self::virtio::VirtioMmioDevice;
pub use self::virtio::VirtioPciDevice;
#[cfg(all(feature = "vtpm", target_arch = "x86_64"))]
pub use self::vtpm_proxy::VtpmProxy;

mod pflash;
pub use self::pflash::Pflash;
pub use self::pflash::PflashParameters;
cfg_if::cfg_if! {
    if #[cfg(unix)] {
        mod platform;
        mod proxy;
        pub mod vmwdt;
        #[cfg(feature = "usb")]
        pub mod usb;
        #[cfg(feature = "usb")]
        mod utils;
        pub mod vfio;

        #[cfg(feature = "audio")]
        pub use self::pci::{Ac97Backend, Ac97Dev, Ac97Parameters};
        pub use self::pci::{
            CoIommuDev, CoIommuParameters, CoIommuUnpinPolicy,
            PvPanicCode, PcieRootPort, PcieHostPort,
            PvPanicPciDevice, VfioPciDevice, PciBridge, PcieDownstreamPort, PcieUpstreamPort
        };
        pub use self::platform::VfioPlatformDevice;
        pub use self::proxy::Error as ProxyError;
        pub use self::proxy::ProxyDevice;
        #[cfg(feature = "usb")]
        pub use self::usb::host_backend::host_backend_device_provider::HostBackendDeviceProvider;
        #[cfg(feature = "usb")]
        pub use self::usb::xhci::xhci_controller::XhciController;
        pub use self::vfio::{VfioContainer, VfioDevice};
        pub use self::virtio::vfio_wrapper;

    } else if #[cfg(windows)] {
        // We define Minijail as an empty struct on Windows because the concept
        // of jailing is baked into a bunch of places where it isn't easy
        // to compile it out. In the long term, this should go away.
        #[cfg(windows)]
        pub struct Minijail {}
    } else {
        compile_error!("Unsupported platform");
    }
}

/// Request CoIOMMU to unpin a specific range.
use serde::Deserialize;
/// Request CoIOMMU to unpin a specific range.
use serde::Serialize;
#[derive(Serialize, Deserialize, Debug)]
pub struct UnpinRequest {
    /// The ranges presents (start gfn, count).
    ranges: Vec<(u64, u64)>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum UnpinResponse {
    Success,
    Failed,
}

#[derive(Debug)]
pub enum ParseIommuDevTypeResult {
    NoSuchType,
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum IommuDevType {
    NoIommu,
    VirtioIommu,
    CoIommu,
}

use std::str::FromStr;
impl FromStr for IommuDevType {
    type Err = ParseIommuDevTypeResult;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "off" => Ok(IommuDevType::NoIommu),
            "viommu" => Ok(IommuDevType::VirtioIommu),
            "coiommu" => Ok(IommuDevType::CoIommu),
            _ => Err(ParseIommuDevTypeResult::NoSuchType),
        }
    }
}

// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Emulates virtual and hardware devices.

mod bus;
mod cmos;
#[cfg(feature = "direct")]
pub mod direct_io;
#[cfg(feature = "direct")]
pub mod direct_irq;
mod i8042;
pub mod irqchip;
mod pci;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod pit;
pub mod pl030;
mod platform;
mod proxy;
#[cfg(feature = "usb")]
#[macro_use]
mod register_space;
pub mod acpi;
pub mod bat;
mod serial;
pub mod serial_device;
#[cfg(feature = "usb")]
pub mod usb;
#[cfg(feature = "usb")]
mod utils;
pub mod vfio;
pub mod virtio;

pub use self::acpi::ACPIPMResource;
pub use self::bat::{BatteryError, GoldfishBattery};
pub use self::bus::Error as BusError;
pub use self::bus::{
    Bus, BusAccessInfo, BusDevice, BusDeviceObj, BusDeviceSync, BusRange, BusResumeDevice, BusType,
    HostHotPlugKey, HotPlugBus,
};
pub use self::cmos::Cmos;
#[cfg(feature = "direct")]
pub use self::direct_io::{DirectIo, DirectMmio};
#[cfg(feature = "direct")]
pub use self::direct_irq::{DirectIrq, DirectIrqError};
pub use self::i8042::I8042Device;
pub use self::irqchip::*;
#[cfg(feature = "audio")]
pub use self::pci::{Ac97Backend, Ac97Dev, Ac97Parameters};
pub use self::pci::{
    BarRange, CoIommuDev, CoIommuParameters, CoIommuUnpinPolicy, PciAddress, PciBridge,
    PciClassCode, PciConfigIo, PciConfigMmio, PciDevice, PciDeviceError, PciInterruptPin, PciRoot,
    PciVirtualConfigMmio, PcieHostRootPort, PcieRootPort, PvPanicCode, PvPanicPciDevice,
    StubPciDevice, StubPciParameters, VfioPciDevice,
};
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use self::pit::{Pit, PitError};
pub use self::pl030::Pl030;
pub use self::platform::VfioPlatformDevice;
pub use self::proxy::Error as ProxyError;
pub use self::proxy::ProxyDevice;
pub use self::serial::Serial;
pub use self::serial_device::{
    Error as SerialError, SerialDevice, SerialHardware, SerialParameters, SerialType,
};
#[cfg(feature = "usb")]
pub use self::usb::host_backend::host_backend_device_provider::HostBackendDeviceProvider;
#[cfg(feature = "usb")]
pub use self::usb::xhci::xhci_controller::XhciController;
pub use self::vfio::{VfioContainer, VfioDevice};
pub use self::virtio::{vfio_wrapper, VirtioPciDevice};

/// Request CoIOMMU to unpin a specific range.
use serde::{Deserialize, Serialize};
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

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
pub use self::bus::{Bus, BusAccessInfo, BusDevice, BusDeviceSync, BusRange, BusResumeDevice};
pub use self::cmos::Cmos;
#[cfg(feature = "direct")]
pub use self::direct_io::DirectIo;
#[cfg(feature = "direct")]
pub use self::direct_irq::{DirectIrq, DirectIrqError};
pub use self::i8042::I8042Device;
pub use self::irqchip::*;
#[cfg(feature = "audio")]
pub use self::pci::{Ac97Backend, Ac97Dev, Ac97Parameters};
pub use self::pci::{
    PciAddress, PciConfigIo, PciConfigMmio, PciDevice, PciDeviceError, PciInterruptPin, PciRoot,
    VfioPciDevice,
};
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use self::pit::{Pit, PitError};
pub use self::pl030::Pl030;
pub use self::proxy::Error as ProxyError;
pub use self::proxy::ProxyDevice;
pub use self::serial::Serial;
pub use self::serial_device::SerialDevice;
#[cfg(feature = "usb")]
pub use self::usb::host_backend::host_backend_device_provider::HostBackendDeviceProvider;
#[cfg(feature = "usb")]
pub use self::usb::xhci::xhci_controller::XhciController;
pub use self::vfio::{VfioContainer, VfioDevice};
pub use self::virtio::VirtioPciDevice;

/// Whether the VM should be run in protected mode or not.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ProtectionType {
    /// The VM should be run in the unprotected mode, where the host has access to its memory.
    Unprotected,
    /// The VM should be run in protected mode, so the host cannot access its memory directly.
    Protected,
}

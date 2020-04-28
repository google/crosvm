// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Emulates virtual and hardware devices.

mod bus;
mod cmos;
mod i8042;
mod ioapic;
mod pci;
mod pic;
mod pit;
pub mod pl030;
mod proxy;
#[macro_use]
mod register_space;
pub mod acpi;
mod serial;
mod serial_device;
pub mod split_irqchip_common;
pub mod usb;
mod utils;
pub mod vfio;
pub mod virtio;

pub use self::acpi::ACPIPMResource;
pub use self::bus::Error as BusError;
pub use self::bus::{Bus, BusDevice, BusRange, BusResumeDevice};
pub use self::cmos::Cmos;
pub use self::i8042::I8042Device;
pub use self::ioapic::{Ioapic, IOAPIC_BASE_ADDRESS, IOAPIC_MEM_LENGTH_BYTES};
pub use self::pci::{
    Ac97Backend, Ac97Dev, Ac97Parameters, PciAddress, PciConfigIo, PciConfigMmio, PciDevice,
    PciDeviceError, PciInterruptPin, PciRoot, VfioPciDevice,
};
pub use self::pic::Pic;
pub use self::pit::{Pit, PitError};
pub use self::pl030::Pl030;
pub use self::proxy::Error as ProxyError;
pub use self::proxy::ProxyDevice;
pub use self::serial::Serial;
pub use self::serial_device::SerialDevice;
pub use self::usb::host_backend::host_backend_device_provider::HostBackendDeviceProvider;
pub use self::usb::xhci::xhci_controller::XhciController;
pub use self::vfio::{VfioContainer, VfioDevice};
pub use self::virtio::VirtioPciDevice;

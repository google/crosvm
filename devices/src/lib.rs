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
mod serial;
pub mod split_irqchip_common;
pub mod usb;
mod utils;
pub mod virtio;

pub use self::bus::Error as BusError;
pub use self::bus::{Bus, BusDevice, BusRange};
pub use self::cmos::Cmos;
pub use self::i8042::I8042Device;
pub use self::ioapic::Ioapic;
pub use self::pci::{
    Ac97Dev, PciConfigIo, PciConfigMmio, PciDevice, PciDeviceError, PciInterruptPin, PciRoot,
};
pub use self::pic::Pic;
pub use self::pit::{Pit, PitError};
pub use self::pl030::Pl030;
pub use self::proxy::Error as ProxyError;
pub use self::proxy::ProxyDevice;
pub use self::serial::Error as SerialError;
pub use self::serial::{
    get_serial_tty_string, Serial, SerialParameters, SerialType, DEFAULT_SERIAL_PARAMS, SERIAL_ADDR,
};
pub use self::usb::host_backend::host_backend_device_provider::HostBackendDeviceProvider;
pub use self::usb::xhci::xhci_controller::XhciController;
pub use self::virtio::VirtioPciDevice;

// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Emulates virtual and hardware devices.

extern crate audio_streams;
extern crate bit_field;
extern crate byteorder;
extern crate data_model;
extern crate enumn;
extern crate io_jail;
extern crate kvm;
extern crate libc;
extern crate msg_on_socket_derive;
extern crate msg_socket;
extern crate net_sys;
extern crate net_util;
extern crate p9;
extern crate resources;
extern crate sync;
#[macro_use]
extern crate sys_util;
#[cfg(feature = "tpm")]
extern crate tpm2;
extern crate vhost;
extern crate virtio_sys;
extern crate vm_control;

#[allow(dead_code)]
#[macro_use]
mod register_space;

mod bus;
mod cmos;
mod i8042;
mod pci;
mod pit;
pub mod pl030;
mod proxy;
mod serial;
#[allow(dead_code)]
mod usb;
#[allow(dead_code)]
mod utils;
pub mod virtio;

pub use self::bus::Error as BusError;
pub use self::bus::{Bus, BusDevice, BusRange};
pub use self::cmos::Cmos;
pub use self::i8042::I8042Device;
pub use self::pci::{
    Ac97Dev, PciConfigIo, PciConfigMmio, PciDevice, PciDeviceError, PciInterruptPin, PciRoot,
};
pub use self::pit::{Pit, PitError};
pub use self::pl030::Pl030;
pub use self::proxy::Error as ProxyError;
pub use self::proxy::ProxyDevice;
pub use self::serial::Serial;
pub use self::virtio::VirtioPciDevice;

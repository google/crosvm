// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::convert::TryInto;
use std::fmt::{self, Display};
use std::sync::Arc;

use base::RawDescriptor;
use sync::Mutex;

use crate::pci::pci_configuration::{
    PciBridgeSubclass, PciClassCode, PciConfiguration, PciHeaderType,
};
use crate::pci::pci_device::{Error, PciDevice};
use crate::{BusAccessInfo, BusDevice};
use resources::SystemAllocator;

// A PciDevice that holds the root hub's configuration.
struct PciRootConfiguration {
    config: PciConfiguration,
}

impl PciDevice for PciRootConfiguration {
    fn debug_label(&self) -> String {
        "pci root device".to_owned()
    }
    fn allocate_address(&mut self, _resources: &mut SystemAllocator) -> Result<PciAddress, Error> {
        // PCI root fixed address.
        Ok(PciAddress {
            bus: 0,
            dev: 0,
            func: 0,
        })
    }
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        Vec::new()
    }
    fn read_config_register(&self, reg_idx: usize) -> u32 {
        self.config.read_reg(reg_idx)
    }

    fn write_config_register(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        (&mut self.config).write_reg(reg_idx, offset, data)
    }

    fn read_bar(&mut self, _addr: u64, _data: &mut [u8]) {}

    fn write_bar(&mut self, _addr: u64, _data: &[u8]) {}
}

/// PCI Device Address, AKA Bus:Device.Function
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PciAddress {
    pub bus: u8,
    pub dev: u8,  /* u5 */
    pub func: u8, /* u3 */
}

impl Display for PciAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:04x}:{:02x}.{:0x}", self.bus, self.dev, self.func)
    }
}

impl PciAddress {
    const BUS_OFFSET: usize = 16;
    const BUS_MASK: u32 = 0x00ff;
    const DEVICE_OFFSET: usize = 11;
    const DEVICE_MASK: u32 = 0x1f;
    const FUNCTION_OFFSET: usize = 8;
    const FUNCTION_MASK: u32 = 0x07;
    const REGISTER_OFFSET: usize = 2;
    const REGISTER_MASK: u32 = 0x3f;

    /// Construct PciAddress and register tuple from CONFIG_ADDRESS value.
    pub fn from_config_address(config_address: u32) -> (Self, usize) {
        let bus = ((config_address >> Self::BUS_OFFSET) & Self::BUS_MASK) as u8;
        let dev = ((config_address >> Self::DEVICE_OFFSET) & Self::DEVICE_MASK) as u8;
        let func = ((config_address >> Self::FUNCTION_OFFSET) & Self::FUNCTION_MASK) as u8;
        let register = ((config_address >> Self::REGISTER_OFFSET) & Self::REGISTER_MASK) as usize;

        (PciAddress { bus, dev, func }, register)
    }

    /// Construct PciAddress from string domain:bus:device.function.
    pub fn from_string(address: &str) -> Self {
        let mut func_dev_bus_domain = address
            .split(|c| c == ':' || c == '.')
            .map(|v| u8::from_str_radix(v, 16).unwrap_or_default())
            .rev()
            .collect::<Vec<u8>>();
        func_dev_bus_domain.resize(4, 0);
        PciAddress {
            bus: func_dev_bus_domain[2],
            dev: func_dev_bus_domain[1],
            func: func_dev_bus_domain[0],
        }
    }

    /// Encode PciAddress into CONFIG_ADDRESS value.
    pub fn to_config_address(&self, register: usize) -> u32 {
        ((Self::BUS_MASK & self.bus as u32) << Self::BUS_OFFSET)
            | ((Self::DEVICE_MASK & self.dev as u32) << Self::DEVICE_OFFSET)
            | ((Self::FUNCTION_MASK & self.func as u32) << Self::FUNCTION_OFFSET)
            | ((Self::REGISTER_MASK & register as u32) << Self::REGISTER_OFFSET)
    }

    /// Returns true if the address points to PCI root host-bridge.
    fn is_root(&self) -> bool {
        matches!(
            &self,
            PciAddress {
                bus: 0,
                dev: 0,
                func: 0
            }
        )
    }
}

/// Emulates the PCI Root bridge.
pub struct PciRoot {
    /// Bus configuration for the root device.
    root_configuration: PciRootConfiguration,
    /// Devices attached to this bridge.
    devices: BTreeMap<PciAddress, Arc<Mutex<dyn BusDevice>>>,
}

const PCI_VENDOR_ID_INTEL: u16 = 0x8086;
const PCI_DEVICE_ID_INTEL_82441: u16 = 0x1237;

impl PciRoot {
    /// Create an empty PCI root bus.
    pub fn new() -> Self {
        PciRoot {
            root_configuration: PciRootConfiguration {
                config: PciConfiguration::new(
                    PCI_VENDOR_ID_INTEL,
                    PCI_DEVICE_ID_INTEL_82441,
                    PciClassCode::BridgeDevice,
                    &PciBridgeSubclass::HostBridge,
                    None,
                    PciHeaderType::Device,
                    0,
                    0,
                    0,
                ),
            },
            devices: BTreeMap::new(),
        }
    }

    /// Add a `device` to this root PCI bus.
    pub fn add_device(&mut self, address: PciAddress, device: Arc<Mutex<dyn BusDevice>>) {
        // Ignore attempt to replace PCI Root host bridge.
        if !address.is_root() {
            self.devices.insert(address, device);
        }
    }

    pub fn config_space_read(&self, address: PciAddress, register: usize) -> u32 {
        if address.is_root() {
            self.root_configuration.config_register_read(register)
        } else {
            self.devices
                .get(&address)
                .map_or(0xffff_ffff, |d| d.lock().config_register_read(register))
        }
    }

    pub fn config_space_write(
        &mut self,
        address: PciAddress,
        register: usize,
        offset: u64,
        data: &[u8],
    ) {
        if offset as usize + data.len() > 4 {
            return;
        }
        if address.is_root() {
            self.root_configuration
                .config_register_write(register, offset, data);
        } else if let Some(d) = self.devices.get(&address) {
            d.lock().config_register_write(register, offset, data);
        }
    }
}

/// Emulates PCI configuration access mechanism #1 (I/O ports 0xcf8 and 0xcfc).
pub struct PciConfigIo {
    /// PCI root bridge.
    pci_root: PciRoot,
    /// Current address to read/write from (0xcf8 register, litte endian).
    config_address: u32,
}

impl PciConfigIo {
    pub fn new(pci_root: PciRoot) -> Self {
        PciConfigIo {
            pci_root,
            config_address: 0,
        }
    }

    fn config_space_read(&self) -> u32 {
        let enabled = (self.config_address & 0x8000_0000) != 0;
        if !enabled {
            return 0xffff_ffff;
        }

        let (address, register) = PciAddress::from_config_address(self.config_address);
        self.pci_root.config_space_read(address, register)
    }

    fn config_space_write(&mut self, offset: u64, data: &[u8]) {
        let enabled = (self.config_address & 0x8000_0000) != 0;
        if !enabled {
            return;
        }

        let (address, register) = PciAddress::from_config_address(self.config_address);
        self.pci_root
            .config_space_write(address, register, offset, data)
    }

    fn set_config_address(&mut self, offset: u64, data: &[u8]) {
        if offset as usize + data.len() > 4 {
            return;
        }
        let (mask, value): (u32, u32) = match data.len() {
            1 => (
                0x0000_00ff << (offset * 8),
                (data[0] as u32) << (offset * 8),
            ),
            2 => (
                0x0000_ffff << (offset * 16),
                u32::from(u16::from_le_bytes(data.try_into().unwrap())) << (offset * 16),
            ),
            4 => (0xffff_ffff, u32::from_le_bytes(data.try_into().unwrap())),
            _ => return,
        };
        self.config_address = (self.config_address & !mask) | value;
    }
}

impl BusDevice for PciConfigIo {
    fn debug_label(&self) -> String {
        format!("pci config io-port 0x{:03x}", self.config_address)
    }

    fn read(&mut self, info: BusAccessInfo, data: &mut [u8]) {
        // `offset` is relative to 0xcf8
        let value = match info.offset {
            0..=3 => self.config_address,
            4..=7 => self.config_space_read(),
            _ => 0xffff_ffff,
        };

        // Only allow reads to the register boundary.
        let start = info.offset as usize % 4;
        let end = start + data.len();
        if end <= 4 {
            for i in start..end {
                data[i - start] = (value >> (i * 8)) as u8;
            }
        } else {
            for d in data {
                *d = 0xff;
            }
        }
    }

    fn write(&mut self, info: BusAccessInfo, data: &[u8]) {
        // `offset` is relative to 0xcf8
        match info.offset {
            o @ 0..=3 => self.set_config_address(o, data),
            o @ 4..=7 => self.config_space_write(o - 4, data),
            _ => (),
        };
    }
}

/// Emulates PCI memory-mapped configuration access mechanism.
pub struct PciConfigMmio {
    /// PCI root bridge.
    pci_root: PciRoot,
}

impl PciConfigMmio {
    pub fn new(pci_root: PciRoot) -> Self {
        PciConfigMmio { pci_root }
    }

    fn config_space_read(&self, config_address: u32) -> u32 {
        let (address, register) = PciAddress::from_config_address(config_address);
        self.pci_root.config_space_read(address, register)
    }

    fn config_space_write(&mut self, config_address: u32, offset: u64, data: &[u8]) {
        let (address, register) = PciAddress::from_config_address(config_address);
        self.pci_root
            .config_space_write(address, register, offset, data)
    }
}

impl BusDevice for PciConfigMmio {
    fn debug_label(&self) -> String {
        "pci config mmio".to_owned()
    }

    fn read(&mut self, info: BusAccessInfo, data: &mut [u8]) {
        // Only allow reads to the register boundary.
        let start = info.offset as usize % 4;
        let end = start + data.len();
        if end > 4 || info.offset > u32::max_value() as u64 {
            for d in data {
                *d = 0xff;
            }
            return;
        }

        let value = self.config_space_read(info.offset as u32);
        for i in start..end {
            data[i - start] = (value >> (i * 8)) as u8;
        }
    }

    fn write(&mut self, info: BusAccessInfo, data: &[u8]) {
        if info.offset > u32::max_value() as u64 {
            return;
        }
        self.config_space_write(info.offset as u32, info.offset % 4, data)
    }
}

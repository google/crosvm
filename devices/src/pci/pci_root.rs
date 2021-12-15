// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::convert::TryInto;
use std::fmt::{self, Display};
use std::ops::Bound::Included;
use std::sync::{Arc, Weak};

use base::{error, Event, RawDescriptor};
use serde::{Deserialize, Serialize};
use sync::Mutex;

use crate::pci::pci_configuration::{
    PciBarConfiguration, PciBridgeSubclass, PciClassCode, PciConfiguration, PciHeaderType,
    HEADER_TYPE_MULTIFUNCTION_MASK, HEADER_TYPE_REG,
};
use crate::pci::pci_device::{Error, PciDevice};
use crate::{Bus, BusAccessInfo, BusDevice, BusType};
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

    fn get_bar_configuration(&self, bar_num: usize) -> Option<PciBarConfiguration> {
        self.config.get_bar_configuration(bar_num)
    }
}

/// PCI Device Address, AKA Bus:Device.Function
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
    const BUS_MASK: u32 = 0x00ff;
    const DEVICE_BITS_NUM: usize = 5;
    const DEVICE_MASK: u32 = 0x1f;
    const FUNCTION_BITS_NUM: usize = 3;
    const FUNCTION_MASK: u32 = 0x07;
    const REGISTER_OFFSET: usize = 2;

    /// Construct PciAddress and register tuple from CONFIG_ADDRESS value.
    pub fn from_config_address(config_address: u32, register_bits_num: usize) -> (Self, usize) {
        let bus_offset = register_bits_num + Self::FUNCTION_BITS_NUM + Self::DEVICE_BITS_NUM;
        let bus = ((config_address >> bus_offset) & Self::BUS_MASK) as u8;
        let dev_offset = register_bits_num + Self::FUNCTION_BITS_NUM;
        let dev = ((config_address >> dev_offset) & Self::DEVICE_MASK) as u8;
        let func = ((config_address >> register_bits_num) & Self::FUNCTION_MASK) as u8;
        let register_mask: u32 = (1_u32 << (register_bits_num - Self::REGISTER_OFFSET)) - 1;
        let register = ((config_address >> Self::REGISTER_OFFSET) & register_mask) as usize;

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
    pub fn to_config_address(&self, register: usize, register_bits_num: usize) -> u32 {
        let bus_offset = register_bits_num + Self::FUNCTION_BITS_NUM + Self::DEVICE_BITS_NUM;
        let dev_offset = register_bits_num + Self::FUNCTION_BITS_NUM;
        let register_mask: u32 = (1_u32 << (register_bits_num - Self::REGISTER_OFFSET)) - 1;
        ((Self::BUS_MASK & self.bus as u32) << bus_offset)
            | ((Self::DEVICE_MASK & self.dev as u32) << dev_offset)
            | ((Self::FUNCTION_MASK & self.func as u32) << register_bits_num)
            | ((register_mask & register as u32) << Self::REGISTER_OFFSET)
    }

    /// Convert B:D:F PCI address to unsigned 32 bit integer
    pub fn to_u32(&self) -> u32 {
        ((Self::BUS_MASK & self.bus as u32) << (Self::FUNCTION_BITS_NUM + Self::DEVICE_BITS_NUM))
            | ((Self::DEVICE_MASK & self.dev as u32) << Self::FUNCTION_BITS_NUM)
            | (Self::FUNCTION_MASK & self.func as u32)
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
#[allow(dead_code)] // TODO(b/174705596): remove once mmio_bus and io_bus are used
pub struct PciRoot {
    /// Memory (MMIO) bus.
    mmio_bus: Weak<Bus>,
    /// IO bus (x86 only - for non-x86 platforms, this is just an empty Bus).
    io_bus: Weak<Bus>,
    /// Bus configuration for the root device.
    root_configuration: PciRootConfiguration,
    /// Devices attached to this bridge.
    devices: BTreeMap<PciAddress, Arc<Mutex<dyn BusDevice>>>,
    /// pcie enhanced configuration access mmio base
    pcie_cfg_mmio: Option<u64>,
}

pub const PCI_VENDOR_ID_INTEL: u16 = 0x8086;
const PCI_DEVICE_ID_INTEL_82441: u16 = 0x1237;
const PCIE_XBAR_BASE_ADDR: usize = 24;

impl PciRoot {
    /// Create an empty PCI root bus.
    pub fn new(mmio_bus: Weak<Bus>, io_bus: Weak<Bus>) -> Self {
        PciRoot {
            mmio_bus,
            io_bus,
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
            pcie_cfg_mmio: None,
        }
    }

    /// enable pcie enhanced configuration access and set base mmio
    pub fn enable_pcie_cfg_mmio(&mut self, pcie_cfg_mmio: u64) {
        self.pcie_cfg_mmio = Some(pcie_cfg_mmio);
    }

    /// Add a `device` to this root PCI bus.
    pub fn add_device(&mut self, address: PciAddress, device: Arc<Mutex<dyn BusDevice>>) {
        // Ignore attempt to replace PCI Root host bridge.
        if !address.is_root() {
            self.devices.insert(address, device);
        }
    }

    fn remove_device(&mut self, address: PciAddress) {
        if let Some(d) = self.devices.remove(&address) {
            for (range, bus_type) in d.lock().get_ranges() {
                let bus_ptr = if bus_type == BusType::Mmio {
                    match self.mmio_bus.upgrade() {
                        Some(m) => m,
                        None => continue,
                    }
                } else {
                    match self.io_bus.upgrade() {
                        Some(i) => i,
                        None => continue,
                    }
                };
                let _ = bus_ptr.remove(range.base, range.len);
            }
            d.lock().destroy_device();
        }
    }

    pub fn config_space_read(&self, address: PciAddress, register: usize) -> u32 {
        if address.is_root() {
            if register == PCIE_XBAR_BASE_ADDR && self.pcie_cfg_mmio.is_some() {
                let pcie_mmio = self.pcie_cfg_mmio.unwrap() as u32;
                pcie_mmio | 0x1
            } else if register == (PCIE_XBAR_BASE_ADDR + 1) && self.pcie_cfg_mmio.is_some() {
                (self.pcie_cfg_mmio.unwrap() >> 32) as u32
            } else {
                self.root_configuration.config_register_read(register)
            }
        } else {
            let mut data = self
                .devices
                .get(&address)
                .map_or(0xffff_ffff, |d| d.lock().config_register_read(register));

            if register == HEADER_TYPE_REG {
                // Set multifunction bit in header type if there are devices at non-zero functions
                // in this slot.
                if self
                    .devices
                    .range((
                        Included(&PciAddress {
                            bus: address.bus,
                            dev: address.dev,
                            func: 1,
                        }),
                        Included(&PciAddress {
                            bus: address.bus,
                            dev: address.dev,
                            func: 7,
                        }),
                    ))
                    .next()
                    .is_some()
                {
                    data |= HEADER_TYPE_MULTIFUNCTION_MASK;
                }
            }

            data
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
            let res = d.lock().config_register_write(register, offset, data);

            if !res.mmio_add.is_empty() || !res.mmio_remove.is_empty() {
                let mmio_bus = match self.mmio_bus.upgrade() {
                    Some(m) => m,
                    None => return,
                };
                for range in &res.mmio_remove {
                    let _ = mmio_bus.remove(range.base, range.len);
                }
                for range in &res.mmio_add {
                    let _ = mmio_bus.insert(d.clone(), range.base, range.len);
                }
            }

            if !res.io_add.is_empty() || !res.io_remove.is_empty() {
                let io_bus = match self.io_bus.upgrade() {
                    Some(i) => i,
                    None => return,
                };
                for range in &res.io_remove {
                    let _ = io_bus.remove(range.base, range.len);
                }
                for range in &res.io_add {
                    let _ = io_bus.insert(d.clone(), range.base, range.len);
                }
            }

            for remove_pci_device in res.removed_pci_devices.iter() {
                self.remove_device(*remove_pci_device);
            }
        }
    }
}

/// Emulates PCI configuration access mechanism #1 (I/O ports 0xcf8 and 0xcfc).
pub struct PciConfigIo {
    /// PCI root bridge.
    pci_root: Arc<Mutex<PciRoot>>,
    /// Current address to read/write from (0xcf8 register, litte endian).
    config_address: u32,
    /// Event to signal that the quest requested reset via writing to 0xcf9 register.
    reset_evt: Event,
}

impl PciConfigIo {
    const REGISTER_BITS_NUM: usize = 8;

    pub fn new(pci_root: Arc<Mutex<PciRoot>>, reset_evt: Event) -> Self {
        PciConfigIo {
            pci_root,
            config_address: 0,
            reset_evt,
        }
    }

    fn config_space_read(&self) -> u32 {
        let enabled = (self.config_address & 0x8000_0000) != 0;
        if !enabled {
            return 0xffff_ffff;
        }

        let (address, register) =
            PciAddress::from_config_address(self.config_address, Self::REGISTER_BITS_NUM);
        self.pci_root.lock().config_space_read(address, register)
    }

    fn config_space_write(&mut self, offset: u64, data: &[u8]) {
        let enabled = (self.config_address & 0x8000_0000) != 0;
        if !enabled {
            return;
        }

        let (address, register) =
            PciAddress::from_config_address(self.config_address, Self::REGISTER_BITS_NUM);
        self.pci_root
            .lock()
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

const PCI_RESET_CPU_BIT: u8 = 1 << 2;

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
            _o @ 1 if data.len() == 1 && data[0] & PCI_RESET_CPU_BIT != 0 => {
                if let Err(e) = self.reset_evt.write(1) {
                    error!("failed to trigger PCI 0xcf9 reset event: {}", e);
                }
            }
            o @ 0..=3 => self.set_config_address(o, data),
            o @ 4..=7 => self.config_space_write(o - 4, data),
            _ => (),
        };
    }
}

/// Emulates PCI memory-mapped configuration access mechanism.
pub struct PciConfigMmio {
    /// PCI root bridge.
    pci_root: Arc<Mutex<PciRoot>>,
    /// Register bit number in config address.
    register_bit_num: usize,
}

impl PciConfigMmio {
    pub fn new(pci_root: Arc<Mutex<PciRoot>>, register_bit_num: usize) -> Self {
        PciConfigMmio {
            pci_root,
            register_bit_num,
        }
    }

    fn config_space_read(&self, config_address: u32) -> u32 {
        let (address, register) =
            PciAddress::from_config_address(config_address, self.register_bit_num);
        self.pci_root.lock().config_space_read(address, register)
    }

    fn config_space_write(&mut self, config_address: u32, offset: u64, data: &[u8]) {
        let (address, register) =
            PciAddress::from_config_address(config_address, self.register_bit_num);
        self.pci_root
            .lock()
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

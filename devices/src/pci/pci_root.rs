// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std;
use std::sync::{Arc, Mutex};

use byteorder::{ByteOrder, LittleEndian};

use io_jail::Minijail;
use sys_util::{self, EventFd};
use resources::SystemAllocator;

use Bus;
use BusDevice;
use bus::Error as BusError;
use proxy::Error as ProxyError;
use ProxyDevice;

use pci::pci_configuration::{PciBridgeSubclass, PciClassCode, PciConfiguration,
                             PciHeaderType};
use pci::pci_device::{self, PciDevice};
use pci::PciInterruptPin;

#[derive(Debug)]
pub enum Error {
    CreateEventFd(sys_util::Error),
    MmioRegistration(BusError),
    ProxyCreation(ProxyError),
    DeviceIoSpaceAllocation(pci_device::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

/// Contains the devices that will be on a PCI bus. Used to configure a PCI bus before adding it to
/// a VM. Use `generate_hub` to produce a PciRoot for use in a Vm.
pub struct PciDeviceList {
    devices: Vec<(Box<PciDevice + 'static>, Minijail)>,
}

impl PciDeviceList {
    pub fn new() -> Self {
        PciDeviceList {
            devices: Vec::new(),
        }
    }

    pub fn add_device(&mut self, device: Box<PciDevice + 'static>, jail: Minijail) {
        self.devices.push((device, jail));
    }

    pub fn generate_root(self, mmio_bus: &mut Bus, resources: &mut SystemAllocator)
            -> Result<(PciRoot, Vec<(u32, PciInterruptPin)>)> {
        let mut root = PciRoot::new();
        let mut pci_irqs = Vec::new();
        for (dev_idx, (mut device, jail)) in self.devices.into_iter().enumerate() {
            let irqfd = EventFd::new().map_err(Error::CreateEventFd)?;
            let irq_num = resources.allocate_irq().unwrap() as u32;
            let pci_irq_pin = match dev_idx % 4 {
                0 => PciInterruptPin::IntA,
                1 => PciInterruptPin::IntB,
                2 => PciInterruptPin::IntC,
                3 => PciInterruptPin::IntD,
                _ => panic!(""), // Obviously not possible, but the compiler is not smart enough.
            };
            device.assign_irq(irqfd, irq_num, pci_irq_pin);
            pci_irqs.push((irq_num, pci_irq_pin));
            root.add_device(device, &jail, mmio_bus, resources)?;
        }
        Ok((root, pci_irqs))
    }
}

// A PciDevice that holds the root hub's configuration.
struct PciRootConfiguration {
    config: PciConfiguration,
}

impl PciDevice for PciRootConfiguration {
    fn config_registers(&self) -> &PciConfiguration {
        &self.config
    }

    fn config_registers_mut(&mut self) -> &mut PciConfiguration {
        &mut self.config
    }

    fn read_bar(&mut self, _addr: u64, _data: &mut [u8]) {}

    fn write_bar(&mut self, _addr: u64, _data: &[u8]) {}
}

/// Emulates the PCI Root bridge.
pub struct PciRoot {
    /// Bus configuration for the root device.
    root_configuration: PciRootConfiguration,
    /// Current address to read/write from (0xcf8 register, litte endian).
    config_address: u32,
    /// Devices attached to this bridge.
    devices: Vec<Arc<Mutex<ProxyDevice>>>,
}

impl PciRoot {
    /// Create an empty PCI root bus.
    fn new() -> Self {
        PciRoot {
            root_configuration: PciRootConfiguration {
                config: PciConfiguration::new(
                            0,
                            0,
                            PciClassCode::BridgeDevice,
                            &PciBridgeSubclass::HostBridge,
                            PciHeaderType::Bridge,
                            ),
            },
            config_address: 0,
            devices: Vec::new(),
        }
    }

    /// Add a `device` to this root PCI bus.
    pub fn add_device<D: PciDevice>(&mut self, mut device: D, jail: &Minijail,
                      mmio_bus: &mut Bus, // TODO - move to resources or something.
                      resources: &mut SystemAllocator) -> Result<()> {
        let ranges = device
            .allocate_io_bars(resources)
            .map_err(Error::DeviceIoSpaceAllocation)?;
        let proxy = ProxyDevice::new(device, &jail, Vec::new())
            .map_err(Error::ProxyCreation)?;
        let arced_dev = Arc::new(Mutex::new(proxy));
        for range in &ranges {
            mmio_bus.insert(arced_dev.clone(), range.0, range.1, true)
                .map_err(Error::MmioRegistration)?;
        }
        self.devices.push(arced_dev);
        Ok(())
    }

    fn config_space_read(&self) -> u32 {
        let (enabled, bus, device, _, register) = parse_config_address(self.config_address);

        // Only support one bus.
        if !enabled || bus != 0 {
            return 0xffff_ffff;
        }

        match device {
            0 => {
                // If bus and device are both zero, then read from the root config.
                self.root_configuration.config_register_read(register)
            }
            dev_num => self
                .devices
                .get(dev_num - 1)
                .map_or(0xffff_ffff, |d| {
                    d.lock().unwrap().config_register_read(register)
                }),
        }
    }

    fn config_space_write(&mut self, offset: u64, data: &[u8]) {
        if offset as usize + data.len() > 4 {
            return;
        }

        let (enabled, bus, device, _, register) = parse_config_address(self.config_address);

        // Only support one bus.
        if !enabled || bus != 0 {
            return;
        }

        match device {
            0 => {
                // If bus and device are both zero, then read from the root config.
                self.root_configuration.config_register_write(register, offset, data);
            }
            dev_num => {
                // dev_num is 1-indexed here.
                if let Some(d) = self.devices.get(dev_num - 1) {
                    d.lock().unwrap().config_register_write(register, offset, data);
                }
            }
        }
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
                ((data[1] as u32) << 8 | data[0] as u32) << (offset * 16),
            ),
            4 => (0xffff_ffff, LittleEndian::read_u32(data)),
            _ => return,
        };
        self.config_address = (self.config_address & !mask) | value;
    }
}

impl BusDevice for PciRoot {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        // `offset` is relative to 0xcf8
        let value = match offset {
            0...3 => self.config_address,
            4...7 => self.config_space_read(),
            _ => 0xffff_ffff,
        };

        // Only allow reads to the register boundary.
        let start = offset as usize % 4;
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

    fn write(&mut self, offset: u64, data: &[u8]) {
        // `offset` is relative to 0xcf8
        match offset {
            o @ 0...3 => self.set_config_address(o, data),
            o @ 4...7 => self.config_space_write(o - 4, data),
            _ => (),
        };
    }
}

// Parse the CONFIG_ADDRESS register to a (enabled, bus, device, function, register) tuple.
fn parse_config_address(config_address: u32) -> (bool, usize, usize, usize, usize) {
    const BUS_NUMBER_OFFSET: usize = 16;
    const BUS_NUMBER_MASK: u32 = 0x00ff;
    const DEVICE_NUMBER_OFFSET: usize = 11;
    const DEVICE_NUMBER_MASK: u32 = 0x1f;
    const FUNCTION_NUMBER_OFFSET: usize = 8;
    const FUNCTION_NUMBER_MASK: u32 = 0x07;
    const REGISTER_NUMBER_OFFSET: usize = 2;
    const REGISTER_NUMBER_MASK: u32 = 0x3f;

    let enabled = (config_address & 0x8000_0000) != 0;
    let bus_number = ((config_address >> BUS_NUMBER_OFFSET) & BUS_NUMBER_MASK) as usize;
    let device_number = ((config_address >> DEVICE_NUMBER_OFFSET) & DEVICE_NUMBER_MASK) as usize;
    let function_number =
        ((config_address >> FUNCTION_NUMBER_OFFSET) & FUNCTION_NUMBER_MASK) as usize;
    let register_number =
        ((config_address >> REGISTER_NUMBER_OFFSET) & REGISTER_NUMBER_MASK) as usize;

    (
        enabled,
        bus_number,
        device_number,
        function_number,
        register_number,
    )
}

// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use byteorder::{ByteOrder, LittleEndian};

use std;
use std::fmt::{self, Display};
use std::os::unix::io::RawFd;

use kvm::Datamatch;
use resources::{Error as SystemAllocatorFaliure, SystemAllocator};
use sys_util::EventFd;

use crate::pci::pci_configuration::{self, PciConfiguration};
use crate::pci::PciInterruptPin;
use crate::BusDevice;

#[derive(Debug)]
pub enum Error {
    /// Setup of the device capabilities failed.
    CapabilitiesSetup(pci_configuration::Error),
    /// Allocating space for an IO BAR failed.
    IoAllocationFailed(u64, SystemAllocatorFaliure),
    /// Registering an IO BAR failed.
    IoRegistrationFailed(u64, pci_configuration::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            CapabilitiesSetup(e) => write!(f, "failed to add capability {}", e),
            IoAllocationFailed(size, e) => write!(
                f,
                "failed to allocate space for an IO BAR, size={}: {}",
                size, e
            ),
            IoRegistrationFailed(addr, e) => {
                write!(f, "failed to register an IO BAR, addr={} err={}", addr, e)
            }
        }
    }
}

pub trait PciDevice: Send {
    /// Returns a label suitable for debug output.
    fn debug_label(&self) -> String;
    /// Assign a unique bus and device number to this device.
    fn assign_bus_dev(&mut self, _bus: u8, _device: u8 /*u5*/) {}
    /// A vector of device-specific file descriptors that must be kept open
    /// after jailing. Must be called before the process is jailed.
    fn keep_fds(&self) -> Vec<RawFd>;
    /// Assign a legacy PCI IRQ to this device.
    /// The device may write to `irq_evt` to trigger an interrupt.
    /// When `irq_resample_evt` is signaled, the device should re-assert `irq_evt` if necessary.
    fn assign_irq(
        &mut self,
        _irq_evt: EventFd,
        _irq_resample_evt: EventFd,
        _irq_num: u32,
        _irq_pin: PciInterruptPin,
    ) {
    }
    /// Allocates the needed IO BAR space using the `allocate` function which takes a size and
    /// returns an address. Returns a Vec of (address, length) tuples.
    fn allocate_io_bars(&mut self, _resources: &mut SystemAllocator) -> Result<Vec<(u64, u64)>> {
        Ok(Vec::new())
    }

    /// Allocates the needed device BAR space. Returns a Vec of (address, length) tuples.
    /// Unlike MMIO BARs (see allocate_io_bars), device BARs are not expected to incur VM exits
    /// - these BARs represent normal memory.
    fn allocate_device_bars(
        &mut self,
        _resources: &mut SystemAllocator,
    ) -> Result<Vec<(u64, u64)>> {
        Ok(Vec::new())
    }

    /// Register any capabilties specified by the device.
    fn register_device_capabilities(&mut self) -> Result<()> {
        Ok(())
    }

    /// Gets a list of ioeventfds that should be registered with the running VM. The list is
    /// returned as a Vec of (eventfd, addr, datamatch) tuples.
    fn ioeventfds(&self) -> Vec<(&EventFd, u64, Datamatch)> {
        Vec::new()
    }
    /// Gets the configuration registers of the Pci Device.
    fn config_registers(&self) -> &PciConfiguration; // TODO - remove these
    /// Gets the configuration registers of the Pci Device for modification.
    fn config_registers_mut(&mut self) -> &mut PciConfiguration;
    /// Reads from a BAR region mapped in to the device.
    /// * `addr` - The guest address inside the BAR.
    /// * `data` - Filled with the data from `addr`.
    fn read_bar(&mut self, addr: u64, data: &mut [u8]);
    /// Writes to a BAR region mapped in to the device.
    /// * `addr` - The guest address inside the BAR.
    /// * `data` - The data to write.
    fn write_bar(&mut self, addr: u64, data: &[u8]);
    /// Invoked when the device is sandboxed.
    fn on_device_sandboxed(&mut self) {}
}

impl<T: PciDevice> BusDevice for T {
    fn debug_label(&self) -> String {
        PciDevice::debug_label(self)
    }

    fn read(&mut self, offset: u64, data: &mut [u8]) {
        self.read_bar(offset, data)
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        self.write_bar(offset, data)
    }

    fn config_register_write(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        if offset as usize + data.len() > 4 {
            return;
        }

        let regs = self.config_registers_mut();

        match data.len() {
            1 => regs.write_byte(reg_idx * 4 + offset as usize, data[0]),
            2 => regs.write_word(
                reg_idx * 4 + offset as usize,
                (data[0] as u16) | (data[1] as u16) << 8,
            ),
            4 => regs.write_reg(reg_idx, LittleEndian::read_u32(data)),
            _ => (),
        }
    }

    fn config_register_read(&self, reg_idx: usize) -> u32 {
        self.config_registers().read_reg(reg_idx)
    }

    fn on_sandboxed(&mut self) {
        self.on_device_sandboxed();
    }
}

impl<T: PciDevice + ?Sized> PciDevice for Box<T> {
    /// Returns a label suitable for debug output.
    fn debug_label(&self) -> String {
        (**self).debug_label()
    }
    fn assign_bus_dev(&mut self, bus: u8, device: u8 /*u5*/) {
        (**self).assign_bus_dev(bus, device)
    }
    fn keep_fds(&self) -> Vec<RawFd> {
        (**self).keep_fds()
    }
    fn assign_irq(
        &mut self,
        irq_evt: EventFd,
        irq_resample_evt: EventFd,
        irq_num: u32,
        irq_pin: PciInterruptPin,
    ) {
        (**self).assign_irq(irq_evt, irq_resample_evt, irq_num, irq_pin)
    }
    fn allocate_io_bars(&mut self, resources: &mut SystemAllocator) -> Result<Vec<(u64, u64)>> {
        (**self).allocate_io_bars(resources)
    }
    fn allocate_device_bars(&mut self, resources: &mut SystemAllocator) -> Result<Vec<(u64, u64)>> {
        (**self).allocate_device_bars(resources)
    }
    fn register_device_capabilities(&mut self) -> Result<()> {
        (**self).register_device_capabilities()
    }
    fn ioeventfds(&self) -> Vec<(&EventFd, u64, Datamatch)> {
        (**self).ioeventfds()
    }
    fn config_registers(&self) -> &PciConfiguration {
        (**self).config_registers()
    }
    fn config_registers_mut(&mut self) -> &mut PciConfiguration {
        (**self).config_registers_mut()
    }
    fn read_bar(&mut self, addr: u64, data: &mut [u8]) {
        (**self).read_bar(addr, data)
    }
    fn write_bar(&mut self, addr: u64, data: &[u8]) {
        (**self).write_bar(addr, data)
    }
    /// Invoked when the device is sandboxed.
    fn on_device_sandboxed(&mut self) {
        (**self).on_device_sandboxed()
    }
}

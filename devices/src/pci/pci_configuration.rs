// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use pci::PciInterruptPin;

// The number of 32bit registers in the config space, 256 bytes.
const NUM_CONFIGURATION_REGISTERS: usize = 64;

const BAR0_REG: usize = 4;
const BAR_IO_ADDR_MASK: u32 = 0xffff_fffc;
const BAR_IO_BIT: u32 = 0x0000_0001;
const BAR_MEM_ADDR_MASK: u32 = 0xffff_fff0;
const NUM_BAR_REGS: usize = 6;

const INTERRUPT_LINE_PIN_REG: usize = 15;

/// Represents the types of PCI headers allowed in the configuration registers.
#[derive(Copy, Clone)]
pub enum PciHeaderType {
    Device,
    Bridge,
}

/// Classes of PCI nodes.
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciClassCode {
    TooOld,
    MassStorage,
    NetworkController,
    DisplayController,
    MultimediaController,
    MemoryController,
    BridgeDevice,
    SimpleCommunicationController,
    BaseSystemPeripheral,
    InputDevice,
    DockingStation,
    Processor,
    SerialBusController,
    WirelessController,
    IntelligentIoController,
    EncryptionController,
    DataAcquisitionSignalProcessing,
    Other = 0xff,
}

impl PciClassCode {
    pub fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// A PCI sublcass. Each class in `PciClassCode` can specify a unique set of subclasses. This trait
/// is implemented by each subclass. It allows use of a trait object to generate configurations.
pub trait PciSubclass {
    /// Convert this subclass to the value used in the PCI specification.
    fn get_register_value(&self) -> u8;
}

/// Subclasses of the MultimediaController class.
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciMultimediaSubclass {
    VideoController = 0x00,
    AudioController = 0x01,
    TelephonyDevice = 0x02,
    AudioDevice = 0x03,
    Other = 0x80,
}

impl PciSubclass for PciMultimediaSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// Subclasses of the BridgeDevice
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciBridgeSubclass {
    HostBridge = 0x00,
    IsaBridge = 0x01,
    EisaBridge = 0x02,
    McaBridge = 0x03,
    PciToPciBridge = 0x04,
    PcmciaBridge = 0x05,
    NuBusBridge = 0x06,
    CardBusBridge = 0x07,
    RACEwayBridge = 0x08,
    PciToPciSemiTransparentBridge = 0x09,
    InfiniBrandToPciHostBridge = 0x0a,
    OtherBridgeDevice = 0x80,
}

impl PciSubclass for PciBridgeSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// Contains the configuration space of a PCI node.
/// See the [specification](https://en.wikipedia.org/wiki/PCI_configuration_space).
/// The configuration space is accessed with DWORD reads and writes from the guest.
pub struct PciConfiguration {
    registers: [u32; NUM_CONFIGURATION_REGISTERS],
    writable_bits: [u32; NUM_CONFIGURATION_REGISTERS], // writable bits for each register.
    num_bars: usize,
}

impl PciConfiguration {
    pub fn new(
        vendor_id: u16,
        device_id: u16,
        class_code: PciClassCode,
        subclass: &PciSubclass,
        header_type: PciHeaderType,
    ) -> Self {
        let mut registers = [0u32; NUM_CONFIGURATION_REGISTERS];
        registers[0] = u32::from(device_id) << 16 | u32::from(vendor_id);
        registers[2] = u32::from(class_code.get_register_value()) << 24
            | u32::from(subclass.get_register_value()) << 16;
        match header_type {
            PciHeaderType::Device => (),
            PciHeaderType::Bridge => registers[3] = 0x0001_0000,
        };
        PciConfiguration {
            registers,
            writable_bits: [0xffff_ffff; NUM_CONFIGURATION_REGISTERS],
            num_bars: 0,
        }
    }

    /// Reads a 32bit register from `reg_idx` in the register map.
    pub fn read_reg(&self, reg_idx: usize) -> u32 {
        *(self.registers.get(reg_idx).unwrap_or(&0xffff_ffff))
    }

    /// Writes a 32bit register to `reg_idx` in the register map.
    pub fn write_reg(&mut self, reg_idx: usize, value: u32) {
        if let Some(r) = self.registers.get_mut(reg_idx) {
            *r = value & self.writable_bits[reg_idx];
        } else {
            warn!("bad PCI register write {}", reg_idx);
        }
    }

    /// Writes a 16bit word to `offset`. `offset` must be 16bit aligned.
    pub fn write_word(&mut self, offset: usize, value: u16) {
        let shift = match offset % 4 {
            0 => 0,
            2 => 16,
            _ => {
                warn!("bad PCI config write offset {}", offset);
                return;
            }
        };
        let reg_idx = offset / 4;

        if let Some(r) = self.registers.get_mut(reg_idx) {
            let writable_mask = self.writable_bits[reg_idx];
            let mask = (0xffffu32 << shift) & writable_mask;
            let shifted_value = (u32::from(value) << shift) & writable_mask;
            *r = *r & !mask | shifted_value;
        } else {
            warn!("bad PCI config write offset {}", offset);
        }
    }

    /// Writes a byte to `offset`.
    pub fn write_byte(&mut self, offset: usize, value: u8) {
        let shift = (offset % 4) * 8;
        let reg_idx = offset / 4;

        if let Some(r) = self.registers.get_mut(reg_idx) {
            let writable_mask = self.writable_bits[reg_idx];
            let mask = (0xffu32 << shift) & writable_mask;
            let shifted_value = (u32::from(value) << shift) & writable_mask;
            *r = *r & !mask | shifted_value;
        } else {
            warn!("bad PCI config write offset {}", offset);
        }
    }

    // Add either an IO or memory region, depending on `mem_type` mask, which is ORed in to the
    // value before saving it.
    fn add_bar(&mut self, addr: u64, size: u64, addr_mask: u32, mem_type: u32) -> Option<usize> {
        if self.num_bars >= NUM_BAR_REGS {
            return None;
        }
        if size.count_ones() != 1 {
            return None;
        }

        // TODO(dgreid) Allow 64 bit address and size.
        if addr.checked_add(size)? > u64::from(u32::max_value()) {
                return None;
        }

        let bar_idx = BAR0_REG + self.num_bars;

        self.registers[bar_idx] = addr as u32 & addr_mask | mem_type;
        // The first writable bit represents the size of the region.
        self.writable_bits[bar_idx] = !(size - 1) as u32;

        self.num_bars += 1;
        Some(bar_idx)
    }

    /// Adds a memory region of `size` at `addr`. Configures the next available BAR register to
    /// report this region and size to the guest kernel. Returns 'None' if all BARs are full, or
    /// `Some(BarIndex)` on success. `size` must be a power of 2.
    pub fn add_memory_region(&mut self, addr: u64, size: u64) -> Option<usize> {
        self.add_bar(addr, size, BAR_MEM_ADDR_MASK, 0)
    }

    /// Adds an IO region of `size` at `addr`. Configures the next available BAR register to
    /// report this region and size to the guest kernel. Returns 'None' if all BARs are full, or
    /// `Some(BarIndex)` on success. `size` must be a power of 2.
    pub fn add_io_region(&mut self, addr: u64, size: u64) -> Option<usize> {
        self.add_bar(addr, size, BAR_IO_ADDR_MASK, BAR_IO_BIT)
    }

    /// Returns the address of the given BAR region.
    pub fn get_bar_addr(&self, bar_num: usize) -> u32 {
        let bar_idx = BAR0_REG + bar_num;

        self.registers[bar_idx] & BAR_MEM_ADDR_MASK
    }

    /// Configures the IRQ line and pin used by this device.
    pub fn set_irq(&mut self, line: u8, pin: PciInterruptPin) {
        // `pin` is 1-based in the pci config space.
        let pin_idx = (pin as u32) + 1;
        self.registers[INTERRUPT_LINE_PIN_REG] = (self.registers[INTERRUPT_LINE_PIN_REG]
            & 0xffff_0000) | (pin_idx << 8)
            | u32::from(line);
    }
}

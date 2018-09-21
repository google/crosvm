// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use pci::PciInterruptPin;

// The number of 32bit registers in the config space, 256 bytes.
const NUM_CONFIGURATION_REGISTERS: usize = 64;

const STATUS_REG: usize = 1;
const STATUS_REG_CAPABILITIES_USED_MASK: u32 = 0x0010_0000;
const BAR0_REG: usize = 4;
const BAR_IO_ADDR_MASK: u32 = 0xffff_fffc;
const BAR_IO_BIT: u32 = 0x0000_0001;
const BAR_MEM_ADDR_MASK: u32 = 0xffff_fff0;
const NUM_BAR_REGS: usize = 6;
const CAPABILITY_LIST_HEAD_OFFSET: usize = 0x34;
const FIRST_CAPABILITY_OFFSET: usize = 0x40;
const CAPABILITY_MAX_OFFSET: usize = 192;

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

/// Subclass of the SerialBus
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciSerialBusSubClass {
    Firewire = 0x00,
    ACCESSbus = 0x01,
    SSA = 0x02,
    USB = 0x03,
}

impl PciSubclass for PciSerialBusSubClass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// A PCI class programming interface. Each combination of `PciClassCode` and
/// `PciSubclass` can specify a set of register-level programming interfaces.
/// This trait is implemented by each programming interface.
/// It allows use of a trait object to generate configurations.
pub trait PciProgrammingInterface {
    /// Convert this programming interface to the value used in the PCI specification.
    fn get_register_value(&self) -> u8;
}

/// Types of PCI capabilities.
pub enum PciCapabilityID {
    ListID = 0,
    PowerManagement = 0x01,
    AcceleratedGraphicsPort = 0x02,
    VitalProductData = 0x03,
    SlotIdentification = 0x04,
    MessageSignalledInterrupts = 0x05,
    CompactPCIHotSwap = 0x06,
    PCIX = 0x07,
    HyperTransport = 0x08,
    VendorSpecific = 0x09,
    Debugport = 0x0A,
    CompactPCICentralResourceControl = 0x0B,
    PCIStandardHotPlugController = 0x0C,
    BridgeSubsystemVendorDeviceID = 0x0D,
    AGPTargetPCIPCIbridge = 0x0E,
    SecureDevice = 0x0F,
    PCIExpress = 0x10,
    MSIX = 0x11,
    SATADataIndexConf = 0x12,
    PCIAdvancedFeatures = 0x13,
    PCIEnhancedAllocation = 0x14,
}

/// A PCI capability list. Devices can optionally specify capabilities in their configuration space.
pub trait PciCapability {
    fn bytes(&self) -> &[u8];
    fn id(&self) -> PciCapabilityID;
}

/// Contains the configuration space of a PCI node.
/// See the [specification](https://en.wikipedia.org/wiki/PCI_configuration_space).
/// The configuration space is accessed with DWORD reads and writes from the guest.
pub struct PciConfiguration {
    registers: [u32; NUM_CONFIGURATION_REGISTERS],
    writable_bits: [u32; NUM_CONFIGURATION_REGISTERS], // writable bits for each register.
    num_bars: usize,
    // Contains the byte offset and size of the last capability.
    last_capability: Option<(usize, usize)>,
}

impl PciConfiguration {
    pub fn new(
        vendor_id: u16,
        device_id: u16,
        class_code: PciClassCode,
        subclass: &PciSubclass,
        programming_interface: Option<&PciProgrammingInterface>,
        header_type: PciHeaderType,
        subsystem_vendor_id: u16,
        subsystem_id: u16,
    ) -> Self {
        let mut registers = [0u32; NUM_CONFIGURATION_REGISTERS];
        registers[0] = u32::from(device_id) << 16 | u32::from(vendor_id);
        let pi = if let Some(pi) = programming_interface {
            pi.get_register_value()
        } else {
            0
        };
        registers[2] = u32::from(class_code.get_register_value()) << 24
            | u32::from(subclass.get_register_value()) << 16
            | u32::from(pi) << 8;
        match header_type {
            PciHeaderType::Device => (),
            PciHeaderType::Bridge => registers[3] = 0x0001_0000,
        };
        registers[11] = u32::from(subsystem_id) << 16 | u32::from(subsystem_vendor_id);
        PciConfiguration {
            registers,
            writable_bits: [0xffff_ffff; NUM_CONFIGURATION_REGISTERS],
            num_bars: 0,
            last_capability: None,
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

    /// Adds the capability `cap_data` to the list of capabilities.
    /// `cap_data` should not include the two-byte PCI capability header (type, next);
    /// it will be generated automatically based on `cap_data.id()`.
    pub fn add_capability(&mut self, cap_data: &PciCapability) -> Option<usize> {
        let total_len = cap_data.bytes().len() + 2;
        // Check that the length is valid.
        if cap_data.bytes().len() < 1 {
            return None;
        }
        let (cap_offset, tail_offset) = match self.last_capability {
            Some((offset, len)) => (Self::next_dword(offset, len), offset + 1),
            None => (FIRST_CAPABILITY_OFFSET, CAPABILITY_LIST_HEAD_OFFSET),
        };
        if cap_offset.checked_add(cap_data.bytes().len() + 2)? > CAPABILITY_MAX_OFFSET {
            return None;
        }
        self.registers[STATUS_REG] |= STATUS_REG_CAPABILITIES_USED_MASK;
        self.write_byte(tail_offset, cap_offset as u8);
        self.write_byte(cap_offset, cap_data.id() as u8);
        self.write_byte(cap_offset + 1, 0); // Next pointer.
        for (i, byte) in cap_data.bytes().iter().enumerate() {
            self.write_byte(cap_offset + i + 2, *byte);
        }
        self.last_capability = Some((cap_offset, total_len));
        Some(cap_offset)
    }

    // Find the next aligned offset after the one given.
    fn next_dword(offset: usize, len: usize) -> usize {
        let next = offset + len;
        (next + 3) & !3
    }
}

#[cfg(test)]
mod tests {
    use data_model::DataInit;

    use super::*;

    #[repr(packed)]
    #[derive(Clone, Copy)]
    #[allow(dead_code)]
    struct TestCap {
        len: u8,
        foo: u8,
    }

    // It is safe to implement DataInit; all members are simple numbers and any value is valid.
    unsafe impl DataInit for TestCap {}

    impl PciCapability for TestCap {
        fn bytes(&self) -> &[u8] {
            self.as_slice()
        }

        fn id(&self) -> PciCapabilityID {
            PciCapabilityID::VendorSpecific
        }
    }

    #[test]
    fn add_capability() {
        let mut cfg = PciConfiguration::new(
            0x1234,
            0x5678,
            PciClassCode::MultimediaController,
            &PciMultimediaSubclass::AudioController,
            None,
            PciHeaderType::Device,
            0xABCD,
            0x2468,
        );

        // Add two capabilities with different contents.
        let cap1 = TestCap { len: 4, foo: 0xAA };
        let cap1_offset = cfg.add_capability(&cap1).unwrap();
        assert_eq!(cap1_offset % 4, 0);

        let cap2 = TestCap { len: 0x04, foo: 0x55 };
        let cap2_offset = cfg.add_capability(&cap2).unwrap();
        assert_eq!(cap2_offset % 4, 0);

        // The capability list head should be pointing to cap1.
        let cap_ptr = cfg.read_reg(CAPABILITY_LIST_HEAD_OFFSET / 4) & 0xFF;
        assert_eq!(cap1_offset, cap_ptr as usize);

        // Verify the contents of the capabilities.
        let cap1_data = cfg.read_reg(cap1_offset / 4);
        assert_eq!(cap1_data & 0xFF, 0x09); // capability ID
        assert_eq!((cap1_data >> 8) & 0xFF, cap2_offset as u32); // next capability pointer
        assert_eq!((cap1_data >> 16) & 0xFF, 0x04); // cap1.len
        assert_eq!((cap1_data >> 24) & 0xFF, 0xAA); // cap1.foo

        let cap2_data = cfg.read_reg(cap2_offset / 4);
        assert_eq!(cap2_data & 0xFF, 0x09); // capability ID
        assert_eq!((cap2_data >> 8) & 0xFF, 0x00); // next capability pointer
        assert_eq!((cap2_data >> 16) & 0xFF, 0x04); // cap2.len
        assert_eq!((cap2_data >> 24) & 0xFF, 0x55); // cap2.foo
    }

    #[derive(Copy, Clone)]
    enum TestPI {
        Test = 0x5a,
    }

    impl PciProgrammingInterface for TestPI {
        fn get_register_value(&self) -> u8 {
            *self as u8
        }
    }

    #[test]
    fn class_code() {
        let cfg = PciConfiguration::new(
            0x1234,
            0x5678,
            PciClassCode::MultimediaController,
            &PciMultimediaSubclass::AudioController,
            Some(&TestPI::Test),
            PciHeaderType::Device,
            0xABCD,
            0x2468,
        );

        let class_reg = cfg.read_reg(2);
        let class_code = (class_reg >> 24) & 0xFF;
        let subclass = (class_reg >> 16) & 0xFF;
        let prog_if = (class_reg >> 8) & 0xFF;
        assert_eq!(class_code, 0x04);
        assert_eq!(subclass, 0x01);
        assert_eq!(prog_if, 0x5a);
    }
}

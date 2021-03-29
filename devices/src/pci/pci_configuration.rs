// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryInto;
use std::fmt::{self, Display};

use crate::pci::PciInterruptPin;
use base::warn;

// The number of 32bit registers in the config space, 256 bytes.
const NUM_CONFIGURATION_REGISTERS: usize = 64;

pub const COMMAND_REG: usize = 1;
pub const COMMAND_REG_IO_SPACE_MASK: u32 = 0x0000_0001;
pub const COMMAND_REG_MEMORY_SPACE_MASK: u32 = 0x0000_0002;
const STATUS_REG: usize = 1;
const STATUS_REG_CAPABILITIES_USED_MASK: u32 = 0x0010_0000;
const BAR0_REG: usize = 4;
const BAR_IO_ADDR_MASK: u32 = 0xffff_fffc;
const BAR_IO_MIN_SIZE: u64 = 4;
const BAR_MEM_ADDR_MASK: u32 = 0xffff_fff0;
const BAR_MEM_MIN_SIZE: u64 = 16;
const NUM_BAR_REGS: usize = 6;
const CAPABILITY_LIST_HEAD_OFFSET: usize = 0x34;
const FIRST_CAPABILITY_OFFSET: usize = 0x40;
const CAPABILITY_MAX_OFFSET: usize = 255;

const INTERRUPT_LINE_PIN_REG: usize = 15;

/// Represents the types of PCI headers allowed in the configuration registers.
#[allow(dead_code)]
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

/// Subclasses of the DisplayController class.
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciDisplaySubclass {
    VgaCompatibleController = 0x00,
    XgaCompatibleController = 0x01,
    ThreeDController = 0x02,
    Other = 0x80,
}

impl PciSubclass for PciDisplaySubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
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
    bar_used: [bool; NUM_BAR_REGS],
    bar_configs: [Option<PciBarConfiguration>; NUM_BAR_REGS],
    // Contains the byte offset and size of the last capability.
    last_capability: Option<(usize, usize)>,
}

/// See pci_regs.h in kernel
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum PciBarRegionType {
    Memory32BitRegion = 0,
    IORegion = 0x01,
    Memory64BitRegion = 0x04,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum PciBarPrefetchable {
    NotPrefetchable = 0,
    Prefetchable = 0x08,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct PciBarConfiguration {
    addr: u64,
    size: u64,
    reg_idx: usize,
    region_type: PciBarRegionType,
    prefetchable: PciBarPrefetchable,
}

pub struct PciBarIter<'a> {
    config: &'a PciConfiguration,
    bar_num: usize,
}

impl<'a> Iterator for PciBarIter<'a> {
    type Item = PciBarConfiguration;

    fn next(&mut self) -> Option<Self::Item> {
        while self.bar_num < NUM_BAR_REGS {
            let bar_config = self.config.get_bar_configuration(self.bar_num);
            self.bar_num += 1;
            if let Some(bar_config) = bar_config {
                return Some(bar_config);
            }
        }

        None
    }
}

#[derive(Debug, PartialEq)]
pub enum Error {
    BarAddressInvalid(u64, u64),
    BarAlignmentInvalid(u64, u64),
    BarInUse(usize),
    BarInUse64(usize),
    BarInvalid(usize),
    BarInvalid64(usize),
    BarSizeInvalid(u64),
    CapabilityEmpty,
    CapabilityLengthInvalid(usize),
    CapabilitySpaceFull(usize),
}
pub type Result<T> = std::result::Result<T, Error>;

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;
        match self {
            BarAddressInvalid(a, s) => write!(f, "address {} size {} too big", a, s),
            BarAlignmentInvalid(a, s) => write!(f, "address {} is not aligned to size {}", a, s),
            BarInUse(b) => write!(f, "bar {} already used", b),
            BarInUse64(b) => write!(f, "64bit bar {} already used(requires two regs)", b),
            BarInvalid(b) => write!(f, "bar {} invalid, max {}", b, NUM_BAR_REGS - 1),
            BarInvalid64(b) => write!(
                f,
                "64bitbar {} invalid, requires two regs, max {}",
                b,
                NUM_BAR_REGS - 1
            ),
            BarSizeInvalid(s) => write!(f, "bar address {} not a power of two", s),
            CapabilityEmpty => write!(f, "empty capabilities are invalid"),
            CapabilityLengthInvalid(l) => write!(f, "Invalid capability length {}", l),
            CapabilitySpaceFull(s) => write!(f, "capability of size {} doesn't fit", s),
        }
    }
}

impl PciConfiguration {
    pub fn new(
        vendor_id: u16,
        device_id: u16,
        class_code: PciClassCode,
        subclass: &dyn PciSubclass,
        programming_interface: Option<&dyn PciProgrammingInterface>,
        header_type: PciHeaderType,
        subsystem_vendor_id: u16,
        subsystem_id: u16,
        revision_id: u8,
    ) -> Self {
        let mut registers = [0u32; NUM_CONFIGURATION_REGISTERS];
        let mut writable_bits = [0u32; NUM_CONFIGURATION_REGISTERS];
        registers[0] = u32::from(device_id) << 16 | u32::from(vendor_id);
        // TODO(dverkamp): Status should be write-1-to-clear
        writable_bits[1] = 0x0000_ffff; // Status (r/o), command (r/w)
        let pi = if let Some(pi) = programming_interface {
            pi.get_register_value()
        } else {
            0
        };
        registers[2] = u32::from(class_code.get_register_value()) << 24
            | u32::from(subclass.get_register_value()) << 16
            | u32::from(pi) << 8
            | u32::from(revision_id);
        writable_bits[3] = 0x0000_00ff; // Cacheline size (r/w)
        match header_type {
            PciHeaderType::Device => {
                registers[3] = 0x0000_0000; // Header type 0 (device)
                writable_bits[15] = 0x0000_00ff; // Interrupt line (r/w)
            }
            PciHeaderType::Bridge => {
                registers[3] = 0x0001_0000; // Header type 1 (bridge)
                writable_bits[9] = 0xfff0_fff0; // Memory base and limit
                writable_bits[15] = 0xffff_00ff; // Bridge control (r/w), interrupt line (r/w)
            }
        };
        registers[11] = u32::from(subsystem_id) << 16 | u32::from(subsystem_vendor_id);

        PciConfiguration {
            registers,
            writable_bits,
            bar_used: [false; NUM_BAR_REGS],
            bar_configs: [None; NUM_BAR_REGS],
            last_capability: None,
        }
    }

    /// Reads a 32bit register from `reg_idx` in the register map.
    pub fn read_reg(&self, reg_idx: usize) -> u32 {
        *(self.registers.get(reg_idx).unwrap_or(&0xffff_ffff))
    }

    /// Writes data to PciConfiguration.registers.
    /// `reg_idx` - index into PciConfiguration.registers.
    /// `offset`  - PciConfiguration.registers is in unit of DWord, offset define byte
    ///             offset in the DWrod.
    /// `data`    - The data to write.
    pub fn write_reg(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        let reg_offset = reg_idx * 4 + offset as usize;
        match data.len() {
            1 => self.write_byte(reg_offset, data[0]),
            2 => self.write_word(reg_offset, u16::from_le_bytes(data.try_into().unwrap())),
            4 => self.write_dword(reg_offset, u32::from_le_bytes(data.try_into().unwrap())),
            _ => (),
        }
    }

    /// Writes a 32bit dword to `offset`. `offset` must be 32bit aligned.
    fn write_dword(&mut self, offset: usize, value: u32) {
        if offset % 4 != 0 {
            warn!("bad PCI config dword write offset {}", offset);
            return;
        }
        let reg_idx = offset / 4;
        if let Some(r) = self.registers.get_mut(reg_idx) {
            *r = (*r & !self.writable_bits[reg_idx]) | (value & self.writable_bits[reg_idx]);
        } else {
            warn!("bad PCI dword write {}", offset);
        }
    }

    /// Writes a 16bit word to `offset`. `offset` must be 16bit aligned.
    fn write_word(&mut self, offset: usize, value: u16) {
        let shift = match offset % 4 {
            0 => 0,
            2 => 16,
            _ => {
                warn!("bad PCI config word write offset {}", offset);
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
            warn!("bad PCI config word write offset {}", offset);
        }
    }

    /// Writes a byte to `offset`.
    fn write_byte(&mut self, offset: usize, value: u8) {
        self.write_byte_internal(offset, value, true);
    }

    /// Writes a byte to `offset`, optionally enforcing read-only bits.
    fn write_byte_internal(&mut self, offset: usize, value: u8, apply_writable_mask: bool) {
        let shift = (offset % 4) * 8;
        let reg_idx = offset / 4;

        if let Some(r) = self.registers.get_mut(reg_idx) {
            let writable_mask = if apply_writable_mask {
                self.writable_bits[reg_idx]
            } else {
                0xffff_ffff
            };
            let mask = (0xffu32 << shift) & writable_mask;
            let shifted_value = (u32::from(value) << shift) & writable_mask;
            *r = *r & !mask | shifted_value;
        } else {
            warn!("bad PCI config byte write offset {}", offset);
        }
    }

    /// Adds a region specified by `config`.  Configures the specified BAR(s) to
    /// report this region and size to the guest kernel.  Enforces a few constraints
    /// (i.e, region size must be power of two, register not already used). Returns 'None' on
    /// failure all, `Some(BarIndex)` on success.
    pub fn add_pci_bar(&mut self, config: PciBarConfiguration) -> Result<usize> {
        if config.reg_idx >= NUM_BAR_REGS {
            return Err(Error::BarInvalid(config.reg_idx));
        }

        if self.bar_used[config.reg_idx] {
            return Err(Error::BarInUse(config.reg_idx));
        }

        if config.size.count_ones() != 1 {
            return Err(Error::BarSizeInvalid(config.size));
        }

        let min_size = if config.region_type == PciBarRegionType::IORegion {
            BAR_IO_MIN_SIZE
        } else {
            BAR_MEM_MIN_SIZE
        };

        if config.size < min_size {
            return Err(Error::BarSizeInvalid(config.size));
        }

        if config.addr % config.size != 0 {
            return Err(Error::BarAlignmentInvalid(config.addr, config.size));
        }

        let bar_idx = BAR0_REG + config.reg_idx;
        let end_addr = config
            .addr
            .checked_add(config.size)
            .ok_or(Error::BarAddressInvalid(config.addr, config.size))?;
        match config.region_type {
            PciBarRegionType::Memory32BitRegion | PciBarRegionType::IORegion => {
                if end_addr > u64::from(u32::max_value()) {
                    return Err(Error::BarAddressInvalid(config.addr, config.size));
                }
            }
            PciBarRegionType::Memory64BitRegion => {
                if config.reg_idx + 1 >= NUM_BAR_REGS {
                    return Err(Error::BarInvalid64(config.reg_idx));
                }

                if end_addr > u64::max_value() {
                    return Err(Error::BarAddressInvalid(config.addr, config.size));
                }

                if self.bar_used[config.reg_idx + 1] {
                    return Err(Error::BarInUse64(config.reg_idx));
                }

                self.registers[bar_idx + 1] = (config.addr >> 32) as u32;
                self.writable_bits[bar_idx + 1] = !((config.size - 1) >> 32) as u32;
                self.bar_used[config.reg_idx + 1] = true;
            }
        }

        let (mask, lower_bits) = match config.region_type {
            PciBarRegionType::Memory32BitRegion | PciBarRegionType::Memory64BitRegion => {
                self.registers[COMMAND_REG] |= COMMAND_REG_MEMORY_SPACE_MASK;
                (
                    BAR_MEM_ADDR_MASK,
                    config.prefetchable as u32 | config.region_type as u32,
                )
            }
            PciBarRegionType::IORegion => {
                self.registers[COMMAND_REG] |= COMMAND_REG_IO_SPACE_MASK;
                (BAR_IO_ADDR_MASK, config.region_type as u32)
            }
        };

        self.registers[bar_idx] = ((config.addr as u32) & mask) | lower_bits;
        self.writable_bits[bar_idx] = !(config.size - 1) as u32;
        self.bar_used[config.reg_idx] = true;
        self.bar_configs[config.reg_idx] = Some(config);
        Ok(config.reg_idx)
    }

    /// Returns an iterator of the currently configured base address registers.
    #[allow(dead_code)] // TODO(dverkamp): remove this once used
    pub fn get_bars(&self) -> PciBarIter {
        PciBarIter {
            config: &self,
            bar_num: 0,
        }
    }

    fn get_bar_configuration(&self, bar_num: usize) -> Option<PciBarConfiguration> {
        let config = self.bar_configs.get(bar_num)?;

        if let Some(mut config) = config {
            // The address may have been modified by the guest, so the value in bar_configs
            // may be outdated. Replace it with the current value.
            config.addr = self.get_bar_addr(bar_num);
            Some(config)
        } else {
            None
        }
    }

    /// Returns the type of the given BAR region.
    pub fn get_bar_type(&self, bar_num: usize) -> Option<PciBarRegionType> {
        self.bar_configs.get(bar_num)?.map(|c| c.region_type)
    }

    /// Returns the address of the given BAR region.
    pub fn get_bar_addr(&self, bar_num: usize) -> u64 {
        let bar_idx = BAR0_REG + bar_num;

        let bar_type = match self.get_bar_type(bar_num) {
            Some(t) => t,
            None => return 0,
        };

        match bar_type {
            PciBarRegionType::IORegion => u64::from(self.registers[bar_idx] & BAR_IO_ADDR_MASK),
            PciBarRegionType::Memory32BitRegion => {
                u64::from(self.registers[bar_idx] & BAR_MEM_ADDR_MASK)
            }
            PciBarRegionType::Memory64BitRegion => {
                u64::from(self.registers[bar_idx] & BAR_MEM_ADDR_MASK)
                    | u64::from(self.registers[bar_idx + 1]) << 32
            }
        }
    }

    /// Configures the IRQ line and pin used by this device.
    pub fn set_irq(&mut self, line: u8, pin: PciInterruptPin) {
        // `pin` is 1-based in the pci config space.
        let pin_idx = (pin as u32) + 1;
        self.registers[INTERRUPT_LINE_PIN_REG] = (self.registers[INTERRUPT_LINE_PIN_REG]
            & 0xffff_0000)
            | (pin_idx << 8)
            | u32::from(line);
    }

    /// Adds the capability `cap_data` to the list of capabilities.
    /// `cap_data` should include the two-byte PCI capability header (type, next),
    /// but not populate it. Correct values will be generated automatically based
    /// on `cap_data.id()`.
    pub fn add_capability(&mut self, cap_data: &dyn PciCapability) -> Result<usize> {
        let total_len = cap_data.bytes().len();
        // Check that the length is valid.
        if cap_data.bytes().is_empty() {
            return Err(Error::CapabilityEmpty);
        }
        let (cap_offset, tail_offset) = match self.last_capability {
            Some((offset, len)) => (Self::next_dword(offset, len), offset + 1),
            None => (FIRST_CAPABILITY_OFFSET, CAPABILITY_LIST_HEAD_OFFSET),
        };
        let end_offset = cap_offset
            .checked_add(total_len)
            .ok_or(Error::CapabilitySpaceFull(total_len))?;
        if end_offset > CAPABILITY_MAX_OFFSET {
            return Err(Error::CapabilitySpaceFull(total_len));
        }
        self.registers[STATUS_REG] |= STATUS_REG_CAPABILITIES_USED_MASK;
        self.write_byte_internal(tail_offset, cap_offset as u8, false);
        self.write_byte_internal(cap_offset, cap_data.id() as u8, false);
        self.write_byte_internal(cap_offset + 1, 0, false); // Next pointer.
        for (i, byte) in cap_data.bytes().iter().enumerate().skip(2) {
            self.write_byte_internal(cap_offset + i, *byte, false);
        }
        self.last_capability = Some((cap_offset, total_len));
        Ok(cap_offset)
    }

    // Find the next aligned offset after the one given.
    fn next_dword(offset: usize, len: usize) -> usize {
        let next = offset + len;
        (next + 3) & !3
    }
}

impl Default for PciBarConfiguration {
    fn default() -> Self {
        PciBarConfiguration {
            reg_idx: 0,
            addr: 0,
            size: 0,
            region_type: PciBarRegionType::Memory32BitRegion,
            prefetchable: PciBarPrefetchable::NotPrefetchable,
        }
    }
}

impl PciBarConfiguration {
    pub fn new(
        reg_idx: usize,
        size: u64,
        region_type: PciBarRegionType,
        prefetchable: PciBarPrefetchable,
    ) -> Self {
        PciBarConfiguration {
            reg_idx,
            addr: 0,
            size,
            region_type,
            prefetchable,
        }
    }

    pub fn set_register_index(mut self, reg_idx: usize) -> Self {
        self.reg_idx = reg_idx;
        self
    }

    pub fn get_register_index(&self) -> usize {
        self.reg_idx
    }

    pub fn set_address(mut self, addr: u64) -> Self {
        self.addr = addr;
        self
    }

    pub fn set_size(mut self, size: u64) -> Self {
        self.size = size;
        self
    }

    pub fn get_size(&self) -> u64 {
        self.size
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
        _vndr: u8,
        _next: u8,
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
            0,
        );

        // Add two capabilities with different contents.
        let cap1 = TestCap {
            _vndr: 0,
            _next: 0,
            len: 4,
            foo: 0xAA,
        };
        let cap1_offset = cfg.add_capability(&cap1).unwrap();
        assert_eq!(cap1_offset % 4, 0);

        let cap2 = TestCap {
            _vndr: 0,
            _next: 0,
            len: 0x04,
            foo: 0x55,
        };
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
            0,
        );

        let class_reg = cfg.read_reg(2);
        let class_code = (class_reg >> 24) & 0xFF;
        let subclass = (class_reg >> 16) & 0xFF;
        let prog_if = (class_reg >> 8) & 0xFF;
        assert_eq!(class_code, 0x04);
        assert_eq!(subclass, 0x01);
        assert_eq!(prog_if, 0x5a);
    }

    #[test]
    fn read_only_bits() {
        let mut cfg = PciConfiguration::new(
            0x1234,
            0x5678,
            PciClassCode::MultimediaController,
            &PciMultimediaSubclass::AudioController,
            Some(&TestPI::Test),
            PciHeaderType::Device,
            0xABCD,
            0x2468,
            0,
        );

        // Attempt to overwrite vendor ID and device ID, which are read-only
        cfg.write_reg(0, 0, &[0xBA, 0xAD, 0xF0, 0x0D]);
        // The original vendor and device ID should remain.
        assert_eq!(cfg.read_reg(0), 0x56781234);
    }

    #[test]
    fn query_unused_bar() {
        let cfg = PciConfiguration::new(
            0x1234,
            0x5678,
            PciClassCode::MultimediaController,
            &PciMultimediaSubclass::AudioController,
            Some(&TestPI::Test),
            PciHeaderType::Device,
            0xABCD,
            0x2468,
            0,
        );

        // No BAR 0 has been configured, so these should return None or 0 as appropriate.
        assert_eq!(cfg.get_bar_type(0), None);
        assert_eq!(cfg.get_bar_addr(0), 0);

        let mut bar_iter = cfg.get_bars();
        assert_eq!(bar_iter.next(), None);
    }

    #[test]
    fn add_pci_bar_mem_64bit() {
        let mut cfg = PciConfiguration::new(
            0x1234,
            0x5678,
            PciClassCode::MultimediaController,
            &PciMultimediaSubclass::AudioController,
            Some(&TestPI::Test),
            PciHeaderType::Device,
            0xABCD,
            0x2468,
            0,
        );

        cfg.add_pci_bar(
            PciBarConfiguration::new(
                0,
                0x10,
                PciBarRegionType::Memory64BitRegion,
                PciBarPrefetchable::NotPrefetchable,
            )
            .set_address(0x01234567_89ABCDE0),
        )
        .expect("add_pci_bar failed");

        assert_eq!(
            cfg.get_bar_type(0),
            Some(PciBarRegionType::Memory64BitRegion)
        );
        assert_eq!(cfg.get_bar_addr(0), 0x01234567_89ABCDE0);
        assert_eq!(cfg.writable_bits[BAR0_REG + 1], 0xFFFFFFFF);
        assert_eq!(cfg.writable_bits[BAR0_REG + 0], 0xFFFFFFF0);

        let mut bar_iter = cfg.get_bars();
        assert_eq!(
            bar_iter.next(),
            Some(PciBarConfiguration {
                addr: 0x01234567_89ABCDE0,
                size: 0x10,
                reg_idx: 0,
                region_type: PciBarRegionType::Memory64BitRegion,
                prefetchable: PciBarPrefetchable::NotPrefetchable
            })
        );
        assert_eq!(bar_iter.next(), None);
    }

    #[test]
    fn add_pci_bar_mem_32bit() {
        let mut cfg = PciConfiguration::new(
            0x1234,
            0x5678,
            PciClassCode::MultimediaController,
            &PciMultimediaSubclass::AudioController,
            Some(&TestPI::Test),
            PciHeaderType::Device,
            0xABCD,
            0x2468,
            0,
        );

        cfg.add_pci_bar(
            PciBarConfiguration::new(
                0,
                0x10,
                PciBarRegionType::Memory32BitRegion,
                PciBarPrefetchable::NotPrefetchable,
            )
            .set_address(0x12345670),
        )
        .expect("add_pci_bar failed");

        assert_eq!(
            cfg.get_bar_type(0),
            Some(PciBarRegionType::Memory32BitRegion)
        );
        assert_eq!(cfg.get_bar_addr(0), 0x12345670);
        assert_eq!(cfg.writable_bits[BAR0_REG], 0xFFFFFFF0);

        let mut bar_iter = cfg.get_bars();
        assert_eq!(
            bar_iter.next(),
            Some(PciBarConfiguration {
                addr: 0x12345670,
                size: 0x10,
                reg_idx: 0,
                region_type: PciBarRegionType::Memory32BitRegion,
                prefetchable: PciBarPrefetchable::NotPrefetchable
            })
        );
        assert_eq!(bar_iter.next(), None);
    }

    #[test]
    fn add_pci_bar_io() {
        let mut cfg = PciConfiguration::new(
            0x1234,
            0x5678,
            PciClassCode::MultimediaController,
            &PciMultimediaSubclass::AudioController,
            Some(&TestPI::Test),
            PciHeaderType::Device,
            0xABCD,
            0x2468,
            0,
        );

        cfg.add_pci_bar(
            PciBarConfiguration::new(
                0,
                0x4,
                PciBarRegionType::IORegion,
                PciBarPrefetchable::NotPrefetchable,
            )
            .set_address(0x1230),
        )
        .expect("add_pci_bar failed");

        assert_eq!(cfg.get_bar_type(0), Some(PciBarRegionType::IORegion));
        assert_eq!(cfg.get_bar_addr(0), 0x1230);
        assert_eq!(cfg.writable_bits[BAR0_REG], 0xFFFFFFFC);

        let mut bar_iter = cfg.get_bars();
        assert_eq!(
            bar_iter.next(),
            Some(PciBarConfiguration {
                addr: 0x1230,
                size: 0x4,
                reg_idx: 0,
                region_type: PciBarRegionType::IORegion,
                prefetchable: PciBarPrefetchable::NotPrefetchable
            })
        );
        assert_eq!(bar_iter.next(), None);
    }

    #[test]
    fn add_pci_bar_multiple() {
        let mut cfg = PciConfiguration::new(
            0x1234,
            0x5678,
            PciClassCode::MultimediaController,
            &PciMultimediaSubclass::AudioController,
            Some(&TestPI::Test),
            PciHeaderType::Device,
            0xABCD,
            0x2468,
            0,
        );

        // bar_num 0-1: 64-bit memory
        cfg.add_pci_bar(
            PciBarConfiguration::new(
                0,
                0x10,
                PciBarRegionType::Memory64BitRegion,
                PciBarPrefetchable::NotPrefetchable,
            )
            .set_address(0x01234567_89ABCDE0),
        )
        .expect("add_pci_bar failed");

        // bar 2: 32-bit memory
        cfg.add_pci_bar(
            PciBarConfiguration::new(
                2,
                0x10,
                PciBarRegionType::Memory32BitRegion,
                PciBarPrefetchable::NotPrefetchable,
            )
            .set_address(0x12345670),
        )
        .expect("add_pci_bar failed");

        // bar 3: I/O
        cfg.add_pci_bar(
            PciBarConfiguration::new(
                3,
                0x4,
                PciBarRegionType::IORegion,
                PciBarPrefetchable::NotPrefetchable,
            )
            .set_address(0x1230),
        )
        .expect("add_pci_bar failed");

        // Confirm default memory and I/O region configurations.
        let mut bar_iter = cfg.get_bars();
        assert_eq!(
            bar_iter.next(),
            Some(PciBarConfiguration {
                addr: 0x01234567_89ABCDE0,
                size: 0x10,
                reg_idx: 0,
                region_type: PciBarRegionType::Memory64BitRegion,
                prefetchable: PciBarPrefetchable::NotPrefetchable
            })
        );
        assert_eq!(
            bar_iter.next(),
            Some(PciBarConfiguration {
                addr: 0x12345670,
                size: 0x10,
                reg_idx: 2,
                region_type: PciBarRegionType::Memory32BitRegion,
                prefetchable: PciBarPrefetchable::NotPrefetchable
            })
        );
        assert_eq!(
            bar_iter.next(),
            Some(PciBarConfiguration {
                addr: 0x1230,
                size: 0x4,
                reg_idx: 3,
                region_type: PciBarRegionType::IORegion,
                prefetchable: PciBarPrefetchable::NotPrefetchable
            })
        );
        assert_eq!(bar_iter.next(), None);

        // Reassign the address for BAR 0 and verify that get_memory_regions() matches.
        cfg.write_reg(4 + 0, 0, &0xBBAA9980u32.to_le_bytes());
        cfg.write_reg(4 + 1, 0, &0xFFEEDDCCu32.to_le_bytes());

        let mut bar_iter = cfg.get_bars();
        assert_eq!(
            bar_iter.next(),
            Some(PciBarConfiguration {
                addr: 0xFFEEDDCC_BBAA9980,
                size: 0x10,
                reg_idx: 0,
                region_type: PciBarRegionType::Memory64BitRegion,
                prefetchable: PciBarPrefetchable::NotPrefetchable
            })
        );
        assert_eq!(
            bar_iter.next(),
            Some(PciBarConfiguration {
                addr: 0x12345670,
                size: 0x10,
                reg_idx: 2,
                region_type: PciBarRegionType::Memory32BitRegion,
                prefetchable: PciBarPrefetchable::NotPrefetchable
            })
        );
        assert_eq!(
            bar_iter.next(),
            Some(PciBarConfiguration {
                addr: 0x1230,
                size: 0x4,
                reg_idx: 3,
                region_type: PciBarRegionType::IORegion,
                prefetchable: PciBarPrefetchable::NotPrefetchable
            })
        );
        assert_eq!(bar_iter.next(), None);
    }

    #[test]
    fn add_pci_bar_invalid_size() {
        let mut cfg = PciConfiguration::new(
            0x1234,
            0x5678,
            PciClassCode::MultimediaController,
            &PciMultimediaSubclass::AudioController,
            Some(&TestPI::Test),
            PciHeaderType::Device,
            0xABCD,
            0x2468,
            0,
        );

        // I/O BAR with size 2 (too small)
        assert_eq!(
            cfg.add_pci_bar(
                PciBarConfiguration::new(
                    0,
                    0x2,
                    PciBarRegionType::IORegion,
                    PciBarPrefetchable::NotPrefetchable,
                )
                .set_address(0x1230),
            ),
            Err(Error::BarSizeInvalid(0x2))
        );

        // I/O BAR with size 3 (not a power of 2)
        assert_eq!(
            cfg.add_pci_bar(
                PciBarConfiguration::new(
                    0,
                    0x3,
                    PciBarRegionType::IORegion,
                    PciBarPrefetchable::NotPrefetchable,
                )
                .set_address(0x1230),
            ),
            Err(Error::BarSizeInvalid(0x3))
        );

        // Memory BAR with size 8 (too small)
        assert_eq!(
            cfg.add_pci_bar(
                PciBarConfiguration::new(
                    0,
                    0x8,
                    PciBarRegionType::Memory32BitRegion,
                    PciBarPrefetchable::NotPrefetchable,
                )
                .set_address(0x12345670),
            ),
            Err(Error::BarSizeInvalid(0x8))
        );
    }
}

// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Handles routing to devices in an address space.

use std::cmp::{Ord, Ordering, PartialEq, PartialOrd};
use std::collections::btree_map::BTreeMap;
use std::fmt::{self, Display};
use std::result;
use std::sync::Arc;

use sync::Mutex;

/// Trait for devices that respond to reads or writes in an arbitrary address space.
///
/// The device does not care where it exists in address space as each method is only given an offset
/// into its allocated portion of address space.
#[allow(unused_variables)]
pub trait BusDevice: Send {
    /// Returns a label suitable for debug output.
    fn debug_label(&self) -> String;
    /// Reads at `offset` from this device
    fn read(&mut self, offset: u64, data: &mut [u8]) {}
    /// Writes at `offset` into this device
    fn write(&mut self, offset: u64, data: &[u8]) {}
    /// Sets a register in the configuration space. Only used by PCI.
    /// * `reg_idx` - The index of the config register to modify.
    /// * `offset` - Offset in to the register.
    fn config_register_write(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {}
    /// Gets a register from the configuration space. Only used by PCI.
    /// * `reg_idx` - The index of the config register to read.
    fn config_register_read(&self, reg_idx: usize) -> u32 {
        0
    }
    /// Invoked when the device is sandboxed.
    fn on_sandboxed(&mut self) {}
}

#[derive(Debug)]
pub enum Error {
    /// The insertion failed because the new device overlapped with an old device.
    Overlap,
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            Overlap => write!(f, "new device overlaps with an old device"),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

/// Holds a base and length representing the address space occupied by a `BusDevice`.
///
/// * base - The address at which the range start.
/// * len - The length of the range in bytes.
/// * full_addr - If true, return the full address from `get_device`, otherwise return the offset
///               from `base`
#[derive(Debug, Copy, Clone)]
pub struct BusRange {
    pub base: u64,
    pub len: u64,
    pub full_addr: bool,
}

impl BusRange {
    /// Returns true if `addr` is within the range.
    pub fn contains(&self, addr: u64) -> bool {
        self.base <= addr && addr < self.base + self.len
    }

    /// Returns true if there is overlap with the given range.
    pub fn overlaps(&self, base: u64, len: u64) -> bool {
        self.base < (base + len) && base < self.base + self.len
    }
}

impl Eq for BusRange {}

impl PartialEq for BusRange {
    fn eq(&self, other: &BusRange) -> bool {
        self.base == other.base
    }
}

impl Ord for BusRange {
    fn cmp(&self, other: &BusRange) -> Ordering {
        self.base.cmp(&other.base)
    }
}

impl PartialOrd for BusRange {
    fn partial_cmp(&self, other: &BusRange) -> Option<Ordering> {
        self.base.partial_cmp(&other.base)
    }
}

/// A device container for routing reads and writes over some address space.
///
/// This doesn't have any restrictions on what kind of device or address space this applies to. The
/// only restriction is that no two devices can overlap in this address space.
#[derive(Clone)]
pub struct Bus {
    devices: BTreeMap<BusRange, Arc<Mutex<dyn BusDevice>>>,
}

impl Bus {
    /// Constructs an a bus with an empty address space.
    pub fn new() -> Bus {
        Bus {
            devices: BTreeMap::new(),
        }
    }

    fn first_before(&self, addr: u64) -> Option<(BusRange, &Mutex<dyn BusDevice>)> {
        let (range, dev) = self
            .devices
            .range(
                ..=BusRange {
                    base: addr,
                    len: 1,
                    full_addr: false,
                },
            )
            .rev()
            .next()?;
        Some((*range, dev))
    }

    fn get_device(&self, addr: u64) -> Option<(u64, &Mutex<dyn BusDevice>)> {
        if let Some((range, dev)) = self.first_before(addr) {
            let offset = addr - range.base;
            if offset < range.len {
                if range.full_addr {
                    return Some((addr, dev));
                } else {
                    return Some((offset, dev));
                }
            }
        }
        None
    }

    /// Puts the given device at the given address space.
    pub fn insert(
        &mut self,
        device: Arc<Mutex<dyn BusDevice>>,
        base: u64,
        len: u64,
        full_addr: bool,
    ) -> Result<()> {
        if len == 0 {
            return Err(Error::Overlap);
        }

        // Reject all cases where the new device's range overlaps with an existing device.
        if self
            .devices
            .iter()
            .any(|(range, _dev)| range.overlaps(base, len))
        {
            return Err(Error::Overlap);
        }

        if self
            .devices
            .insert(
                BusRange {
                    base,
                    len,
                    full_addr,
                },
                device,
            )
            .is_some()
        {
            return Err(Error::Overlap);
        }

        Ok(())
    }

    /// Reads data from the device that owns the range containing `addr` and puts it into `data`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn read(&self, addr: u64, data: &mut [u8]) -> bool {
        if let Some((offset, dev)) = self.get_device(addr) {
            dev.lock().read(offset, data);
            true
        } else {
            false
        }
    }

    /// Writes `data` to the device that owns the range containing `addr`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn write(&self, addr: u64, data: &[u8]) -> bool {
        if let Some((offset, dev)) = self.get_device(addr) {
            dev.lock().write(offset, data);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyDevice;
    impl BusDevice for DummyDevice {
        fn debug_label(&self) -> String {
            "dummy device".to_owned()
        }
    }

    struct ConstantDevice;
    impl BusDevice for ConstantDevice {
        fn debug_label(&self) -> String {
            "constant device".to_owned()
        }

        fn read(&mut self, offset: u64, data: &mut [u8]) {
            for (i, v) in data.iter_mut().enumerate() {
                *v = (offset as u8) + (i as u8);
            }
        }

        fn write(&mut self, offset: u64, data: &[u8]) {
            for (i, v) in data.iter().enumerate() {
                assert_eq!(*v, (offset as u8) + (i as u8))
            }
        }
    }

    #[test]
    fn bus_insert() {
        let mut bus = Bus::new();
        let dummy = Arc::new(Mutex::new(DummyDevice));
        assert!(bus.insert(dummy.clone(), 0x10, 0, false).is_err());
        assert!(bus.insert(dummy.clone(), 0x10, 0x10, false).is_ok());
        assert!(bus.insert(dummy.clone(), 0x0f, 0x10, false).is_err());
        assert!(bus.insert(dummy.clone(), 0x10, 0x10, false).is_err());
        assert!(bus.insert(dummy.clone(), 0x10, 0x15, false).is_err());
        assert!(bus.insert(dummy.clone(), 0x12, 0x15, false).is_err());
        assert!(bus.insert(dummy.clone(), 0x12, 0x01, false).is_err());
        assert!(bus.insert(dummy.clone(), 0x0, 0x20, false).is_err());
        assert!(bus.insert(dummy.clone(), 0x20, 0x05, false).is_ok());
        assert!(bus.insert(dummy.clone(), 0x25, 0x05, false).is_ok());
        assert!(bus.insert(dummy.clone(), 0x0, 0x10, false).is_ok());
    }

    #[test]
    fn bus_insert_full_addr() {
        let mut bus = Bus::new();
        let dummy = Arc::new(Mutex::new(DummyDevice));
        assert!(bus.insert(dummy.clone(), 0x10, 0, true).is_err());
        assert!(bus.insert(dummy.clone(), 0x10, 0x10, true).is_ok());
        assert!(bus.insert(dummy.clone(), 0x0f, 0x10, true).is_err());
        assert!(bus.insert(dummy.clone(), 0x10, 0x10, true).is_err());
        assert!(bus.insert(dummy.clone(), 0x10, 0x15, true).is_err());
        assert!(bus.insert(dummy.clone(), 0x12, 0x15, true).is_err());
        assert!(bus.insert(dummy.clone(), 0x12, 0x01, true).is_err());
        assert!(bus.insert(dummy.clone(), 0x0, 0x20, true).is_err());
        assert!(bus.insert(dummy.clone(), 0x20, 0x05, true).is_ok());
        assert!(bus.insert(dummy.clone(), 0x25, 0x05, true).is_ok());
        assert!(bus.insert(dummy.clone(), 0x0, 0x10, true).is_ok());
    }

    #[test]
    fn bus_read_write() {
        let mut bus = Bus::new();
        let dummy = Arc::new(Mutex::new(DummyDevice));
        assert!(bus.insert(dummy.clone(), 0x10, 0x10, false).is_ok());
        assert!(bus.read(0x10, &mut [0, 0, 0, 0]));
        assert!(bus.write(0x10, &[0, 0, 0, 0]));
        assert!(bus.read(0x11, &mut [0, 0, 0, 0]));
        assert!(bus.write(0x11, &[0, 0, 0, 0]));
        assert!(bus.read(0x16, &mut [0, 0, 0, 0]));
        assert!(bus.write(0x16, &[0, 0, 0, 0]));
        assert!(!bus.read(0x20, &mut [0, 0, 0, 0]));
        assert!(!bus.write(0x20, &mut [0, 0, 0, 0]));
        assert!(!bus.read(0x06, &mut [0, 0, 0, 0]));
        assert!(!bus.write(0x06, &mut [0, 0, 0, 0]));
    }

    #[test]
    fn bus_read_write_values() {
        let mut bus = Bus::new();
        let dummy = Arc::new(Mutex::new(ConstantDevice));
        assert!(bus.insert(dummy.clone(), 0x10, 0x10, false).is_ok());

        let mut values = [0, 1, 2, 3];
        assert!(bus.read(0x10, &mut values));
        assert_eq!(values, [0, 1, 2, 3]);
        assert!(bus.write(0x10, &values));
        assert!(bus.read(0x15, &mut values));
        assert_eq!(values, [5, 6, 7, 8]);
        assert!(bus.write(0x15, &values));
    }

    #[test]
    fn bus_read_write_full_addr_values() {
        let mut bus = Bus::new();
        let dummy = Arc::new(Mutex::new(ConstantDevice));
        assert!(bus.insert(dummy.clone(), 0x10, 0x10, true).is_ok());

        let mut values = [0u8; 4];
        assert!(bus.read(0x10, &mut values));
        assert_eq!(values, [0x10, 0x11, 0x12, 0x13]);
        assert!(bus.write(0x10, &values));
        assert!(bus.read(0x15, &mut values));
        assert_eq!(values, [0x15, 0x16, 0x17, 0x18]);
        assert!(bus.write(0x15, &values));
    }

    #[test]
    fn bus_range_contains() {
        let a = BusRange {
            base: 0x1000,
            len: 0x400,
            full_addr: false,
        };
        assert!(a.contains(0x1000));
        assert!(a.contains(0x13ff));
        assert!(!a.contains(0xfff));
        assert!(!a.contains(0x1400));
        assert!(a.contains(0x1200));
    }

    #[test]
    fn bus_range_overlap() {
        let a = BusRange {
            base: 0x1000,
            len: 0x400,
            full_addr: false,
        };
        assert!(a.overlaps(0x1000, 0x400));
        assert!(a.overlaps(0xf00, 0x400));
        assert!(a.overlaps(0x1000, 0x01));
        assert!(a.overlaps(0xfff, 0x02));
        assert!(a.overlaps(0x1100, 0x100));
        assert!(a.overlaps(0x13ff, 0x100));
        assert!(!a.overlaps(0x1400, 0x100));
        assert!(!a.overlaps(0xf00, 0x100));
    }
}

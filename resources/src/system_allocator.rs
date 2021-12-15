// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
use std::collections::BTreeMap;

use base::pagesize;

use crate::address_allocator::{AddressAllocator, AddressAllocatorSet};
use crate::{Alloc, Error, Result};

/// Manages allocating system resources such as address space and interrupt numbers.
///
/// # Example - Use the `SystemAddress` builder.
///
/// ```
/// # use resources::{Alloc, MmioType, SystemAllocator};
///   if let Ok(mut a) = SystemAllocator::builder()
///           .add_io_addresses(0x1000, 0x10000)
///           .add_high_mmio_addresses(0x10000000, 0x10000000)
///           .add_low_mmio_addresses(0x30000000, 0x10000)
///           .create_allocator(5) {
///       assert_eq!(a.allocate_irq(), Some(5));
///       assert_eq!(a.allocate_irq(), Some(6));
///       assert_eq!(
///           a.mmio_allocator(MmioType::High)
///              .allocate(
///                  0x100,
///                  Alloc::PciBar { bus: 0, dev: 0, func: 0, bar: 0 },
///                  "bar0".to_string()
///              ),
///           Ok(0x10000000)
///       );
///       assert_eq!(
///           a.mmio_allocator(MmioType::High)
///              .get(&Alloc::PciBar { bus: 0, dev: 0, func: 0, bar: 0 }),
///           Some(&(0x10000000, 0x100, "bar0".to_string()))
///       );
///   }
/// ```

/// MMIO address Type
///    Low: address allocated from low_address_space
///    High: address allocated from high_address_space
pub enum MmioType {
    Low,
    High,
}

#[derive(Debug)]
pub struct SystemAllocator {
    io_address_space: Option<AddressAllocator>,

    // Indexed by MmioType::Low and MmioType::High.
    mmio_address_spaces: [AddressAllocator; 2],
    mmio_platform_address_spaces: Option<AddressAllocator>,

    // Each bus number has a AddressAllocator
    pci_allocator: BTreeMap<u8, AddressAllocator>,
    irq_allocator: AddressAllocator,
    next_anon_id: usize,
}

impl SystemAllocator {
    /// Creates a new `SystemAllocator` for managing addresses and irq numvers.
    /// Can return `None` if `base` + `size` overflows a u64 or if alignment isn't a power
    /// of two.
    ///
    /// * `io_base` - The starting address of IO memory.
    /// * `io_size` - The size of IO memory.
    /// * `high_base` - The starting address of high MMIO space.
    /// * `high_size` - The size of high MMIO space.
    /// * `low_base` - The starting address of low MMIO space.
    /// * `low_size` - The size of low MMIO space.
    /// * `first_irq` - The first irq number to give out.
    fn new(
        io_base: Option<u64>,
        io_size: Option<u64>,
        high_base: u64,
        high_size: u64,
        low_base: u64,
        low_size: u64,
        platform_base: Option<u64>,
        platform_size: Option<u64>,
        first_irq: u32,
    ) -> Result<Self> {
        let page_size = pagesize() as u64;
        Ok(SystemAllocator {
            io_address_space: if let (Some(b), Some(s)) = (io_base, io_size) {
                Some(AddressAllocator::new(b, s, Some(0x400), None)?)
            } else {
                None
            },
            mmio_address_spaces: [
                // MmioType::Low
                AddressAllocator::new(low_base, low_size, Some(page_size), None)?,
                // MmioType::High
                AddressAllocator::new(high_base, high_size, Some(page_size), None)?,
            ],

            pci_allocator: BTreeMap::new(),

            mmio_platform_address_spaces: if let (Some(b), Some(s)) = (platform_base, platform_size)
            {
                Some(AddressAllocator::new(b, s, Some(page_size), None)?)
            } else {
                None
            },

            irq_allocator: AddressAllocator::new(
                first_irq as u64,
                1024 - first_irq as u64,
                Some(1),
                None,
            )?,
            next_anon_id: 0,
        })
    }

    /// Returns a `SystemAllocatorBuilder` that can create a new `SystemAllocator`.
    pub fn builder() -> SystemAllocatorBuilder {
        SystemAllocatorBuilder::new()
    }

    /// Reserves the next available system irq number.
    pub fn allocate_irq(&mut self) -> Option<u32> {
        let id = self.get_anon_alloc();
        self.irq_allocator
            .allocate(1, id, "irq-auto".to_string())
            .map(|v| v as u32)
            .ok()
    }

    /// release irq to system irq number pool
    pub fn release_irq(&mut self, irq: u32) {
        let _ = self.irq_allocator.release_containing(irq.into());
    }

    /// Reserves the next available system irq number.
    pub fn reserve_irq(&mut self, irq: u32) -> bool {
        let id = self.get_anon_alloc();
        self.irq_allocator
            .allocate_at(irq as u64, 1, id, "irq-fixed".to_string())
            .is_ok()
    }

    fn get_pci_allocator_mut(&mut self, bus: u8) -> Option<&mut AddressAllocator> {
        // pci root is 00:00.0, Bus 0 next device is 00:01.0 with mandatory function
        // number zero.
        if self.pci_allocator.get(&bus).is_none() {
            let base = if bus == 0 { 8 } else { 0 };

            // Each bus supports up to 32 (devices) x 8 (functions).
            // Prefer allocating at device granularity (preferred_align = 8), but fall back to
            // allocating individual functions (min_align = 1) when we run out of devices.
            match AddressAllocator::new(base, (32 * 8) - base, Some(1), Some(8)) {
                Ok(v) => self.pci_allocator.insert(bus, v),
                Err(_) => return None,
            };
        }
        self.pci_allocator.get_mut(&bus)
    }

    // Check whether devices exist or not on the specified bus
    pub fn pci_bus_empty(&self, bus: u8) -> bool {
        if self.pci_allocator.get(&bus).is_none() {
            true
        } else {
            false
        }
    }

    /// Allocate PCI slot location.
    pub fn allocate_pci(&mut self, bus: u8, tag: String) -> Option<Alloc> {
        let id = self.get_anon_alloc();
        let allocator = match self.get_pci_allocator_mut(bus) {
            Some(v) => v,
            None => return None,
        };
        allocator
            .allocate(1, id, tag)
            .map(|v| Alloc::PciBar {
                bus,
                dev: (v >> 3) as u8,
                func: (v & 7) as u8,
                bar: 0,
            })
            .ok()
    }

    /// Reserve PCI slot location.
    pub fn reserve_pci(&mut self, alloc: Alloc, tag: String) -> bool {
        let id = self.get_anon_alloc();
        match alloc {
            Alloc::PciBar {
                bus,
                dev,
                func,
                bar: _,
            } => {
                let allocator = match self.get_pci_allocator_mut(bus) {
                    Some(v) => v,
                    None => return false,
                };
                let df = ((dev as u64) << 3) | (func as u64);
                allocator.allocate_at(df, 1, id, tag).is_ok()
            }
            _ => false,
        }
    }

    /// release PCI slot location.
    pub fn release_pci(&mut self, bus: u8, dev: u8, func: u8) -> bool {
        let allocator = match self.get_pci_allocator_mut(bus) {
            Some(v) => v,
            None => return false,
        };
        let df = ((dev as u64) << 3) | (func as u64);
        allocator.release_containing(df).is_ok()
    }

    /// Gets an allocator to be used for platform device MMIO allocation.
    pub fn mmio_platform_allocator(&mut self) -> Option<&mut AddressAllocator> {
        self.mmio_platform_address_spaces.as_mut()
    }

    /// Gets an allocator to be used for IO memory.
    pub fn io_allocator(&mut self) -> Option<&mut AddressAllocator> {
        self.io_address_space.as_mut()
    }

    /// Gets an allocator to be used for MMIO allocation.
    ///    MmioType::Low: low mmio allocator
    ///    MmioType::High: high mmio allocator
    pub fn mmio_allocator(&mut self, mmio_type: MmioType) -> &mut AddressAllocator {
        &mut self.mmio_address_spaces[mmio_type as usize]
    }

    /// Gets a set of allocators to be used for MMIO allocation.
    /// The set of allocators will try the low and high MMIO allocators, in that order.
    pub fn mmio_allocator_any(&mut self) -> AddressAllocatorSet {
        AddressAllocatorSet::new(&mut self.mmio_address_spaces)
    }

    /// Gets a unique anonymous allocation
    pub fn get_anon_alloc(&mut self) -> Alloc {
        self.next_anon_id += 1;
        Alloc::Anon(self.next_anon_id)
    }
}

/// Used to build a system address map for use in creating a `SystemAllocator`.
pub struct SystemAllocatorBuilder {
    io_base: Option<u64>,
    io_size: Option<u64>,
    low_mmio_base: Option<u64>,
    low_mmio_size: Option<u64>,
    high_mmio_base: Option<u64>,
    high_mmio_size: Option<u64>,
    platform_mmio_base: Option<u64>,
    platform_mmio_size: Option<u64>,
}

impl SystemAllocatorBuilder {
    pub fn new() -> Self {
        SystemAllocatorBuilder {
            io_base: None,
            io_size: None,
            low_mmio_base: None,
            low_mmio_size: None,
            high_mmio_base: None,
            high_mmio_size: None,
            platform_mmio_base: None,
            platform_mmio_size: None,
        }
    }

    pub fn add_io_addresses(mut self, base: u64, size: u64) -> Self {
        self.io_base = Some(base);
        self.io_size = Some(size);
        self
    }

    pub fn add_low_mmio_addresses(mut self, base: u64, size: u64) -> Self {
        self.low_mmio_base = Some(base);
        self.low_mmio_size = Some(size);
        self
    }

    pub fn add_high_mmio_addresses(mut self, base: u64, size: u64) -> Self {
        self.high_mmio_base = Some(base);
        self.high_mmio_size = Some(size);
        self
    }

    pub fn add_platform_mmio_addresses(mut self, base: u64, size: u64) -> Self {
        self.platform_mmio_base = Some(base);
        self.platform_mmio_size = Some(size);
        self
    }

    pub fn create_allocator(&self, first_irq: u32) -> Result<SystemAllocator> {
        SystemAllocator::new(
            self.io_base,
            self.io_size,
            self.high_mmio_base.ok_or(Error::MissingHighMMIOAddresses)?,
            self.high_mmio_size.ok_or(Error::MissingHighMMIOAddresses)?,
            self.low_mmio_base.ok_or(Error::MissingLowMMIOAddresses)?,
            self.low_mmio_size.ok_or(Error::MissingLowMMIOAddresses)?,
            self.platform_mmio_base,
            self.platform_mmio_size,
            first_irq,
        )
    }
}

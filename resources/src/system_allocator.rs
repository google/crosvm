// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
use std::collections::BTreeMap;
use std::ops::RangeInclusive;

use base::pagesize;

use crate::address_allocator::{AddressAllocator, AddressAllocatorSet};
use crate::{Alloc, Error, Result};

/// Manages allocating system resources such as address space and interrupt numbers.

/// MMIO address Type
///    Low: address allocated from low_address_space
///    High: address allocated from high_address_space
#[derive(Copy, Clone)]
pub enum MmioType {
    Low,
    High,
}

/// Region of memory.
#[derive(Debug)]
pub struct MemRegion {
    pub base: u64,
    pub size: u64,
}

pub struct SystemAllocatorConfig {
    /// IO ports. Only for x86_64.
    pub io: Option<MemRegion>,
    /// Low (<=4GB) MMIO region.
    ///
    /// Parts of this region may be reserved or otherwise excluded from the
    /// created SystemAllocator's MmioType::Low allocator. However, no new
    /// regions will be added.
    pub low_mmio: MemRegion,
    /// High (>4GB) MMIO region.
    ///
    /// Parts of this region may be reserved or otherwise excluded from the
    /// created SystemAllocator's MmioType::High allocator. However, no new
    /// regions will be added.
    pub high_mmio: MemRegion,
    /// Platform MMIO space. Only for ARM.
    pub platform_mmio: Option<MemRegion>,
    /// The first IRQ number to give out.
    pub first_irq: u32,
}

#[derive(Debug)]
pub struct SystemAllocator {
    io_address_space: Option<AddressAllocator>,

    // Indexed by MmioType::Low and MmioType::High.
    mmio_address_spaces: [AddressAllocator; 2],
    mmio_platform_address_spaces: Option<AddressAllocator>,

    reserved_region: Option<MemRegion>,

    // Each bus number has a AddressAllocator
    pci_allocator: BTreeMap<u8, AddressAllocator>,
    irq_allocator: AddressAllocator,
    next_anon_id: usize,
}

fn to_range_inclusive(base: u64, size: u64) -> Result<RangeInclusive<u64>> {
    let end = base
        .checked_add(size.checked_sub(1).ok_or(Error::PoolSizeZero)?)
        .ok_or(Error::PoolOverflow { base, size })?;
    Ok(RangeInclusive::new(base, end))
}

fn range_intersect(r1: &RangeInclusive<u64>, r2: &RangeInclusive<u64>) -> RangeInclusive<u64> {
    RangeInclusive::new(
        u64::max(*r1.start(), *r2.start()),
        u64::min(*r1.end(), *r2.end()),
    )
}

impl SystemAllocator {
    /// Creates a new `SystemAllocator` for managing addresses and irq numbers.
    /// Will return an error if `base` + `size` overflows u64 (or allowed
    /// maximum for the specific type), or if alignment isn't a power of two.
    ///
    /// If `reserve_region_size` is not None, then a region is reserved from
    /// the start of `config.high_mmio` before the mmio allocator is created.
    ///
    /// If `mmio_address_ranges` is not empty, then `config.low_mmio` and
    /// `config.high_mmio` are intersected with the ranges specified.
    pub fn new(
        config: SystemAllocatorConfig,
        reserve_region_size: Option<u64>,
        mmio_address_ranges: &[RangeInclusive<u64>],
    ) -> Result<Self> {
        let page_size = pagesize() as u64;

        let (high_mmio, reserved_region) = match reserve_region_size {
            Some(len) => {
                if len > config.high_mmio.size {
                    return Err(Error::PoolSizeZero);
                }
                (
                    MemRegion {
                        base: config.high_mmio.base + len,
                        size: config.high_mmio.size - len,
                    },
                    Some(MemRegion {
                        base: config.high_mmio.base,
                        size: len,
                    }),
                )
            }
            None => (config.high_mmio, None),
        };

        let intersect_mmio_range = |src: MemRegion| -> Result<Vec<RangeInclusive<u64>>> {
            let src_range = to_range_inclusive(src.base, src.size)?;
            Ok(if mmio_address_ranges.is_empty() {
                vec![src_range]
            } else {
                mmio_address_ranges
                    .iter()
                    .map(|r| range_intersect(r, &src_range))
                    .collect()
            })
        };

        Ok(SystemAllocator {
            io_address_space: if let Some(io) = config.io {
                // TODO make sure we don't overlap with existing well known
                // ports such as 0xcf8 (serial ports).
                if io.base > 0x1_0000 || io.size + io.base > 0x1_0000 {
                    return Err(Error::IOPortOutOfRange(io.base, io.size));
                }
                Some(AddressAllocator::new(
                    to_range_inclusive(io.base, io.size)?,
                    Some(0x400),
                    None,
                )?)
            } else {
                None
            },
            mmio_address_spaces: [
                // MmioType::Low
                AddressAllocator::new_from_list(
                    intersect_mmio_range(config.low_mmio)?,
                    Some(page_size),
                    None,
                )?,
                // MmioType::High
                AddressAllocator::new_from_list(
                    intersect_mmio_range(high_mmio)?,
                    Some(page_size),
                    None,
                )?,
            ],

            pci_allocator: BTreeMap::new(),

            mmio_platform_address_spaces: if let Some(platform) = config.platform_mmio {
                Some(AddressAllocator::new(
                    to_range_inclusive(platform.base, platform.size)?,
                    Some(page_size),
                    None,
                )?)
            } else {
                None
            },

            reserved_region,

            irq_allocator: AddressAllocator::new(
                RangeInclusive::new(config.first_irq as u64, 1023),
                Some(1),
                None,
            )?,
            next_anon_id: 0,
        })
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
            match AddressAllocator::new(RangeInclusive::new(base, (32 * 8) - 1), Some(1), Some(8)) {
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

    /// Gets the pools of all mmio allocators.
    pub fn mmio_pools(&self) -> Vec<&RangeInclusive<u64>> {
        self.mmio_address_spaces
            .iter()
            .flat_map(|mmio_as| mmio_as.pools())
            .collect()
    }

    /// Gets the reserved address space region.
    pub fn reserved_region(&self) -> Option<&MemRegion> {
        self.reserved_region.as_ref()
    }

    /// Gets a unique anonymous allocation
    pub fn get_anon_alloc(&mut self) -> Alloc {
        self.next_anon_id += 1;
        Alloc::Anon(self.next_anon_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example() {
        let mut a = SystemAllocator::new(
            SystemAllocatorConfig {
                io: Some(MemRegion {
                    base: 0x1000,
                    size: 0xf000,
                }),
                low_mmio: MemRegion {
                    base: 0x3000_0000,
                    size: 0x1_0000,
                },
                high_mmio: MemRegion {
                    base: 0x1000_0000,
                    size: 0x1000_0000,
                },
                platform_mmio: None,
                first_irq: 5,
            },
            None,
            &[],
        )
        .unwrap();

        assert_eq!(a.allocate_irq(), Some(5));
        assert_eq!(a.allocate_irq(), Some(6));
        assert_eq!(
            a.mmio_allocator(MmioType::High).allocate(
                0x100,
                Alloc::PciBar {
                    bus: 0,
                    dev: 0,
                    func: 0,
                    bar: 0
                },
                "bar0".to_string()
            ),
            Ok(0x10000000)
        );
        assert_eq!(
            a.mmio_allocator(MmioType::High).get(&Alloc::PciBar {
                bus: 0,
                dev: 0,
                func: 0,
                bar: 0
            }),
            Some(&(0x10000000, 0x100, "bar0".to_string()))
        );
    }
}

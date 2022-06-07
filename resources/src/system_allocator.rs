// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;

use base::pagesize;

use crate::address_allocator::{AddressAllocator, AddressAllocatorSet};
use crate::{AddressRange, Alloc, Error, Result};

/// Manages allocating system resources such as address space and interrupt numbers.

/// MMIO address Type
///    Low: address allocated from low_address_space
///    High: address allocated from high_address_space
#[derive(Copy, Clone)]
pub enum MmioType {
    Low,
    High,
}

pub struct SystemAllocatorConfig {
    /// IO ports. Only for x86_64.
    pub io: Option<AddressRange>,
    /// Low (<=4GB) MMIO region.
    ///
    /// Parts of this region may be reserved or otherwise excluded from the
    /// created SystemAllocator's MmioType::Low allocator. However, no new
    /// regions will be added.
    pub low_mmio: AddressRange,
    /// High (>4GB) MMIO region.
    ///
    /// Parts of this region may be reserved or otherwise excluded from the
    /// created SystemAllocator's MmioType::High allocator. However, no new
    /// regions will be added.
    pub high_mmio: AddressRange,
    /// Platform MMIO space. Only for ARM.
    pub platform_mmio: Option<AddressRange>,
    /// The first IRQ number to give out.
    pub first_irq: u32,
}

#[derive(Debug)]
pub struct SystemAllocator {
    io_address_space: Option<AddressAllocator>,

    // Indexed by MmioType::Low and MmioType::High.
    mmio_address_spaces: [AddressAllocator; 2],
    mmio_platform_address_spaces: Option<AddressAllocator>,

    reserved_region: Option<AddressRange>,

    // Each bus number has a AddressAllocator
    pci_allocator: BTreeMap<u8, AddressAllocator>,
    irq_allocator: AddressAllocator,
    next_anon_id: usize,
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
        mmio_address_ranges: &[AddressRange],
    ) -> Result<Self> {
        let page_size = pagesize() as u64;

        let (high_mmio, reserved_region) = match reserve_region_size {
            Some(reserved_len) => {
                let high_mmio_len = config.high_mmio.len().ok_or(Error::OutOfBounds)?;
                if reserved_len >= high_mmio_len {
                    return Err(Error::PoolSizeZero);
                }
                let reserved_start = config.high_mmio.start;
                let reserved_end = reserved_start + reserved_len - 1;
                let high_mmio_start = reserved_end + 1;
                let high_mmio_end = config.high_mmio.end;
                (
                    AddressRange {
                        start: high_mmio_start,
                        end: high_mmio_end,
                    },
                    Some(AddressRange {
                        start: reserved_start,
                        end: reserved_end,
                    }),
                )
            }
            None => (config.high_mmio, None),
        };

        let intersect_mmio_range = |src_range: AddressRange| -> Result<Vec<AddressRange>> {
            Ok(if mmio_address_ranges.is_empty() {
                vec![src_range]
            } else {
                mmio_address_ranges
                    .iter()
                    .map(|r| r.intersect(src_range))
                    .collect()
            })
        };

        Ok(SystemAllocator {
            io_address_space: if let Some(io) = config.io {
                // TODO make sure we don't overlap with existing well known
                // ports such as 0xcf8 (serial ports).
                if io.end > 0xffff {
                    return Err(Error::IOPortOutOfRange(io));
                }
                Some(AddressAllocator::new(io, Some(0x400), None)?)
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
                Some(AddressAllocator::new(platform, Some(page_size), None)?)
            } else {
                None
            },

            reserved_region,

            irq_allocator: AddressAllocator::new(
                AddressRange {
                    start: config.first_irq as u64,
                    end: 1023,
                },
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
            .allocate_at(
                AddressRange {
                    start: irq.into(),
                    end: irq.into(),
                },
                id,
                "irq-fixed".to_string(),
            )
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
            match AddressAllocator::new(
                AddressRange {
                    start: base,
                    end: (32 * 8) - 1,
                },
                Some(1),
                Some(8),
            ) {
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
                allocator
                    .allocate_at(AddressRange { start: df, end: df }, id, tag)
                    .is_ok()
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

    /// Reserve specified range from pci mmio, get the overlap of specified
    /// range with mmio pools, exclude the overlap from mmio allocator.
    ///
    /// If any part of the specified range has been allocated, return Error.
    pub fn reserve_mmio(&mut self, range: AddressRange) -> Result<()> {
        let mut pools = Vec::new();
        for pool in self.mmio_pools() {
            pools.push(*pool);
        }
        pools.sort_by(|a, b| a.start.cmp(&b.start));
        for pool in &pools {
            if pool.start > range.end {
                break;
            }

            let overlap = pool.intersect(range);
            if !overlap.is_empty() {
                let id = self.get_anon_alloc();
                self.mmio_allocator_any().allocate_at(
                    overlap,
                    id,
                    "pci mmio reserve".to_string(),
                )?;
            }
        }

        Ok(())
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
    pub fn mmio_pools(&self) -> Vec<&AddressRange> {
        self.mmio_address_spaces
            .iter()
            .flat_map(|mmio_as| mmio_as.pools())
            .collect()
    }

    /// Gets the reserved address space region.
    pub fn reserved_region(&self) -> Option<AddressRange> {
        self.reserved_region
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
                io: Some(AddressRange {
                    start: 0x1000,
                    end: 0xffff,
                }),
                low_mmio: AddressRange {
                    start: 0x3000_0000,
                    end: 0x3000_ffff,
                },
                high_mmio: AddressRange {
                    start: 0x1000_0000,
                    end: 0x1fffffff,
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
            Some(&(
                AddressRange {
                    start: 0x10000000,
                    end: 0x100000ff
                },
                "bar0".to_string()
            ))
        );

        let id = a.get_anon_alloc();
        assert_eq!(
            a.mmio_allocator(MmioType::Low).allocate_at(
                AddressRange {
                    start: 0x3000_5000,
                    end: 0x30009fff
                },
                id,
                "Test".to_string()
            ),
            Ok(())
        );
        assert_eq!(a.mmio_allocator(MmioType::Low).release(id), Ok(()));
        assert_eq!(
            a.reserve_mmio(AddressRange {
                start: 0x3000_2000,
                end: 0x30005fff
            }),
            Ok(())
        );
        assert_eq!(
            a.mmio_allocator(MmioType::Low)
                .allocate_at(
                    AddressRange {
                        start: 0x3000_5000,
                        end: 0x3000_9fff
                    },
                    id,
                    "Test".to_string()
                )
                .is_err(),
            true
        );
    }
}

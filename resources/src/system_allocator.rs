// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use sys_util::pagesize;

use crate::address_allocator::AddressAllocator;
use crate::gpu_allocator::{self, GpuMemoryAllocator};
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
///           .create_allocator(5, false) {
///       assert_eq!(a.allocate_irq(), Some(5));
///       assert_eq!(a.allocate_irq(), Some(6));
///       assert_eq!(
///           a.mmio_allocator(MmioType::High)
///              .allocate(
///                  0x100,
///                  Alloc::PciBar { bus: 0, dev: 0, bar: 0 },
///                  "bar0".to_string()
///              ),
///           Ok(0x10000000)
///       );
///       assert_eq!(
///           a.mmio_allocator(MmioType::High).get(&Alloc::PciBar { bus: 0, dev: 0, bar: 0 }),
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
    high_mmio_address_space: AddressAllocator,
    low_mmio_address_space: AddressAllocator,
    gpu_allocator: Option<Box<dyn GpuMemoryAllocator>>,
    next_irq: u32,
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
    /// * `create_gpu_allocator` - If true, enable gpu memory allocation.
    /// * `first_irq` - The first irq number to give out.
    fn new(
        io_base: Option<u64>,
        io_size: Option<u64>,
        high_base: u64,
        high_size: u64,
        low_base: u64,
        low_size: u64,
        create_gpu_allocator: bool,
        first_irq: u32,
    ) -> Result<Self> {
        let page_size = pagesize() as u64;
        Ok(SystemAllocator {
            io_address_space: if let (Some(b), Some(s)) = (io_base, io_size) {
                Some(AddressAllocator::new(b, s, Some(0x400))?)
            } else {
                None
            },
            high_mmio_address_space: AddressAllocator::new(high_base, high_size, Some(page_size))?,
            low_mmio_address_space: AddressAllocator::new(low_base, low_size, Some(page_size))?,
            gpu_allocator: if create_gpu_allocator {
                gpu_allocator::create_gpu_memory_allocator().map_err(Error::CreateGpuAllocator)?
            } else {
                None
            },
            next_irq: first_irq,
            next_anon_id: 0,
        })
    }

    /// Returns a `SystemAllocatorBuilder` that can create a new `SystemAllocator`.
    pub fn builder() -> SystemAllocatorBuilder {
        SystemAllocatorBuilder::new()
    }

    /// Reserves the next available system irq number.
    pub fn allocate_irq(&mut self) -> Option<u32> {
        if let Some(irq_num) = self.next_irq.checked_add(1) {
            self.next_irq = irq_num;
            Some(irq_num - 1)
        } else {
            None
        }
    }

    /// Gets an allocator to be used for IO memory.
    pub fn io_allocator(&mut self) -> Option<&mut AddressAllocator> {
        self.io_address_space.as_mut()
    }

    /// Gets an allocator to be used for MMIO allocation.
    ///    MmioType::Low: low mmio allocator
    ///    MmioType::High: high mmio allocator
    pub fn mmio_allocator(&mut self, mmio_type: MmioType) -> &mut AddressAllocator {
        match mmio_type {
            MmioType::Low => &mut self.low_mmio_address_space,
            MmioType::High => &mut self.high_mmio_address_space,
        }
    }

    /// Gets an allocator to be used for GPU memory.
    pub fn gpu_memory_allocator(&self) -> Option<&dyn GpuMemoryAllocator> {
        self.gpu_allocator.as_ref().map(|v| v.as_ref())
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

    pub fn create_allocator(
        &self,
        first_irq: u32,
        gpu_allocation: bool,
    ) -> Result<SystemAllocator> {
        SystemAllocator::new(
            self.io_base,
            self.io_size,
            self.high_mmio_base.ok_or(Error::MissingHighMMIOAddresses)?,
            self.high_mmio_size.ok_or(Error::MissingHighMMIOAddresses)?,
            self.low_mmio_base.ok_or(Error::MissingLowMMIOAddresses)?,
            self.low_mmio_size.ok_or(Error::MissingLowMMIOAddresses)?,
            gpu_allocation,
            first_irq,
        )
    }
}

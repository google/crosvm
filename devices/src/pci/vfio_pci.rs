// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::u32;

use kvm::Datamatch;
use resources::{Alloc, SystemAllocator};
use sys_util::EventFd;

use vfio_sys::*;

use crate::pci::pci_device::{Error as PciDeviceError, PciDevice};
use crate::pci::PciInterruptPin;

use crate::vfio::VfioDevice;

struct VfioPciConfig {
    device: Arc<VfioDevice>,
}

impl VfioPciConfig {
    fn new(device: Arc<VfioDevice>) -> Self {
        VfioPciConfig { device }
    }

    #[allow(dead_code)]
    fn read_config_byte(&self, offset: u32) -> u8 {
        let mut data: [u8; 1] = [0];
        self.device
            .region_read(VFIO_PCI_CONFIG_REGION_INDEX, data.as_mut(), offset.into());

        data[0]
    }

    #[allow(dead_code)]
    fn read_config_word(&self, offset: u32) -> u16 {
        let mut data: [u8; 2] = [0, 0];
        self.device
            .region_read(VFIO_PCI_CONFIG_REGION_INDEX, data.as_mut(), offset.into());

        u16::from_le_bytes(data)
    }

    #[allow(dead_code)]
    fn read_config_dword(&self, offset: u32) -> u32 {
        let mut data: [u8; 4] = [0, 0, 0, 0];
        self.device
            .region_read(VFIO_PCI_CONFIG_REGION_INDEX, data.as_mut(), offset.into());

        u32::from_le_bytes(data)
    }

    #[allow(dead_code)]
    fn write_config_byte(&self, buf: u8, offset: u32) {
        self.device.region_write(
            VFIO_PCI_CONFIG_REGION_INDEX,
            ::std::slice::from_ref(&buf),
            offset.into(),
        )
    }

    #[allow(dead_code)]
    fn write_config_word(&self, buf: u16, offset: u32) {
        let data: [u8; 2] = buf.to_le_bytes();
        self.device
            .region_write(VFIO_PCI_CONFIG_REGION_INDEX, &data, offset.into())
    }

    #[allow(dead_code)]
    fn write_config_dword(&self, buf: u32, offset: u32) {
        let data: [u8; 4] = buf.to_le_bytes();
        self.device
            .region_write(VFIO_PCI_CONFIG_REGION_INDEX, &data, offset.into())
    }
}

struct MmioInfo {
    bar_index: u32,
    start: u64,
    length: u64,
}

struct IoInfo {
    bar_index: u32,
}

/// Implements the Vfio Pci device, then a pci device is added into vm
pub struct VfioPciDevice {
    device: Arc<VfioDevice>,
    config: VfioPciConfig,
    pci_bus_dev: Option<(u8, u8)>,
    interrupt_evt: Option<EventFd>,
    interrupt_resample_evt: Option<EventFd>,
    mmio_regions: Vec<MmioInfo>,
    io_regions: Vec<IoInfo>,
}

impl VfioPciDevice {
    /// Constructs a new Vfio Pci device for the give Vfio device
    pub fn new(device: Box<VfioDevice>) -> Self {
        let dev = Arc::new(*device);
        let config = VfioPciConfig::new(Arc::clone(&dev));
        VfioPciDevice {
            device: dev,
            config,
            pci_bus_dev: None,
            interrupt_evt: None,
            interrupt_resample_evt: None,
            mmio_regions: Vec::new(),
            io_regions: Vec::new(),
        }
    }

    fn find_region(&self, addr: u64) -> Option<MmioInfo> {
        for mmio_info in self.mmio_regions.iter() {
            if addr >= mmio_info.start && addr < mmio_info.start + mmio_info.length {
                return Some(MmioInfo {
                    bar_index: mmio_info.bar_index,
                    start: mmio_info.start,
                    length: mmio_info.length,
                });
            }
        }

        None
    }
}

impl PciDevice for VfioPciDevice {
    fn debug_label(&self) -> String {
        format!("vfio pci device")
    }

    fn assign_bus_dev(&mut self, bus: u8, device: u8) {
        self.pci_bus_dev = Some((bus, device));
    }

    fn keep_fds(&self) -> Vec<RawFd> {
        let fds = Vec::new();
        fds
    }

    fn assign_irq(
        &mut self,
        irq_evt: EventFd,
        irq_resample_evt: EventFd,
        irq_num: u32,
        irq_pin: PciInterruptPin,
    ) {
        self.config.write_config_byte(irq_num as u8, 0x3C);
        self.config.write_config_byte(irq_pin as u8 + 1, 0x3D);
        self.interrupt_evt = Some(irq_evt);
        self.interrupt_resample_evt = Some(irq_resample_evt);
    }

    fn allocate_io_bars(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> Result<Vec<(u64, u64)>, PciDeviceError> {
        let mut ranges = Vec::new();
        let mut i = VFIO_PCI_BAR0_REGION_INDEX;
        let (bus, dev) = self
            .pci_bus_dev
            .expect("assign_bus_dev must be called prior to allocate_io_bars");

        while i <= VFIO_PCI_ROM_REGION_INDEX {
            let mut low: u32 = 0xffffffff;
            let offset: u32;
            if i == VFIO_PCI_ROM_REGION_INDEX {
                offset = 0x30;
            } else {
                offset = 0x10 + i * 4;
            }
            self.config.write_config_dword(low, offset);
            low = self.config.read_config_dword(offset);

            let low_flag = low & 0xf;
            let is_64bit = match low_flag & 0x4 {
                0x4 => true,
                _ => false,
            };
            if (low_flag & 0x1 == 0 || i == VFIO_PCI_ROM_REGION_INDEX) && low != 0 {
                let mut upper: u32 = 0xffffffff;
                if is_64bit {
                    self.config.write_config_dword(upper, offset + 4);
                    upper = self.config.read_config_dword(offset + 4);
                }

                low &= 0xffff_fff0;
                let mut size: u64 = u64::from(upper);
                size <<= 32;
                size |= u64::from(low);
                size = !size + 1;
                let bar_addr = resources
                    .mmio_allocator()
                    .allocate_with_align(
                        size,
                        Alloc::PciBar {
                            bus,
                            dev,
                            bar: i as u8,
                        },
                        "vfio_bar".to_string(),
                        size,
                    )
                    .map_err(|e| PciDeviceError::IoAllocationFailed(size, e))?;
                ranges.push((bar_addr, size));
                self.mmio_regions.push(MmioInfo {
                    bar_index: i,
                    start: bar_addr,
                    length: size,
                });

                low = bar_addr as u32;
                low |= low_flag;
                self.config.write_config_dword(low, offset);
                if is_64bit {
                    upper = (bar_addr >> 32) as u32;
                    self.config.write_config_dword(upper, offset + 4);
                }
            } else if low_flag & 0x1 == 0x1 {
                self.io_regions.push(IoInfo { bar_index: i });
            }

            if is_64bit {
                i += 2;
            } else {
                i += 1;
            }
        }
        Ok(ranges)
    }

    fn allocate_device_bars(
        &mut self,
        _resources: &mut SystemAllocator,
    ) -> Result<Vec<(u64, u64)>, PciDeviceError> {
        Ok(Vec::new())
    }

    fn register_device_capabilities(&mut self) -> Result<(), PciDeviceError> {
        Ok(())
    }

    fn ioeventfds(&self) -> Vec<(&EventFd, u64, Datamatch)> {
        Vec::new()
    }

    fn read_config_register(&self, reg_idx: usize) -> u32 {
        let reg: u32 = (reg_idx * 4) as u32;

        let mut config = self.config.read_config_dword(reg);

        // Ignore IO bar
        if reg >= 0x10 && reg <= 0x24 {
            for io_info in self.io_regions.iter() {
                if io_info.bar_index * 4 + 0x10 == reg {
                    config = 0;
                }
            }
        }

        config
    }

    fn write_config_register(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        self.device.region_write(
            VFIO_PCI_CONFIG_REGION_INDEX,
            data,
            (reg_idx * 4) as u64 + offset,
        )
    }

    fn read_bar(&mut self, addr: u64, data: &mut [u8]) {
        if let Some(mmio_info) = self.find_region(addr) {
            let offset = addr - mmio_info.start;
            self.device.region_read(mmio_info.bar_index, data, offset);
        }
    }

    fn write_bar(&mut self, addr: u64, data: &[u8]) {
        if let Some(mmio_info) = self.find_region(addr) {
            let offset = addr - mmio_info.start;
            self.device.region_write(mmio_info.bar_index, data, offset);
        }
    }
}

// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use std::u32;

use kvm::Datamatch;
use msg_socket::{MsgReceiver, MsgSender};
use resources::{Alloc, MmioType, SystemAllocator};
use sys_util::{error, EventFd};

use vfio_sys::*;
use vm_control::{MaybeOwnedFd, VmIrqRequest, VmIrqRequestSocket, VmIrqResponse};

use crate::pci::pci_device::{Error as PciDeviceError, PciDevice};
use crate::pci::PciInterruptPin;

use crate::vfio::{VfioDevice, VfioIrqType};

const PCI_INTERRUPT_PIN: u32 = 0x3D;

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

const PCI_CAPABILITY_LIST: u32 = 0x34;
const PCI_CAP_ID_MSI: u8 = 0x05;

// MSI registers
const PCI_MSI_NEXT_POINTER: u32 = 0x1; // Next cap pointer
const PCI_MSI_FLAGS: u32 = 0x2; // Message Control
const PCI_MSI_FLAGS_ENABLE: u16 = 0x0001; // MSI feature enabled
const PCI_MSI_FLAGS_64BIT: u16 = 0x0080; // 64-bit addresses allowed
const PCI_MSI_FLAGS_MASKBIT: u16 = 0x0100; // Per-vector masking capable
const PCI_MSI_ADDRESS_LO: u32 = 0x4; // MSI address lower 32 bits
const PCI_MSI_ADDRESS_HI: u32 = 0x8; // MSI address upper 32 bits (if 64 bit allowed)
const PCI_MSI_DATA_32: u32 = 0x8; // 16 bits of data for 32-bit message address
const PCI_MSI_DATA_64: u32 = 0xC; // 16 bits of date for 64-bit message address

// MSI length
const MSI_LENGTH_32BIT: u32 = 0xA;
const MSI_LENGTH_64BIT_WITHOUT_MASK: u32 = 0xE;
const MSI_LENGTH_64BIT_WITH_MASK: u32 = 0x18;

enum VfioMsiChange {
    Disable,
    Enable,
}

struct VfioMsiCap {
    offset: u32,
    size: u32,
    ctl: u16,
    address: u64,
    data: u16,
    vm_socket_irq: VmIrqRequestSocket,
    irqfd: Option<EventFd>,
    gsi: Option<u32>,
}

impl VfioMsiCap {
    fn new(config: &VfioPciConfig, vm_socket_irq: VmIrqRequestSocket) -> Option<Self> {
        // msi minimum size is 0xa
        let mut msi_len: u32 = MSI_LENGTH_32BIT;
        let mut cap_next: u32 = config.read_config_byte(PCI_CAPABILITY_LIST).into();
        while cap_next != 0 {
            let cap_id = config.read_config_byte(cap_next);
            // find msi cap
            if cap_id == PCI_CAP_ID_MSI {
                let msi_ctl = config.read_config_word(cap_next + PCI_MSI_FLAGS);
                if msi_ctl & PCI_MSI_FLAGS_64BIT != 0 {
                    msi_len = MSI_LENGTH_64BIT_WITHOUT_MASK;
                }
                if msi_ctl & PCI_MSI_FLAGS_MASKBIT != 0 {
                    msi_len = MSI_LENGTH_64BIT_WITH_MASK;
                }
                return Some(VfioMsiCap {
                    offset: cap_next,
                    size: msi_len,
                    ctl: 0,
                    address: 0,
                    data: 0,
                    vm_socket_irq,
                    irqfd: None,
                    gsi: None,
                });
            }
            let offset = cap_next + PCI_MSI_NEXT_POINTER;
            cap_next = config.read_config_byte(offset).into();
        }

        None
    }

    fn is_msi_reg(&self, index: u64, len: usize) -> bool {
        if index >= self.offset as u64
            && index + len as u64 <= (self.offset + self.size) as u64
            && len as u32 <= self.size
        {
            true
        } else {
            false
        }
    }

    fn write_msi_reg(&mut self, index: u64, data: &[u8]) -> Option<VfioMsiChange> {
        let len = data.len();
        let offset = index as u32 - self.offset;
        let mut ret: Option<VfioMsiChange> = None;
        let old_address = self.address;
        let old_data = self.data;

        // write msi ctl
        if len == 2 && offset == PCI_MSI_FLAGS {
            let was_enabled = self.is_msi_enabled();
            let value: [u8; 2] = [data[0], data[1]];
            self.ctl = u16::from_le_bytes(value);
            let is_enabled = self.is_msi_enabled();
            if !was_enabled && is_enabled {
                self.enable();
                ret = Some(VfioMsiChange::Enable);
            } else if was_enabled && !is_enabled {
                ret = Some(VfioMsiChange::Disable)
            }
        } else if len == 4 && offset == PCI_MSI_ADDRESS_LO && self.size == MSI_LENGTH_32BIT {
            //write 32 bit message address
            let value: [u8; 8] = [data[0], data[1], data[2], data[3], 0, 0, 0, 0];
            self.address = u64::from_le_bytes(value);
        } else if len == 4 && offset == PCI_MSI_ADDRESS_LO && self.size != MSI_LENGTH_32BIT {
            // write 64 bit message address low part
            let value: [u8; 8] = [data[0], data[1], data[2], data[3], 0, 0, 0, 0];
            self.address &= !0xffffffff;
            self.address |= u64::from_le_bytes(value);
        } else if len == 4 && offset == PCI_MSI_ADDRESS_HI && self.size != MSI_LENGTH_32BIT {
            //write 64 bit message address high part
            let value: [u8; 8] = [0, 0, 0, 0, data[0], data[1], data[2], data[3]];
            self.address &= 0xffffffff;
            self.address |= u64::from_le_bytes(value);
        } else if len == 8 && offset == PCI_MSI_ADDRESS_LO && self.size != MSI_LENGTH_32BIT {
            // write 64 bit message address
            let value: [u8; 8] = [
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ];
            self.address = u64::from_le_bytes(value);
        } else if len == 2
            && ((offset == PCI_MSI_DATA_32 && self.size == MSI_LENGTH_32BIT)
                || (offset == PCI_MSI_DATA_64 && self.size == MSI_LENGTH_64BIT_WITH_MASK)
                || (offset == PCI_MSI_DATA_64 && self.size == MSI_LENGTH_64BIT_WITHOUT_MASK))
        {
            // write message data
            let value: [u8; 2] = [data[0], data[1]];
            self.data = u16::from_le_bytes(value);
        }

        if self.is_msi_enabled() && (old_address != self.address || old_data != self.data) {
            self.add_msi_route();
        }

        ret
    }

    fn is_msi_enabled(&self) -> bool {
        self.ctl & PCI_MSI_FLAGS_ENABLE == PCI_MSI_FLAGS_ENABLE
    }

    fn add_msi_route(&self) {
        let gsi = match self.gsi {
            Some(g) => g,
            None => {
                error!("Add msi route but gsi is none");
                return;
            }
        };
        if let Err(e) = self.vm_socket_irq.send(&VmIrqRequest::AddMsiRoute {
            gsi,
            msi_address: self.address,
            msi_data: self.data.into(),
        }) {
            error!("failed to send AddMsiRoute request at {:?}", e);
            return;
        }
        match self.vm_socket_irq.recv() {
            Ok(VmIrqResponse::Err(e)) => error!("failed to call AddMsiRoute request {:?}", e),
            Ok(_) => {}
            Err(e) => error!("failed to receive AddMsiRoute response {:?}", e),
        }
    }

    fn allocate_one_msi(&mut self) {
        if self.irqfd.is_none() {
            match EventFd::new() {
                Ok(fd) => self.irqfd = Some(fd),
                Err(e) => {
                    error!("failed to create eventfd: {:?}", e);
                    return;
                }
            };
        }

        if let Err(e) = self.vm_socket_irq.send(&VmIrqRequest::AllocateOneMsi {
            irqfd: MaybeOwnedFd::Borrowed(self.irqfd.as_ref().unwrap().as_raw_fd()),
        }) {
            error!("failed to send AllocateOneMsi request: {:?}", e);
            return;
        }

        match self.vm_socket_irq.recv() {
            Ok(VmIrqResponse::AllocateOneMsi { gsi }) => self.gsi = Some(gsi),
            _ => error!("failed to receive AllocateOneMsi Response"),
        }
    }

    fn enable(&mut self) {
        if self.gsi.is_none() || self.irqfd.is_none() {
            self.allocate_one_msi();
        }

        self.add_msi_route();
    }

    fn get_msi_irqfd(&self) -> Option<&EventFd> {
        self.irqfd.as_ref()
    }

    fn get_vm_socket(&self) -> RawFd {
        self.vm_socket_irq.as_ref().as_raw_fd()
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
    msi_cap: Option<VfioMsiCap>,
    irq_type: Option<VfioIrqType>,
}

impl VfioPciDevice {
    /// Constructs a new Vfio Pci device for the give Vfio device
    pub fn new(device: VfioDevice, vfio_device_socket_irq: VmIrqRequestSocket) -> Self {
        let dev = Arc::new(device);
        let config = VfioPciConfig::new(Arc::clone(&dev));
        let msi_cap = VfioMsiCap::new(&config, vfio_device_socket_irq);

        VfioPciDevice {
            device: dev,
            config,
            pci_bus_dev: None,
            interrupt_evt: None,
            interrupt_resample_evt: None,
            mmio_regions: Vec::new(),
            io_regions: Vec::new(),
            msi_cap,
            irq_type: None,
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

    fn enable_intx(&mut self) {
        if self.interrupt_evt.is_none() || self.interrupt_resample_evt.is_none() {
            return;
        }

        if let Some(ref interrupt_evt) = self.interrupt_evt {
            if let Err(e) = self.device.irq_enable(interrupt_evt, VfioIrqType::Intx) {
                error!("Intx enable failed: {}", e);
                return;
            }
            if let Some(ref irq_resample_evt) = self.interrupt_resample_evt {
                if let Err(e) = self.device.irq_mask(VfioIrqType::Intx) {
                    error!("Intx mask failed: {}", e);
                    self.disable_intx();
                    return;
                }
                if let Err(e) = self.device.resample_virq_enable(irq_resample_evt) {
                    error!("resample enable failed: {}", e);
                    self.disable_intx();
                    return;
                }
                if let Err(e) = self.device.irq_unmask(VfioIrqType::Intx) {
                    error!("Intx unmask failed: {}", e);
                    self.disable_intx();
                    return;
                }
            }
        }

        self.irq_type = Some(VfioIrqType::Intx);
    }

    fn disable_intx(&mut self) {
        if let Err(e) = self.device.irq_disable(VfioIrqType::Intx) {
            error!("Intx disable failed: {}", e);
        }
        self.irq_type = None;
    }

    fn enable_msi(&mut self) {
        if let Some(irq_type) = &self.irq_type {
            match irq_type {
                VfioIrqType::Intx => self.disable_intx(),
                _ => return,
            }
        }

        let irqfd = match &self.msi_cap {
            Some(cap) => {
                if let Some(fd) = cap.get_msi_irqfd() {
                    fd
                } else {
                    self.enable_intx();
                    return;
                }
            }
            None => {
                self.enable_intx();
                return;
            }
        };

        if let Err(e) = self.device.irq_enable(irqfd, VfioIrqType::Msi) {
            error!("failed to enable msi: {}", e);
            self.enable_intx();
            return;
        }

        self.irq_type = Some(VfioIrqType::Msi);
    }

    fn disable_msi(&mut self) {
        if let Err(e) = self.device.irq_disable(VfioIrqType::Msi) {
            error!("failed to disable msi: {}", e);
            return;
        }

        self.enable_intx();
    }
}

impl PciDevice for VfioPciDevice {
    fn debug_label(&self) -> String {
        "vfio pci device".to_string()
    }

    fn assign_bus_dev(&mut self, bus: u8, device: u8) {
        self.pci_bus_dev = Some((bus, device));
    }

    fn keep_fds(&self) -> Vec<RawFd> {
        let mut fds = self.device.keep_fds();
        if let Some(ref interrupt_evt) = self.interrupt_evt {
            fds.push(interrupt_evt.as_raw_fd());
        }
        if let Some(ref interrupt_resample_evt) = self.interrupt_resample_evt {
            fds.push(interrupt_resample_evt.as_raw_fd());
        }
        if let Some(msi_cap) = &self.msi_cap {
            fds.push(msi_cap.get_vm_socket());
        }
        fds
    }

    fn assign_irq(
        &mut self,
        irq_evt: EventFd,
        irq_resample_evt: EventFd,
        irq_num: u32,
        _irq_pin: PciInterruptPin,
    ) {
        self.config.write_config_byte(irq_num as u8, 0x3C);
        self.interrupt_evt = Some(irq_evt);
        self.interrupt_resample_evt = Some(irq_resample_evt);

        // enable INTX
        if self.config.read_config_byte(PCI_INTERRUPT_PIN) > 0 {
            self.enable_intx();
        }
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
                let mmio_type = match is_64bit {
                    false => MmioType::Low,
                    true => MmioType::High,
                };
                let bar_addr = resources
                    .mmio_allocator(mmio_type)
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

        if let Err(e) = self.device.setup_dma_map() {
            error!(
                "failed to add all guest memory regions into iommu table: {}",
                e
            );
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
        let start = (reg_idx * 4) as u64 + offset;

        let mut msi_change: Option<VfioMsiChange> = None;
        if let Some(msi_cap) = self.msi_cap.as_mut() {
            if msi_cap.is_msi_reg(start, data.len()) {
                msi_change = msi_cap.write_msi_reg(start, data);
            }
        }

        match msi_change {
            Some(VfioMsiChange::Enable) => self.enable_msi(),
            Some(VfioMsiChange::Disable) => self.disable_msi(),
            None => (),
        }

        self.device
            .region_write(VFIO_PCI_CONFIG_REGION_INDEX, data, start);
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

// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use std::u32;

use kvm::Datamatch;
use msg_socket::{MsgReceiver, MsgSender};
use resources::{Alloc, MmioType, SystemAllocator};
use sys_util::{error, EventFd, MemoryMapping};

use vfio_sys::*;
use vm_control::{
    MaybeOwnedFd, VmIrqRequest, VmIrqRequestSocket, VmIrqResponse, VmMemoryControlRequestSocket,
    VmMemoryRequest, VmMemoryResponse,
};

use crate::pci::msix::{
    MsixConfig, BITS_PER_PBA_ENTRY, MSIX_PBA_ENTRIES_MODULO, MSIX_TABLE_ENTRIES_MODULO,
};

use crate::pci::pci_device::{Error as PciDeviceError, PciDevice};
use crate::pci::{PciClassCode, PciInterruptPin};

use crate::vfio::{VfioDevice, VfioIrqType};

const PCI_VENDOR_ID: u32 = 0x0;
const INTEL_VENDOR_ID: u16 = 0x8086;
const PCI_COMMAND: u32 = 0x4;
const PCI_COMMAND_MEMORY: u8 = 0x2;
const PCI_BASE_CLASS_CODE: u32 = 0x0B;
const PCI_HEADER_TYPE: usize = 0x0E;
const PCI_MULTI_FLAG: u32 = 0x0080_0000;

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
const PCI_CAP_ID_MSIX: u8 = 0x11;

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
    vm_socket_irq: Arc<VmIrqRequestSocket>,
    irqfd: Option<EventFd>,
    gsi: Option<u32>,
}

impl VfioMsiCap {
    fn new(
        config: &VfioPciConfig,
        msi_cap_start: u32,
        vm_socket_irq: Arc<VmIrqRequestSocket>,
    ) -> Self {
        // msi minimum size is 0xa
        let mut msi_len: u32 = MSI_LENGTH_32BIT;
        let msi_ctl = config.read_config_word(msi_cap_start + PCI_MSI_FLAGS);
        if msi_ctl & PCI_MSI_FLAGS_64BIT != 0 {
            msi_len = MSI_LENGTH_64BIT_WITHOUT_MASK;
        }
        if msi_ctl & PCI_MSI_FLAGS_MASKBIT != 0 {
            msi_len = MSI_LENGTH_64BIT_WITH_MASK;
        }

        VfioMsiCap {
            offset: msi_cap_start,
            size: msi_len,
            ctl: 0,
            address: 0,
            data: 0,
            vm_socket_irq,
            irqfd: None,
            gsi: None,
        }
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
}

// MSI-X registers in MSI-X capability
const PCI_MSIX_FLAGS: u32 = 0x02; // Message Control
const PCI_MSIX_FLAGS_QSIZE: u16 = 0x07FF; // Table size
const PCI_MSIX_TABLE: u32 = 0x04; // Table offset
const PCI_MSIX_TABLE_BIR: u32 = 0x07; // BAR index
const PCI_MSIX_TABLE_OFFSET: u32 = 0xFFFFFFF8; // Offset into specified BAR
const PCI_MSIX_PBA: u32 = 0x08; // Pending bit Array offset
const PCI_MSIX_PBA_BIR: u32 = 0x07; // BAR index
const PCI_MSIX_PBA_OFFSET: u32 = 0xFFFFFFF8; // Offset into specified BAR

struct VfioMsixCap {
    config: MsixConfig,
    offset: u32,
    table_size: u16,
    table_pci_bar: u32,
    table_offset: u64,
    pba_pci_bar: u32,
    pba_offset: u64,
}

impl VfioMsixCap {
    fn new(
        config: &VfioPciConfig,
        msix_cap_start: u32,
        vm_socket_irq: Arc<VmIrqRequestSocket>,
    ) -> Self {
        let msix_ctl = config.read_config_word(msix_cap_start + PCI_MSIX_FLAGS);
        let table_size = (msix_ctl & PCI_MSIX_FLAGS_QSIZE) + 1;
        let table = config.read_config_dword(msix_cap_start + PCI_MSIX_TABLE);
        let table_pci_bar = table & PCI_MSIX_TABLE_BIR;
        let table_offset = (table & PCI_MSIX_TABLE_OFFSET) as u64;
        let pba = config.read_config_dword(msix_cap_start + PCI_MSIX_PBA);
        let pba_pci_bar = pba & PCI_MSIX_PBA_BIR;
        let pba_offset = (pba & PCI_MSIX_PBA_OFFSET) as u64;

        VfioMsixCap {
            config: MsixConfig::new(table_size, vm_socket_irq),
            offset: msix_cap_start,
            table_size,
            table_pci_bar,
            table_offset,
            pba_pci_bar,
            pba_offset,
        }
    }

    // only msix control register is writable and need special handle in pci r/w
    fn is_msix_control_reg(&self, offset: u32, size: u32) -> bool {
        let control_start = self.offset + PCI_MSIX_FLAGS;
        let control_end = control_start + 2;

        if offset < control_end && offset + size > control_start {
            true
        } else {
            false
        }
    }

    fn read_msix_control(&self, data: &mut u32) {
        *data = self.config.read_msix_capability(*data);
    }

    fn write_msix_control(&mut self, data: &[u8]) -> Option<VfioMsiChange> {
        let old_enabled = self.config.enabled();

        self.config
            .write_msix_capability(PCI_MSIX_FLAGS.into(), data);

        let new_enabled = self.config.enabled();
        if !old_enabled && new_enabled {
            Some(VfioMsiChange::Enable)
        } else if old_enabled && !new_enabled {
            Some(VfioMsiChange::Disable)
        } else {
            None
        }
    }

    fn is_msix_table(&self, bar_index: u32, offset: u64) -> bool {
        let table_size: u64 = (self.table_size * (MSIX_TABLE_ENTRIES_MODULO as u16)).into();
        if bar_index != self.table_pci_bar
            || offset < self.table_offset
            || offset >= self.table_offset + table_size
        {
            false
        } else {
            true
        }
    }

    fn read_table(&self, offset: u64, data: &mut [u8]) {
        let offset = offset - self.table_offset;
        self.config.read_msix_table(offset, data);
    }

    fn write_table(&mut self, offset: u64, data: &[u8]) {
        let offset = offset - self.table_offset;
        self.config.write_msix_table(offset, data);
    }

    fn is_msix_pba(&self, bar_index: u32, offset: u64) -> bool {
        let pba_size: u64 = (((self.table_size + BITS_PER_PBA_ENTRY as u16 - 1)
            / BITS_PER_PBA_ENTRY as u16)
            * MSIX_PBA_ENTRIES_MODULO as u16) as u64;
        if bar_index != self.pba_pci_bar
            || offset < self.pba_offset
            || offset >= self.pba_offset + pba_size
        {
            false
        } else {
            true
        }
    }

    fn read_pba(&self, offset: u64, data: &mut [u8]) {
        let offset = offset - self.pba_offset;
        self.config.read_pba_entries(offset, data);
    }

    fn write_pba(&mut self, offset: u64, data: &[u8]) {
        let offset = offset - self.pba_offset;
        self.config.write_pba_entries(offset, data);
    }

    fn is_msix_bar(&self, bar_index: u32) -> bool {
        if bar_index == self.table_pci_bar || bar_index == self.pba_pci_bar {
            true
        } else {
            false
        }
    }

    fn get_msix_irqfds(&self) -> Option<Vec<&EventFd>> {
        let mut irqfds = Vec::new();

        for i in 0..self.table_size {
            let irqfd = self.config.get_irqfd(i as usize);
            if let Some(fd) = irqfd {
                irqfds.push(fd);
            } else {
                return None;
            }
        }

        Some(irqfds)
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

enum DeviceData {
    IntelGfxData { opregion_index: u32 },
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
    msix_cap: Option<VfioMsixCap>,
    irq_type: Option<VfioIrqType>,
    vm_socket_mem: VmMemoryControlRequestSocket,
    vm_socket_irq: Arc<VmIrqRequestSocket>,
    device_data: Option<DeviceData>,

    // scratch MemoryMapping to avoid unmap beform vm exit
    mem: Vec<MemoryMapping>,
}

impl VfioPciDevice {
    /// Constructs a new Vfio Pci device for the give Vfio device
    pub fn new(
        device: VfioDevice,
        vfio_device_socket_irq: VmIrqRequestSocket,
        vfio_device_socket_mem: VmMemoryControlRequestSocket,
    ) -> Self {
        let dev = Arc::new(device);
        let config = VfioPciConfig::new(Arc::clone(&dev));
        let vm_socket_irq = Arc::new(vfio_device_socket_irq);
        let mut msi_cap: Option<VfioMsiCap> = None;
        let mut msix_cap: Option<VfioMsixCap> = None;

        let mut cap_next: u32 = config.read_config_byte(PCI_CAPABILITY_LIST).into();
        while cap_next != 0 {
            let cap_id = config.read_config_byte(cap_next);
            if cap_id == PCI_CAP_ID_MSI {
                msi_cap = Some(VfioMsiCap::new(
                    &config,
                    cap_next,
                    Arc::clone(&vm_socket_irq),
                ));
            } else if cap_id == PCI_CAP_ID_MSIX {
                msix_cap = Some(VfioMsixCap::new(
                    &config,
                    cap_next,
                    Arc::clone(&vm_socket_irq),
                ));
            }
            let offset = cap_next + PCI_MSI_NEXT_POINTER;
            cap_next = config.read_config_byte(offset).into();
        }

        let vendor_id = config.read_config_word(PCI_VENDOR_ID);
        let class_code = config.read_config_byte(PCI_BASE_CLASS_CODE);

        let is_intel_gfx = vendor_id == INTEL_VENDOR_ID
            && class_code == PciClassCode::DisplayController.get_register_value();
        let device_data = if is_intel_gfx {
            Some(DeviceData::IntelGfxData {
                opregion_index: u32::max_value(),
            })
        } else {
            None
        };

        VfioPciDevice {
            device: dev,
            config,
            pci_bus_dev: None,
            interrupt_evt: None,
            interrupt_resample_evt: None,
            mmio_regions: Vec::new(),
            io_regions: Vec::new(),
            msi_cap,
            msix_cap,
            irq_type: None,
            vm_socket_mem: vfio_device_socket_mem,
            vm_socket_irq,
            device_data,
            mem: Vec::new(),
        }
    }

    fn is_intel_gfx(&self) -> bool {
        let mut ret = false;

        if let Some(device_data) = &self.device_data {
            match *device_data {
                DeviceData::IntelGfxData { .. } => ret = true,
            }
        }

        ret
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
            let mut fds = Vec::new();
            fds.push(interrupt_evt);
            if let Err(e) = self.device.irq_enable(fds, VfioIrqType::Intx) {
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

    fn disable_irqs(&mut self) {
        match self.irq_type {
            Some(VfioIrqType::Msi) => self.disable_msi(),
            Some(VfioIrqType::Msix) => self.disable_msix(),
            _ => (),
        }

        // Above disable_msi() or disable_msix() will enable intx again.
        // so disable_intx here again.
        match self.irq_type {
            Some(VfioIrqType::Intx) => self.disable_intx(),
            _ => (),
        }
    }

    fn enable_msi(&mut self) {
        self.disable_irqs();

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

        let mut fds = Vec::new();
        fds.push(irqfd);
        if let Err(e) = self.device.irq_enable(fds, VfioIrqType::Msi) {
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

    fn enable_msix(&mut self) {
        self.disable_irqs();

        let irqfds = match &self.msix_cap {
            Some(cap) => cap.get_msix_irqfds(),
            None => return,
        };

        if let Some(fds) = irqfds {
            if let Err(e) = self.device.irq_enable(fds, VfioIrqType::Msix) {
                error!("failed to enable msix: {}", e);
                self.enable_intx();
                return;
            }
        } else {
            self.enable_intx();
            return;
        }

        self.irq_type = Some(VfioIrqType::Msix);
    }

    fn disable_msix(&mut self) {
        if let Err(e) = self.device.irq_disable(VfioIrqType::Msix) {
            error!("failed to disable msix: {}", e);
            return;
        }

        self.enable_intx();
    }

    fn add_bar_mmap(&self, index: u32, bar_addr: u64) -> Vec<MemoryMapping> {
        let mut mem_map: Vec<MemoryMapping> = Vec::new();
        if self.device.get_region_flags(index) & VFIO_REGION_INFO_FLAG_MMAP != 0 {
            // the bar storing msix table and pba couldn't mmap.
            // these bars should be trapped, so that msix could be emulated.
            if let Some(msix_cap) = &self.msix_cap {
                if msix_cap.is_msix_bar(index) {
                    return mem_map;
                }
            }

            let mmaps = self.device.get_region_mmap(index);
            if mmaps.is_empty() {
                return mem_map;
            }

            for mmap in mmaps.iter() {
                let mmap_offset = mmap.offset;
                let mmap_size = mmap.size;
                let guest_map_start = bar_addr + mmap_offset;
                let region_offset = self.device.get_region_offset(index);
                let offset: usize = (region_offset + mmap_offset) as usize;
                if self
                    .vm_socket_mem
                    .send(&VmMemoryRequest::RegisterMmapMemory {
                        fd: MaybeOwnedFd::Borrowed(self.device.as_raw_fd()),
                        size: mmap_size as usize,
                        offset,
                        gpa: guest_map_start,
                    })
                    .is_err()
                {
                    break;
                }

                let response = match self.vm_socket_mem.recv() {
                    Ok(res) => res,
                    Err(_) => break,
                };
                match response {
                    VmMemoryResponse::Ok => {
                        // Even if vm has mapped this region, but it is in vm main process,
                        // device process doesn't has this mapping, but vfio_dma_map() need it
                        // in device process, so here map it again.
                        let mmap = match MemoryMapping::from_fd_offset(
                            self.device.as_ref(),
                            mmap_size as usize,
                            offset,
                        ) {
                            Ok(v) => v,
                            Err(_e) => break,
                        };
                        let host = (&mmap).as_ptr() as u64;
                        // Safe because the given guest_map_start is valid guest bar address. and
                        // the host pointer is correct and valid guaranteed by MemoryMapping interface.
                        match unsafe { self.device.vfio_dma_map(guest_map_start, mmap_size, host) }
                        {
                            Ok(_) => mem_map.push(mmap),
                            Err(e) => {
                                error!(
                                    "{}, index: {}, bar_addr:0x{:x}, host:0x{:x}",
                                    e, index, bar_addr, host
                                );
                                break;
                            }
                        }
                    }
                    _ => break,
                }
            }
        }

        mem_map
    }

    fn enable_bars_mmap(&mut self) {
        for mmio_info in self.mmio_regions.iter() {
            let mut mem_map = self.add_bar_mmap(mmio_info.bar_index, mmio_info.start);
            self.mem.append(&mut mem_map);
        }
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
        fds.push(self.vm_socket_mem.as_raw_fd());
        fds.push(self.vm_socket_irq.as_ref().as_raw_fd());
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

        // Quirk, enable igd memory for guest vga arbitrate, otherwise kernel vga arbitrate
        // driver doesn't claim this vga device, then xorg couldn't boot up.
        if self.is_intel_gfx() {
            let mut cmd = self.config.read_config_byte(PCI_COMMAND);
            cmd |= PCI_COMMAND_MEMORY;
            self.config.write_config_byte(cmd, PCI_COMMAND);
        }

        Ok(ranges)
    }

    fn allocate_device_bars(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> Result<Vec<(u64, u64)>, PciDeviceError> {
        let mut ranges = Vec::new();

        if !self.is_intel_gfx() {
            return Ok(ranges);
        }

        // Make intel gfx's opregion as mmio bar, and allocate a gpa for it
        // then write this gpa into pci cfg register
        if let Some((index, size)) = self.device.get_cap_type_info(
            VFIO_REGION_TYPE_PCI_VENDOR_TYPE | (INTEL_VENDOR_ID as u32),
            VFIO_REGION_SUBTYPE_INTEL_IGD_OPREGION,
        ) {
            let (bus, dev) = self
                .pci_bus_dev
                .expect("assign_bus_dev must be called prior to allocate_device_bars");
            let bar_addr = resources
                .mmio_allocator(MmioType::Low)
                .allocate(
                    size,
                    Alloc::PciBar {
                        bus,
                        dev,
                        bar: (index * 4) as u8,
                    },
                    "vfio_bar".to_string(),
                )
                .map_err(|e| PciDeviceError::IoAllocationFailed(size, e))?;
            ranges.push((bar_addr, size));
            self.device_data = Some(DeviceData::IntelGfxData {
                opregion_index: index,
            });

            self.mmio_regions.push(MmioInfo {
                bar_index: index,
                start: bar_addr,
                length: size,
            });
            self.config.write_config_dword(bar_addr as u32, 0xFC);
        }

        Ok(ranges)
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
        } else if reg_idx == PCI_HEADER_TYPE / 4 {
            // Clear multifunction flags as pci_root doesn't
            // support multifunction.
            config &= !PCI_MULTI_FLAG;
        } else if let Some(msix_cap) = &self.msix_cap {
            if msix_cap.is_msix_control_reg(reg, 4) {
                msix_cap.read_msix_control(&mut config);
            }
        }

        // Quirk for intel graphic, set stolen memory size to 0 in pci_cfg[0x51]
        if self.is_intel_gfx() && reg == 0x50 {
            config &= 0xffff00ff;
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

        msi_change = None;
        if let Some(msix_cap) = self.msix_cap.as_mut() {
            if msix_cap.is_msix_control_reg(start as u32, data.len() as u32) {
                msi_change = msix_cap.write_msix_control(data);
            }
        }
        match msi_change {
            Some(VfioMsiChange::Enable) => self.enable_msix(),
            Some(VfioMsiChange::Disable) => self.disable_msix(),
            None => (),
        }

        // if guest enable memory access, then enable bar mappable once
        if start == PCI_COMMAND as u64
            && data.len() == 2
            && data[0] & PCI_COMMAND_MEMORY == PCI_COMMAND_MEMORY
            && self.mem.is_empty()
        {
            self.enable_bars_mmap();
        }

        self.device
            .region_write(VFIO_PCI_CONFIG_REGION_INDEX, data, start);
    }

    fn read_bar(&mut self, addr: u64, data: &mut [u8]) {
        if let Some(mmio_info) = self.find_region(addr) {
            let offset = addr - mmio_info.start;
            let bar_index = mmio_info.bar_index;
            if let Some(msix_cap) = &self.msix_cap {
                if msix_cap.is_msix_table(bar_index, offset) {
                    msix_cap.read_table(offset, data);
                    return;
                } else if msix_cap.is_msix_pba(bar_index, offset) {
                    msix_cap.read_pba(offset, data);
                    return;
                }
            }
            self.device.region_read(bar_index, data, offset);
        }
    }

    fn write_bar(&mut self, addr: u64, data: &[u8]) {
        if let Some(mmio_info) = self.find_region(addr) {
            // Ignore igd opregion's write
            if let Some(device_data) = &self.device_data {
                match *device_data {
                    DeviceData::IntelGfxData { opregion_index } => {
                        if opregion_index == mmio_info.bar_index {
                            return;
                        }
                    }
                }
            }

            let offset = addr - mmio_info.start;
            let bar_index = mmio_info.bar_index;

            if let Some(msix_cap) = self.msix_cap.as_mut() {
                if msix_cap.is_msix_table(bar_index, offset) {
                    msix_cap.write_table(offset, data);
                    return;
                } else if msix_cap.is_msix_pba(bar_index, offset) {
                    msix_cap.write_pba(offset, data);
                    return;
                }
            }

            self.device.region_write(bar_index, data, offset);
        }
    }
}

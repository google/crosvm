// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
use std::cmp::{max, min, Ordering};
use std::sync::Arc;
use sync::Mutex;

use crate::pci::msix::{MsixCap, MsixConfig};
use crate::pci::pci_configuration::{PciBridgeSubclass, PciSubclass, CLASS_REG};
use crate::pci::{
    BarRange, PciAddress, PciBarConfiguration, PciBarPrefetchable, PciBarRegionType, PciClassCode,
    PciConfiguration, PciDevice, PciDeviceError, PciHeaderType, PCI_VENDOR_ID_INTEL,
};
use crate::PciInterruptPin;
use base::{warn, AsRawDescriptors, Event, RawDescriptor, Tube};
use hypervisor::Datamatch;
use resources::{Alloc, MmioType, SystemAllocator};

use crate::pci::pcie::pcie_device::PcieDevice;
use crate::IrqLevelEvent;

const BR_MSIX_TABLE_OFFSET: u64 = 0x0;
const BR_MSIX_PBA_OFFSET: u64 = 0x100;
const PCI_BRIDGE_BAR_SIZE: u64 = 0x1000;
pub const BR_BUS_NUMBER_REG: usize = 0x6;
pub const BR_MEM_REG: usize = 0x8;
// bit[15:4] is memory base[31:20] and alignment to 1MB
pub const BR_MEM_BASE_MASK: u32 = 0xFFF0;
pub const BR_MEM_BASE_SHIFT: u32 = 16;
// bit[31:20] is memory limit[31:20] and alignment to 1MB
pub const BR_MEM_LIMIT_MASK: u32 = 0xFFF0_0000;
pub const BR_PREF_MEM_LOW_REG: usize = 0x9;
// bit[0] and bit[16] is 64bit memory flag
pub const BR_PREF_MEM_64BIT: u32 = 0x001_0001;
pub const BR_PREF_MEM_BASE_HIGH_REG: usize = 0xa;
pub const BR_PREF_MEM_LIMIT_HIGH_REG: usize = 0xb;
pub const BR_WINDOW_ALIGNMENT: u64 = 0x10_0000;
// Kernel allocate at least 2MB mmio for each bridge memory window
pub const BR_MEM_MINIMUM: u64 = 0x20_0000;

/// Holds the bus range for a pci bridge
///
/// * primary - primary bus number
/// * secondary - secondary bus number
/// * subordinate - subordinate bus number
#[derive(Debug, Copy, Clone)]
pub struct PciBridgeBusRange {
    pub primary: u8,
    pub secondary: u8,
    pub subordinate: u8,
}

pub struct PciBridge {
    device: Arc<Mutex<dyn PcieDevice>>,
    config: PciConfiguration,
    pci_address: Option<PciAddress>,
    bus_range: PciBridgeBusRange,
    setting_bar: u8,
    msix_config: Arc<Mutex<MsixConfig>>,
    msix_cap_reg_idx: Option<usize>,
    interrupt_evt: Option<IrqLevelEvent>,
}

impl PciBridge {
    pub fn new(device: Arc<Mutex<dyn PcieDevice>>, msi_device_tube: Tube) -> Self {
        let device_id = device.lock().get_device_id();
        let msix_config = Arc::new(Mutex::new(MsixConfig::new(
            1,
            msi_device_tube,
            (PCI_VENDOR_ID_INTEL as u32) | (device_id as u32) << 16,
            device.lock().debug_label(),
        )));
        let mut config = PciConfiguration::new(
            PCI_VENDOR_ID_INTEL,
            device_id,
            PciClassCode::BridgeDevice,
            &PciBridgeSubclass::PciToPciBridge,
            None,
            PciHeaderType::Bridge,
            0,
            0,
            0,
        );

        let bus_range = device
            .lock()
            .get_bus_range()
            .expect("PciBridge's backend device must implement get_bus_range()");
        let data = [
            bus_range.primary,
            bus_range.secondary,
            bus_range.subordinate,
            0,
        ];
        config.write_reg(BR_BUS_NUMBER_REG, 0, &data[..]);

        PciBridge {
            device,
            config,
            pci_address: None,
            bus_range,
            setting_bar: 0,
            msix_config,
            msix_cap_reg_idx: None,
            interrupt_evt: None,
        }
    }

    pub fn is_pci_bridge(dev: &dyn PciDevice) -> bool {
        let class_reg = dev.read_config_register(CLASS_REG);
        class_reg >> 16
            == ((PciClassCode::BridgeDevice.get_register_value() as u32) << 8)
                | PciBridgeSubclass::PciToPciBridge.get_register_value() as u32
    }

    pub fn get_secondary_bus_num(dev: &dyn PciDevice) -> u8 {
        (dev.read_config_register(BR_BUS_NUMBER_REG) >> 8) as u8
    }

    fn write_bridge_window(
        &mut self,
        window_base: u32,
        window_size: u32,
        pref_window_base: u64,
        pref_window_size: u64,
    ) {
        // both window_base and window_size should be aligned to 1M
        if window_base & (BR_WINDOW_ALIGNMENT as u32 - 1) == 0
            && window_size != 0
            && window_size & (BR_WINDOW_ALIGNMENT as u32 - 1) == 0
        {
            // the top of memory will be one less than a 1MB boundary
            let limit = (window_base + window_size - BR_WINDOW_ALIGNMENT as u32) as u32;
            let value = (window_base >> BR_MEM_BASE_SHIFT) | limit;
            self.write_config_register(BR_MEM_REG, 0, &value.to_le_bytes());
        }

        // both pref_window_base and pref_window_size should be aligned to 1M
        if pref_window_base & (BR_WINDOW_ALIGNMENT - 1) == 0
            && pref_window_size != 0
            && pref_window_size & (BR_WINDOW_ALIGNMENT - 1) == 0
        {
            // the top of memory will be one less than a 1MB boundary
            let limit = pref_window_base + pref_window_size - BR_WINDOW_ALIGNMENT;
            let low_value = ((pref_window_base as u32) >> BR_MEM_BASE_SHIFT)
                | (limit as u32)
                | BR_PREF_MEM_64BIT;
            self.write_config_register(BR_PREF_MEM_LOW_REG, 0, &low_value.to_le_bytes());
            let high_base_value = (pref_window_base >> 32) as u32;
            self.write_config_register(
                BR_PREF_MEM_BASE_HIGH_REG,
                0,
                &high_base_value.to_le_bytes(),
            );
            let high_top_value = (limit >> 32) as u32;
            self.write_config_register(
                BR_PREF_MEM_LIMIT_HIGH_REG,
                0,
                &high_top_value.to_le_bytes(),
            );
        }
    }

    pub fn get_secondary_num(&self) -> u8 {
        self.bus_range.secondary
    }

    pub fn get_subordinate_num(&self) -> u8 {
        self.bus_range.subordinate
    }
}

impl PciDevice for PciBridge {
    fn debug_label(&self) -> String {
        self.device.lock().debug_label()
    }

    fn allocate_address(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> std::result::Result<PciAddress, PciDeviceError> {
        let address = self.device.lock().allocate_address(resources)?;
        self.pci_address = Some(address);
        Ok(address)
    }

    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut rds = Vec::new();
        if let Some(interrupt_evt) = &self.interrupt_evt {
            rds.extend(interrupt_evt.as_raw_descriptors());
        }
        let descriptor = self.msix_config.lock().get_msi_socket();
        rds.push(descriptor);
        rds
    }

    fn assign_irq(
        &mut self,
        irq_evt: &IrqLevelEvent,
        irq_num: Option<u32>,
    ) -> Option<(u32, PciInterruptPin)> {
        self.interrupt_evt = Some(irq_evt.try_clone().ok()?);
        let msix_config_clone = self.msix_config.clone();
        self.device.lock().clone_interrupt(msix_config_clone);

        let gsi = irq_num?;
        let pin = self.pci_address.map_or(
            PciInterruptPin::IntA,
            PciConfiguration::suggested_interrupt_pin,
        );
        self.config.set_irq(gsi as u8, pin);

        Some((gsi, pin))
    }

    fn allocate_io_bars(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> std::result::Result<Vec<BarRange>, PciDeviceError> {
        let address = self
            .pci_address
            .expect("allocate_address must be called prior to allocate_io_bars");
        // Pci bridge need one bar for msix
        let mut ranges: Vec<BarRange> = Vec::new();
        let bar_addr = resources
            .mmio_allocator(MmioType::Low)
            .allocate_with_align(
                PCI_BRIDGE_BAR_SIZE,
                Alloc::PciBar {
                    bus: address.bus,
                    dev: address.dev,
                    func: address.func,
                    bar: 0,
                },
                "pcie_rootport_bar".to_string(),
                PCI_BRIDGE_BAR_SIZE,
            )
            .map_err(|e| PciDeviceError::IoAllocationFailed(PCI_BRIDGE_BAR_SIZE, e))?;
        let config = PciBarConfiguration::new(
            0,
            PCI_BRIDGE_BAR_SIZE,
            PciBarRegionType::Memory32BitRegion,
            PciBarPrefetchable::NotPrefetchable,
        )
        .set_address(bar_addr);
        self.setting_bar =
            self.config
                .add_pci_bar(config)
                .map_err(|e| PciDeviceError::IoRegistrationFailed(bar_addr, e))? as u8;
        ranges.push(BarRange {
            addr: bar_addr,
            size: PCI_BRIDGE_BAR_SIZE,
            prefetchable: false,
        });

        let msix_cap = MsixCap::new(
            self.setting_bar,
            self.msix_config.lock().num_vectors(),
            BR_MSIX_TABLE_OFFSET as u32,
            self.setting_bar,
            BR_MSIX_PBA_OFFSET as u32,
        );
        let msix_cap_reg = self
            .config
            .add_capability(&msix_cap)
            .map_err(PciDeviceError::CapabilitiesSetup)?;
        self.msix_cap_reg_idx = Some(msix_cap_reg / 4);

        Ok(ranges)
    }

    fn allocate_device_bars(
        &mut self,
        _resources: &mut SystemAllocator,
    ) -> std::result::Result<Vec<BarRange>, PciDeviceError> {
        Ok(Vec::new())
    }

    fn get_bar_configuration(&self, bar_num: usize) -> Option<PciBarConfiguration> {
        self.config.get_bar_configuration(bar_num)
    }

    fn register_device_capabilities(&mut self) -> std::result::Result<(), PciDeviceError> {
        let caps = self.device.lock().get_caps();
        for cap in caps {
            let cap_reg = self
                .config
                .add_capability(&*cap)
                .map_err(PciDeviceError::CapabilitiesSetup)?;

            self.device
                .lock()
                .set_capability_reg_idx(cap.id(), cap_reg / 4);
        }

        Ok(())
    }

    fn ioevents(&self) -> Vec<(&Event, u64, Datamatch)> {
        Vec::new()
    }

    fn read_config_register(&self, reg_idx: usize) -> u32 {
        let mut data: u32 = self.config.read_reg(reg_idx);
        if let Some(msix_cap_reg_idx) = self.msix_cap_reg_idx {
            if msix_cap_reg_idx == reg_idx {
                data = self.msix_config.lock().read_msix_capability(data);
                return data;
            }
        }

        self.device.lock().read_config(reg_idx, &mut data);
        data
    }

    fn write_config_register(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        if let Some(msix_cap_reg_idx) = self.msix_cap_reg_idx {
            if msix_cap_reg_idx == reg_idx {
                self.msix_config.lock().write_msix_capability(offset, data);
            }
        }

        // Suppose kernel won't modify primary/secondary/subordinate bus number,
        // if it indeed modify, print a warning
        if reg_idx == BR_BUS_NUMBER_REG {
            let len = data.len();
            if offset == 0 && len == 1 && data[0] != self.bus_range.primary {
                warn!(
                    "kernel modify primary bus number: {} -> {}",
                    self.bus_range.primary, data[0]
                );
            } else if offset == 0 && len == 2 {
                if data[0] != self.bus_range.primary {
                    warn!(
                        "kernel modify primary bus number: {} -> {}",
                        self.bus_range.primary, data[0]
                    );
                }
                if data[1] != self.bus_range.secondary {
                    warn!(
                        "kernel modify secondary bus number: {} -> {}",
                        self.bus_range.secondary, data[1]
                    );
                }
            } else if offset == 1 && len == 1 && data[0] != self.bus_range.secondary {
                warn!(
                    "kernel modify secondary bus number: {} -> {}",
                    self.bus_range.secondary, data[0]
                );
            } else if offset == 2 && len == 1 && data[0] != self.bus_range.subordinate {
                warn!(
                    "kernel modify subordinate bus number: {} -> {}",
                    self.bus_range.subordinate, data[0]
                );
            }
        }

        self.device.lock().write_config(reg_idx, offset, data);

        (&mut self.config).write_reg(reg_idx, offset, data)
    }

    fn read_bar(&mut self, addr: u64, data: &mut [u8]) {
        // The driver is only allowed to do aligned, properly sized access.
        let bar0 = self.config.get_bar_addr(self.setting_bar as usize);
        let offset = addr - bar0;
        match offset.cmp(&BR_MSIX_PBA_OFFSET) {
            Ordering::Less => {
                self.msix_config
                    .lock()
                    .read_msix_table(offset - BR_MSIX_TABLE_OFFSET, data);
            }
            Ordering::Equal => {
                self.msix_config
                    .lock()
                    .read_pba_entries(offset - BR_MSIX_PBA_OFFSET, data);
            }
            Ordering::Greater => (),
        }
    }

    fn write_bar(&mut self, addr: u64, data: &[u8]) {
        let bar0 = self.config.get_bar_addr(self.setting_bar as usize);
        let offset = addr - bar0;
        match offset.cmp(&BR_MSIX_PBA_OFFSET) {
            Ordering::Less => {
                self.msix_config
                    .lock()
                    .write_msix_table(offset - BR_MSIX_TABLE_OFFSET, data);
            }
            Ordering::Equal => {
                self.msix_config
                    .lock()
                    .write_pba_entries(offset - BR_MSIX_PBA_OFFSET, data);
            }
            Ordering::Greater => (),
        }
    }

    fn get_removed_children_devices(&self) -> Vec<PciAddress> {
        self.device.lock().get_removed_devices()
    }

    fn configure_bridge_window(
        &mut self,
        resources: &mut SystemAllocator,
        bar_ranges: &[BarRange],
    ) -> std::result::Result<(), PciDeviceError> {
        let address = self
            .pci_address
            .expect("allocate_address must be called prior to configure_bridge_window");

        let mut window_base: u64 = u64::MAX;
        let mut window_size: u64 = 0;
        let mut pref_window_base: u64 = u64::MAX;
        let mut pref_window_size: u64 = 0;

        if self.device.lock().hotplug_implemented() {
            // Bridge for children hotplug, get desired bridge window size and reserve
            // it for guest OS use
            let (win_size, pref_win_size) = self.device.lock().get_bridge_window_size();
            if win_size != 0 {
                window_size = win_size;
            }

            if pref_win_size != 0 {
                pref_window_size = pref_win_size;
            }
        } else {
            // Bridge has children connected, get bridge window size from children
            for &BarRange {
                addr,
                size,
                prefetchable,
            } in bar_ranges.iter()
            {
                if prefetchable {
                    pref_window_base = min(pref_window_base, addr);
                    pref_window_size = max(pref_window_size, addr + size - pref_window_base);
                } else {
                    window_base = min(window_base, addr);
                    window_size = max(window_size, addr + size - window_base);
                }
            }
        }

        if window_size == 0 {
            // Allocate at least 2MB bridge winodw
            window_size = BR_MEM_MINIMUM;
        }
        // align window_size to 1MB
        if window_size & (BR_WINDOW_ALIGNMENT - 1) != 0 {
            window_size = (window_size + BR_WINDOW_ALIGNMENT - 1) & (!(BR_WINDOW_ALIGNMENT - 1));
        }
        // if window_base isn't set, allocate a new one
        if window_base == u64::MAX {
            match resources.mmio_allocator(MmioType::Low).allocate_with_align(
                window_size,
                Alloc::PciBridgeWindow {
                    bus: address.bus,
                    dev: address.dev,
                    func: address.func,
                },
                "pci_bridge_window".to_string(),
                BR_WINDOW_ALIGNMENT,
            ) {
                Ok(addr) => window_base = addr,
                Err(e) => warn!(
                    "{} failed to allocate bridge window: {}",
                    self.debug_label(),
                    e
                ),
            }
        } else {
            // align window_base to 1MB
            if window_base & (BR_WINDOW_ALIGNMENT - 1) != 0 {
                window_base =
                    (window_base + BR_WINDOW_ALIGNMENT - 1) & (!(BR_WINDOW_ALIGNMENT - 1));
            }
        }

        if pref_window_size == 0 {
            // Allocate at least 2MB prefetch bridge window
            pref_window_size = BR_MEM_MINIMUM;
        }
        // align pref_window_size to 1MB
        if pref_window_size & (BR_WINDOW_ALIGNMENT - 1) != 0 {
            pref_window_size =
                (pref_window_size + BR_WINDOW_ALIGNMENT - 1) & (!(BR_WINDOW_ALIGNMENT - 1));
        }
        // if pref_window_base isn't set, allocate a new one
        if pref_window_base == u64::MAX {
            match resources
                .mmio_allocator(MmioType::High)
                .allocate_with_align(
                    pref_window_size,
                    Alloc::PciBridgeWindow {
                        bus: address.bus,
                        dev: address.dev,
                        func: address.func,
                    },
                    "pci_bridge_window".to_string(),
                    BR_WINDOW_ALIGNMENT,
                ) {
                Ok(addr) => pref_window_base = addr,
                Err(e) => warn!(
                    "{} failed to allocate bridge window: {}",
                    self.debug_label(),
                    e
                ),
            }
        } else {
            // align pref_window_base to 1MB
            if pref_window_base & (BR_WINDOW_ALIGNMENT - 1) != 0 {
                pref_window_base =
                    (window_base + BR_WINDOW_ALIGNMENT - 1) & (!(BR_WINDOW_ALIGNMENT - 1));
            }
        }

        self.write_bridge_window(
            window_base as u32,
            window_size as u32,
            pref_window_base,
            pref_window_size,
        );
        Ok(())
    }
}

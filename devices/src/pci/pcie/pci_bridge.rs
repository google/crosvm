// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::max;
use std::cmp::min;
use std::sync::Arc;

use base::warn;
use base::AsRawDescriptors;
use base::RawDescriptor;
use base::Tube;
use resources::Alloc;
use resources::AllocOptions;
use resources::SystemAllocator;
use sync::Mutex;

use crate::pci::msi::MsiCap;
use crate::pci::msi::MsiConfig;
use crate::pci::pci_configuration::PciBridgeSubclass;
use crate::pci::pcie::pcie_device::PcieDevice;
use crate::pci::BarRange;
use crate::pci::PciAddress;
use crate::pci::PciBarConfiguration;
use crate::pci::PciBus;
use crate::pci::PciClassCode;
use crate::pci::PciConfiguration;
use crate::pci::PciDevice;
use crate::pci::PciDeviceError;
use crate::pci::PciHeaderType;
use crate::pci::PCI_VENDOR_ID_INTEL;
use crate::IrqLevelEvent;
use crate::PciInterruptPin;
use crate::Suspendable;

pub const BR_BUS_NUMBER_REG: usize = 0x6;
pub const BR_BUS_SUBORDINATE_OFFSET: usize = 0x2;
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
pub const BR_WINDOW_MASK: u64 = !(BR_WINDOW_ALIGNMENT - 1);
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
    pci_bus: Arc<Mutex<PciBus>>,
    bus_range: PciBridgeBusRange,
    msi_config: Arc<Mutex<MsiConfig>>,
    msi_cap_offset: u32,
    interrupt_evt: Option<IrqLevelEvent>,
}

impl PciBridge {
    pub fn new(device: Arc<Mutex<dyn PcieDevice>>, msi_device_tube: Tube) -> Self {
        let device_id = device.lock().get_device_id();
        let msi_config = Arc::new(Mutex::new(MsiConfig::new(
            true,
            false,
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
        let msi_cap = MsiCap::new(true, false);
        let msi_cap_reg = config
            .add_capability(&msi_cap)
            .map_err(PciDeviceError::CapabilitiesSetup)
            .unwrap();
        let msi_cap_offset = msi_cap_reg as u32;
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
        let pci_bus = Arc::new(Mutex::new(PciBus::new(
            bus_range.secondary,
            bus_range.primary,
            device.lock().hotplug_implemented(),
        )));

        PciBridge {
            device,
            config,
            pci_address: None,
            pci_bus,
            bus_range,
            msi_config,
            msi_cap_offset,
            interrupt_evt: None,
        }
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

fn finalize_window(
    resources: &mut SystemAllocator,
    prefetchable: bool,
    alloc: Alloc,
    mut base: u64,
    mut size: u64,
) -> std::result::Result<(u64, u64), PciDeviceError> {
    if size == 0 {
        // Allocate at least 2MB bridge winodw
        size = BR_MEM_MINIMUM;
    }
    // if base isn't set, allocate a new one
    if base == u64::MAX {
        // align size to 1MB
        if size & (BR_WINDOW_ALIGNMENT - 1) != 0 {
            size = (size + BR_WINDOW_ALIGNMENT - 1) & BR_WINDOW_MASK;
        }
        match resources.allocate_mmio(
            size,
            alloc,
            "pci_bridge_window".to_string(),
            AllocOptions::new()
                .prefetchable(prefetchable)
                .align(BR_WINDOW_ALIGNMENT),
        ) {
            Ok(addr) => Ok((addr, size)),
            Err(e) => Err(PciDeviceError::PciBusWindowAllocationFailure(format!(
                "failed to allocate bridge window: {}",
                e
            ))),
        }
    } else {
        // align base to 1MB
        if base & (BR_WINDOW_ALIGNMENT - 1) != 0 {
            size += base - (base & BR_WINDOW_MASK);
            // align size to 1MB
            if size & (BR_WINDOW_ALIGNMENT - 1) != 0 {
                size = (size + BR_WINDOW_ALIGNMENT - 1) & BR_WINDOW_MASK;
            }
            base &= BR_WINDOW_MASK;
        }
        Ok((base, size))
    }
}

impl PciDevice for PciBridge {
    fn debug_label(&self) -> String {
        self.device.lock().debug_label()
    }

    fn preferred_address(&self) -> Option<PciAddress> {
        self.device.lock().preferred_address()
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
        let descriptor = self.msi_config.lock().get_msi_socket();
        rds.push(descriptor);
        rds
    }

    fn assign_irq(&mut self, irq_evt: IrqLevelEvent, pin: PciInterruptPin, irq_num: u32) {
        self.interrupt_evt = Some(irq_evt);
        let msi_config_clone = self.msi_config.clone();
        self.device.lock().clone_interrupt(msi_config_clone);
        self.config.set_irq(irq_num as u8, pin);
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

    fn read_config_register(&self, reg_idx: usize) -> u32 {
        let mut data: u32 = self.config.read_reg(reg_idx);

        let reg_offset: u64 = reg_idx as u64 * 4;

        let locked_msi_config = self.msi_config.lock();
        if locked_msi_config.is_msi_reg(self.msi_cap_offset, reg_offset, 0) {
            let offset = reg_offset as u32 - self.msi_cap_offset;
            data = locked_msi_config.read_msi_capability(offset, data);
            return data;
        }
        std::mem::drop(locked_msi_config);
        self.device.lock().read_config(reg_idx, &mut data);
        data
    }

    fn write_config_register(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        let reg_offset = reg_idx as u64 * 4;

        let mut locked_msi_config = self.msi_config.lock();
        if locked_msi_config.is_msi_reg(self.msi_cap_offset, reg_offset, data.len()) {
            let offset = reg_offset as u32 + offset as u32 - self.msi_cap_offset;
            locked_msi_config.write_msi_capability(offset, data);
        }
        std::mem::drop(locked_msi_config);
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

    fn read_bar(&mut self, _addr: u64, _data: &mut [u8]) {}

    fn write_bar(&mut self, _addr: u64, _data: &[u8]) {}

    fn get_removed_children_devices(&self) -> Vec<PciAddress> {
        if !self.device.lock().get_removed_devices().is_empty() {
            self.pci_bus.lock().get_downstream_devices()
        } else {
            Vec::new()
        }
    }

    fn get_new_pci_bus(&self) -> Option<Arc<Mutex<PciBus>>> {
        Some(self.pci_bus.clone())
    }

    fn configure_bridge_window(
        &mut self,
        resources: &mut SystemAllocator,
        bar_ranges: &[BarRange],
    ) -> std::result::Result<Vec<BarRange>, PciDeviceError> {
        let address = self
            .pci_address
            .expect("allocate_address must be called prior to configure_bridge_window");
        let mut window_base: u64 = u64::MAX;
        let mut window_size: u64 = 0;
        let mut pref_window_base: u64 = u64::MAX;
        let mut pref_window_size: u64 = 0;
        let hotplug_implemented = self.device.lock().hotplug_implemented();
        let hotplugged = self.device.lock().hotplugged();

        if hotplug_implemented || hotplugged {
            // If bridge is for children hotplug, get desired bridge window size and reserve
            // it for guest OS use.
            // If bridge is hotplugged into the system, get the desired bridge window size
            // from host.
            let (win_size, pref_win_size) = self.device.lock().get_bridge_window_size();
            window_size = win_size;
            pref_window_size = pref_win_size;
        } else {
            // Bridge has children connected, get bridge window size from children
            let mut window_end: u64 = 0;
            let mut pref_window_end: u64 = 0;

            for &BarRange {
                addr,
                size,
                prefetchable,
            } in bar_ranges.iter()
            {
                if prefetchable {
                    pref_window_base = min(pref_window_base, addr);
                    pref_window_end = max(pref_window_end, addr + size);
                } else {
                    window_base = min(window_base, addr);
                    window_end = max(window_end, addr + size);
                }
            }
            if window_end > 0 {
                window_size = window_end - window_base;
            }
            if pref_window_end > 0 {
                pref_window_size = pref_window_end - pref_window_base;
            }
        }

        if !hotplugged {
            // Only static bridge needs to locate their window's position. Hotplugged bridge's
            // window will be handled by guest kernel.
            let window = finalize_window(
                resources,
                false, // prefetchable
                Alloc::PciBridgeWindow {
                    bus: address.bus,
                    dev: address.dev,
                    func: address.func,
                },
                window_base,
                window_size,
            )?;
            window_base = window.0;
            window_size = window.1;

            match finalize_window(
                resources,
                true, // prefetchable
                Alloc::PciBridgePrefetchWindow {
                    bus: address.bus,
                    dev: address.dev,
                    func: address.func,
                },
                pref_window_base,
                pref_window_size,
            ) {
                Ok(pref_window) => {
                    pref_window_base = pref_window.0;
                    pref_window_size = pref_window.1;
                }
                Err(e) => {
                    warn!("failed to allocate PCI bridge prefetchable window: {}", e);
                }
            }
        } else {
            // 0 is Ok here because guest will relocate the bridge window
            if window_size > 0 {
                window_base = 0;
            }
            if pref_window_size > 0 {
                pref_window_base = 0;
            }
        }

        self.write_bridge_window(
            window_base as u32,
            window_size as u32,
            pref_window_base,
            pref_window_size,
        );

        let mut windows = Vec::new();
        if window_size > 0 {
            windows.push(BarRange {
                addr: window_base,
                size: window_size,
                prefetchable: false,
            })
        }
        if pref_window_size > 0 {
            windows.push(BarRange {
                addr: pref_window_base,
                size: pref_window_size,
                prefetchable: true,
            })
        }
        Ok(windows)
    }

    fn set_subordinate_bus(&mut self, bus_no: u8) {
        let bus_reg = self.read_config_register(BR_BUS_NUMBER_REG);
        // Keep the maxmium bus number here because this bridge could have reserved
        // subordinate bus number earlier
        let subordinate_bus = u8::max((bus_reg >> (BR_BUS_SUBORDINATE_OFFSET * 8)) as u8, bus_no);
        self.write_config_register(
            BR_BUS_NUMBER_REG,
            BR_BUS_SUBORDINATE_OFFSET as u64,
            &[subordinate_bus],
        );
    }

    fn destroy_device(&mut self) {
        self.msi_config.lock().destroy()
    }
}

impl Suspendable for PciBridge {}

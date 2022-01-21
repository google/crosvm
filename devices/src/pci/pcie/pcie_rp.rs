// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
use std::sync::Arc;
use sync::Mutex;

use crate::bus::{HostHotPlugKey, HotPlugBus};
use crate::pci::pci_configuration::PciCapabilityID;
use crate::pci::{MsixConfig, PciAddress, PciCapability, PciDeviceError};

use crate::pci::pcie::pci_bridge::PciBridgeBusRange;
use crate::pci::pcie::pcie_device::{PcieCap, PcieDevice};
use crate::pci::pcie::*;
use base::warn;
use data_model::DataInit;
use resources::{Alloc, SystemAllocator};

// reserve 8MB memory window
const PCIE_RP_BR_MEM_SIZE: u64 = 0x80_0000;
// reserve 64MB prefetch window
const PCIE_RP_BR_PREF_MEM_SIZE: u64 = 0x400_0000;

const PCIE_RP_DID: u16 = 0x3420;
pub struct PcieRootPort {
    pcie_cap_reg_idx: Option<usize>,
    msix_config: Option<Arc<Mutex<MsixConfig>>>,
    pci_address: Option<PciAddress>,
    slot_control: u16,
    slot_status: u16,
    bus_range: PciBridgeBusRange,
    downstream_device: Option<(PciAddress, Option<HostHotPlugKey>)>,
    removed_downstream: Option<PciAddress>,
}

impl PcieRootPort {
    /// Constructs a new PCIE root port
    pub fn new(secondary_bus_num: u8) -> Self {
        let bus_range = PciBridgeBusRange {
            primary: 0,
            secondary: secondary_bus_num,
            subordinate: secondary_bus_num,
        };
        PcieRootPort {
            pcie_cap_reg_idx: None,
            msix_config: None,
            pci_address: None,
            slot_control: PCIE_SLTCTL_PIC_OFF | PCIE_SLTCTL_AIC_OFF,
            slot_status: 0,
            bus_range,
            downstream_device: None,
            removed_downstream: None,
        }
    }

    fn read_pcie_cap(&self, offset: usize, data: &mut u32) {
        if offset == PCIE_SLTCTL_OFFSET {
            *data = ((self.slot_status as u32) << 16) | (self.slot_control as u32);
        }
    }

    fn write_pcie_cap(&mut self, offset: usize, data: &[u8]) {
        self.removed_downstream = None;
        match offset {
            PCIE_SLTCTL_OFFSET => match u16::from_slice(data) {
                Some(v) => {
                    let old_control = self.slot_control;
                    self.slot_control = *v;

                    // if slot is populated, power indicator is off,
                    // it will detach devices
                    if (self.slot_status & PCIE_SLTSTA_PDS != 0)
                        && (v & PCIE_SLTCTL_PIC_OFF == PCIE_SLTCTL_PIC_OFF)
                        && (old_control & PCIE_SLTCTL_PIC_OFF != PCIE_SLTCTL_PIC_OFF)
                    {
                        if let Some((guest_pci_addr, _)) = self.downstream_device {
                            self.removed_downstream = Some(guest_pci_addr);
                            self.downstream_device = None;
                        }
                        self.slot_status &= !PCIE_SLTSTA_PDS;
                        self.slot_status |= PCIE_SLTSTA_PDC;
                        self.trigger_hp_interrupt();
                    }

                    if old_control != *v {
                        // send Command completed events
                        self.slot_status |= PCIE_SLTSTA_CC;
                        self.trigger_cc_interrupt();
                    }
                }
                None => warn!("write SLTCTL isn't word, len: {}", data.len()),
            },
            PCIE_SLTSTA_OFFSET => {
                let value = match u16::from_slice(data) {
                    Some(v) => *v,
                    None => {
                        warn!("write SLTSTA isn't word, len: {}", data.len());
                        return;
                    }
                };
                if value & PCIE_SLTSTA_ABP != 0 {
                    self.slot_status &= !PCIE_SLTSTA_ABP;
                }
                if value & PCIE_SLTSTA_PFD != 0 {
                    self.slot_status &= !PCIE_SLTSTA_PFD;
                }
                if value & PCIE_SLTSTA_PDC != 0 {
                    self.slot_status &= !PCIE_SLTSTA_PDC;
                }
                if value & PCIE_SLTSTA_CC != 0 {
                    self.slot_status &= !PCIE_SLTSTA_CC;
                }
                if value & PCIE_SLTSTA_DLLSC != 0 {
                    self.slot_status &= !PCIE_SLTSTA_DLLSC;
                }
            }
            _ => (),
        }
    }

    fn trigger_interrupt(&self) {
        if let Some(msix_config) = &self.msix_config {
            let mut msix_config = msix_config.lock();
            if msix_config.enabled() {
                msix_config.trigger(0)
            }
        }
    }

    fn trigger_cc_interrupt(&self) {
        if (self.slot_control & PCIE_SLTCTL_CCIE) != 0 && (self.slot_status & PCIE_SLTSTA_CC) != 0 {
            self.trigger_interrupt()
        }
    }

    fn trigger_hp_interrupt(&self) {
        if (self.slot_control & PCIE_SLTCTL_HPIE) != 0
            && (self.slot_status & self.slot_control & (PCIE_SLTCTL_ABPE | PCIE_SLTCTL_PDCE)) != 0
        {
            self.trigger_interrupt()
        }
    }
}

impl PcieDevice for PcieRootPort {
    fn get_device_id(&self) -> u16 {
        PCIE_RP_DID
    }
    fn debug_label(&self) -> String {
        "PcieRootPort".to_string()
    }

    fn allocate_address(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> std::result::Result<PciAddress, PciDeviceError> {
        if self.pci_address.is_none() {
            self.pci_address =
                match resources.allocate_pci(self.bus_range.primary, self.debug_label()) {
                    Some(Alloc::PciBar {
                        bus,
                        dev,
                        func,
                        bar: _,
                    }) => Some(PciAddress { bus, dev, func }),
                    _ => None,
                }
        }
        self.pci_address.ok_or(PciDeviceError::PciAllocationFailed)
    }

    fn clone_interrupt(&mut self, msix_config: Arc<Mutex<MsixConfig>>) {
        self.msix_config = Some(msix_config);
    }

    fn get_caps(&self) -> Vec<Box<dyn PciCapability>> {
        vec![Box::new(PcieCap::new(
            PcieDevicePortType::RootPort,
            true,
            0,
        ))]
    }

    fn set_capability_reg_idx(&mut self, id: PciCapabilityID, reg_idx: usize) {
        if let PciCapabilityID::PciExpress = id {
            self.pcie_cap_reg_idx = Some(reg_idx)
        }
    }

    fn read_config(&self, reg_idx: usize, data: &mut u32) {
        if let Some(pcie_cap_reg_idx) = self.pcie_cap_reg_idx {
            if reg_idx >= pcie_cap_reg_idx && reg_idx < pcie_cap_reg_idx + (PCIE_CAP_LEN / 4) {
                let offset = (reg_idx - pcie_cap_reg_idx) * 4;
                self.read_pcie_cap(offset, data);
            }
        }
    }

    fn write_config(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        if let Some(pcie_cap_reg_idx) = self.pcie_cap_reg_idx {
            if reg_idx >= pcie_cap_reg_idx && reg_idx < pcie_cap_reg_idx + (PCIE_CAP_LEN / 4) {
                let delta = ((reg_idx - pcie_cap_reg_idx) * 4) + offset as usize;
                self.write_pcie_cap(delta, data);
            }
        }
    }

    fn get_bus_range(&self) -> Option<PciBridgeBusRange> {
        Some(self.bus_range)
    }

    fn get_removed_devices(&self) -> Vec<PciAddress> {
        let mut removed_devices = Vec::new();
        if let Some(removed_downstream) = self.removed_downstream {
            removed_devices.push(removed_downstream);
        }

        removed_devices
    }

    fn get_bridge_window_size(&self) -> (u64, u64) {
        (PCIE_RP_BR_MEM_SIZE, PCIE_RP_BR_PREF_MEM_SIZE)
    }
}

impl HotPlugBus for PcieRootPort {
    fn hot_plug(&mut self, addr: PciAddress) {
        match self.downstream_device {
            Some((guest_addr, _)) => {
                if guest_addr != addr {
                    return;
                }
            }
            None => return,
        }

        self.slot_status = self.slot_status | PCIE_SLTSTA_PDS | PCIE_SLTSTA_PDC | PCIE_SLTSTA_ABP;
        self.trigger_hp_interrupt();
    }

    fn hot_unplug(&mut self, addr: PciAddress) {
        match self.downstream_device {
            Some((guest_addr, _)) => {
                if guest_addr != addr {
                    return;
                }
            }
            None => return,
        }

        self.slot_status = self.slot_status | PCIE_SLTSTA_PDC | PCIE_SLTSTA_ABP;
        self.trigger_hp_interrupt();
    }

    fn is_match(&self, _host_addr: PciAddress) -> Option<u8> {
        if self.downstream_device.is_none() {
            Some(self.bus_range.secondary)
        } else {
            None
        }
    }

    fn add_hotplug_device(&mut self, host_key: HostHotPlugKey, guest_addr: PciAddress) {
        self.downstream_device = Some((guest_addr, Some(host_key)))
    }

    fn get_hotplug_device(&self, host_key: HostHotPlugKey) -> Option<PciAddress> {
        if let Some((guest_address, Some(host_info))) = &self.downstream_device {
            match host_info {
                HostHotPlugKey::Vfio { host_addr } => {
                    let saved_addr = *host_addr;
                    match host_key {
                        HostHotPlugKey::Vfio { host_addr } => {
                            if host_addr == saved_addr {
                                return Some(*guest_address);
                            }
                        }
                    }
                }
            }
        }

        None
    }
}

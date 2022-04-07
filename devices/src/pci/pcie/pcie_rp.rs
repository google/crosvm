// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::str::FromStr;
use std::sync::Arc;
use sync::Mutex;

use crate::bus::{HostHotPlugKey, HotPlugBus};
use crate::pci::pci_configuration::PciCapabilityID;
use crate::pci::{MsixConfig, PciAddress, PciCapability, PciDeviceError};

use crate::pci::pcie::pci_bridge::PciBridgeBusRange;
use crate::pci::pcie::pcie_device::{PciPmcCap, PcieCap, PcieDevice, PmcConfig};
use crate::pci::pcie::pcie_host::PcieHostRootPort;
use crate::pci::pcie::*;

use anyhow::{anyhow, Result};
use base::warn;
use data_model::DataInit;
use resources::{Alloc, SystemAllocator};
use vm_control::GpeNotify;

// reserve 8MB memory window
const PCIE_RP_BR_MEM_SIZE: u64 = 0x80_0000;
// reserve 64MB prefetch window
const PCIE_RP_BR_PREF_MEM_SIZE: u64 = 0x400_0000;

const PCIE_RP_DID: u16 = 0x3420;
pub struct PcieRootPort {
    pcie_cap_reg_idx: Option<usize>,
    msix_config: Option<Arc<Mutex<MsixConfig>>>,
    pmc_config: PmcConfig,
    pmc_cap_reg_idx: Option<usize>,
    pci_address: Option<PciAddress>,
    slot_control: Option<u16>,
    slot_status: u16,
    root_control: u16,
    root_status: u32,
    hp_interrupt_pending: bool,
    pme_pending_request_id: Option<PciAddress>,
    bus_range: PciBridgeBusRange,
    downstream_device: Option<(PciAddress, Option<HostHotPlugKey>)>,
    removed_downstream: Option<PciAddress>,
    pcie_host: Option<PcieHostRootPort>,
    prepare_hotplug: bool,
}

impl PcieRootPort {
    /// Constructs a new PCIE root port
    pub fn new(secondary_bus_num: u8, slot_implemented: bool) -> Self {
        let bus_range = PciBridgeBusRange {
            primary: 0,
            secondary: secondary_bus_num,
            subordinate: secondary_bus_num,
        };
        PcieRootPort {
            pcie_cap_reg_idx: None,
            msix_config: None,
            pmc_config: PmcConfig::new(),
            pmc_cap_reg_idx: None,
            pci_address: None,
            slot_control: if slot_implemented {
                Some(PCIE_SLTCTL_PIC_OFF | PCIE_SLTCTL_AIC_OFF)
            } else {
                None
            },
            slot_status: 0,
            root_control: 0,
            root_status: 0,
            hp_interrupt_pending: false,
            pme_pending_request_id: None,
            bus_range,
            downstream_device: None,
            removed_downstream: None,
            pcie_host: None,
            prepare_hotplug: false,
        }
    }

    /// Constructs a new PCIE root port which associated with the host physical pcie RP
    pub fn new_from_host(pcie_host: PcieHostRootPort, slot_implemented: bool) -> Result<Self> {
        let bus_range = pcie_host.get_bus_range();
        // if physical pcie root port isn't on bus 0, ignore this physical pcie root port.
        if bus_range.primary != 0 {
            return Err(anyhow!(
                "physical pcie RP isn't on bus 0: {}",
                bus_range.primary
            ));
        }

        Ok(PcieRootPort {
            pcie_cap_reg_idx: None,
            msix_config: None,
            pmc_config: PmcConfig::new(),
            pmc_cap_reg_idx: None,
            pci_address: None,
            slot_control: if slot_implemented {
                Some(PCIE_SLTCTL_PIC_OFF | PCIE_SLTCTL_AIC_OFF)
            } else {
                None
            },
            slot_status: 0,
            root_control: 0,
            root_status: 0,
            hp_interrupt_pending: false,
            pme_pending_request_id: None,
            bus_range,
            downstream_device: None,
            removed_downstream: None,
            pcie_host: Some(pcie_host),
            prepare_hotplug: false,
        })
    }

    fn get_slot_control(&self) -> u16 {
        if let Some(slot_control) = self.slot_control {
            return slot_control;
        }
        0
    }

    fn read_pcie_cap(&self, offset: usize, data: &mut u32) {
        if offset == PCIE_SLTCTL_OFFSET {
            *data = ((self.slot_status as u32) << 16) | (self.get_slot_control() as u32);
        } else if offset == PCIE_ROOTCTL_OFFSET {
            *data = self.root_control as u32;
        } else if offset == PCIE_ROOTSTA_OFFSET {
            *data = self.root_status;
        }
    }

    fn write_pcie_cap(&mut self, offset: usize, data: &[u8]) {
        self.removed_downstream = None;
        match offset {
            PCIE_SLTCTL_OFFSET => {
                let value = match u16::from_slice(data) {
                    Some(&v) => v,
                    None => {
                        warn!("write SLTCTL isn't word, len: {}", data.len());
                        return;
                    }
                };

                // if slot is populated, power indicator is off,
                // it will detach devices
                let old_control = self.get_slot_control();
                match self.slot_control.as_mut() {
                    Some(v) => *v = value,
                    None => return,
                }
                if (self.slot_status & PCIE_SLTSTA_PDS != 0)
                    && (value & PCIE_SLTCTL_PIC_OFF == PCIE_SLTCTL_PIC_OFF)
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

                if old_control != value {
                    // send Command completed events
                    self.slot_status |= PCIE_SLTSTA_CC;
                    self.trigger_cc_interrupt();
                }
            }
            PCIE_SLTSTA_OFFSET => {
                if self.slot_control.is_none() {
                    return;
                }
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
            PCIE_ROOTCTL_OFFSET => match u16::from_slice(data) {
                Some(v) => self.root_control = *v,
                None => warn!("write root control isn't word, len: {}", data.len()),
            },
            PCIE_ROOTSTA_OFFSET => match u32::from_slice(data) {
                Some(v) => {
                    if *v & PCIE_ROOTSTA_PME_STATUS != 0 {
                        if let Some(request_id) = self.pme_pending_request_id {
                            self.root_status &= !PCIE_ROOTSTA_PME_PENDING;
                            let req_id = ((request_id.bus as u32) << 8)
                                | ((request_id.dev as u32) << 3)
                                | (request_id.func as u32);
                            self.root_status &= !PCIE_ROOTSTA_PME_REQ_ID_MASK;
                            self.root_status |= req_id;
                            self.root_status |= PCIE_ROOTSTA_PME_STATUS;
                            self.pme_pending_request_id = None;
                            self.trigger_pme_interrupt();
                        } else {
                            self.root_status &= !PCIE_ROOTSTA_PME_STATUS;
                            if self.hp_interrupt_pending {
                                self.hp_interrupt_pending = false;
                                self.trigger_hp_interrupt();
                            }
                        }
                    }
                }
                None => warn!("write root status isn't dword, len: {}", data.len()),
            },
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
        if (self.get_slot_control() & PCIE_SLTCTL_CCIE) != 0
            && (self.slot_status & PCIE_SLTSTA_CC) != 0
        {
            self.trigger_interrupt()
        }
    }

    fn trigger_hp_interrupt(&self) {
        let slot_control = self.get_slot_control();
        if (slot_control & PCIE_SLTCTL_HPIE) != 0
            && (self.slot_status & slot_control & (PCIE_SLTCTL_ABPE | PCIE_SLTCTL_PDCE)) != 0
        {
            self.trigger_interrupt()
        }
    }

    fn trigger_pme_interrupt(&self) {
        if (self.root_control & PCIE_ROOTCTL_PME_ENABLE) != 0
            && (self.root_status & PCIE_ROOTSTA_PME_STATUS) != 0
        {
            self.trigger_interrupt()
        }
    }

    fn inject_pme(&mut self) {
        if (self.root_status & PCIE_ROOTSTA_PME_STATUS) != 0 {
            self.root_status |= PCIE_ROOTSTA_PME_PENDING;
            self.pme_pending_request_id = self.pci_address;
        } else {
            let request_id = self.pci_address.unwrap();
            let req_id = ((request_id.bus as u32) << 8)
                | ((request_id.dev as u32) << 3)
                | (request_id.func as u32);
            self.root_status &= !PCIE_ROOTSTA_PME_REQ_ID_MASK;
            self.root_status |= req_id;
            self.pme_pending_request_id = None;
            self.root_status |= PCIE_ROOTSTA_PME_STATUS;
            self.trigger_pme_interrupt();
        }
    }

    // when RP is D3, HP interrupt is disabled by pcie driver, so inject a PME to wakeup
    // RP first, then inject HP interrupt.
    fn trigger_hp_or_pme_interrupt(&mut self) {
        if self.pmc_config.should_trigger_pme() {
            self.hp_interrupt_pending = true;
            self.inject_pme();
        } else {
            self.trigger_hp_interrupt();
        }
    }
}

impl PcieDevice for PcieRootPort {
    fn get_device_id(&self) -> u16 {
        match &self.pcie_host {
            Some(host) => host.read_device_id(),
            None => PCIE_RP_DID,
        }
    }

    fn debug_label(&self) -> String {
        match &self.pcie_host {
            Some(host) => host.host_name(),
            None => "PcieRootPort".to_string(),
        }
    }

    fn allocate_address(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> std::result::Result<PciAddress, PciDeviceError> {
        if self.pci_address.is_none() {
            match &self.pcie_host {
                Some(host) => {
                    let address = PciAddress::from_str(&host.host_name())
                        .map_err(|e| PciDeviceError::PciAddressParseFailure(host.host_name(), e))?;
                    if resources.reserve_pci(
                        Alloc::PciBar {
                            bus: address.bus,
                            dev: address.dev,
                            func: address.func,
                            bar: 0,
                        },
                        host.host_name(),
                    ) {
                        self.pci_address = Some(address);
                    } else {
                        self.pci_address = None;
                    }
                }
                None => match resources.allocate_pci(self.bus_range.primary, self.debug_label()) {
                    Some(Alloc::PciBar {
                        bus,
                        dev,
                        func,
                        bar: _,
                    }) => self.pci_address = Some(PciAddress { bus, dev, func }),
                    _ => self.pci_address = None,
                },
            }
        }
        self.pci_address.ok_or(PciDeviceError::PciAllocationFailed)
    }

    fn clone_interrupt(&mut self, msix_config: Arc<Mutex<MsixConfig>>) {
        self.msix_config = Some(msix_config);
    }

    fn get_caps(&self) -> Vec<Box<dyn PciCapability>> {
        vec![
            Box::new(PcieCap::new(
                PcieDevicePortType::RootPort,
                self.slot_control.is_some(),
                0,
            )),
            Box::new(PciPmcCap::new()),
        ]
    }

    fn set_capability_reg_idx(&mut self, id: PciCapabilityID, reg_idx: usize) {
        match id {
            PciCapabilityID::PciExpress => self.pcie_cap_reg_idx = Some(reg_idx),
            PciCapabilityID::PowerManagement => self.pmc_cap_reg_idx = Some(reg_idx),
            _ => (),
        }
    }

    fn read_config(&self, reg_idx: usize, data: &mut u32) {
        if let Some(pcie_cap_reg_idx) = self.pcie_cap_reg_idx {
            if reg_idx >= pcie_cap_reg_idx && reg_idx < pcie_cap_reg_idx + (PCIE_CAP_LEN / 4) {
                let offset = (reg_idx - pcie_cap_reg_idx) * 4;
                self.read_pcie_cap(offset, data);
            }
        }
        if let Some(pmc_cap_reg_idx) = self.pmc_cap_reg_idx {
            if reg_idx == pmc_cap_reg_idx + PMC_CAP_CONTROL_STATE_OFFSET {
                self.pmc_config.read(data);
            }
        }
        if let Some(host) = &self.pcie_host {
            // pcie host may override some config registers
            host.read_config(reg_idx, data);
        }
    }

    fn write_config(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        if let Some(pcie_cap_reg_idx) = self.pcie_cap_reg_idx {
            if reg_idx >= pcie_cap_reg_idx && reg_idx < pcie_cap_reg_idx + (PCIE_CAP_LEN / 4) {
                let delta = ((reg_idx - pcie_cap_reg_idx) * 4) + offset as usize;
                self.write_pcie_cap(delta, data);
            }
        }
        if let Some(pmc_cap_reg_idx) = self.pmc_cap_reg_idx {
            if reg_idx == pmc_cap_reg_idx + PMC_CAP_CONTROL_STATE_OFFSET {
                let old_status = self.pmc_config.get_power_status();
                self.pmc_config.write(offset, data);
                let new_status = self.pmc_config.get_power_status();
                if old_status == PciDevicePower::D3
                    && new_status == PciDevicePower::D0
                    && self.prepare_hotplug
                {
                    if let Some(host) = self.pcie_host.as_mut() {
                        host.hotplug_probe();
                        self.prepare_hotplug = false;
                    }
                }
            }
        }
        if let Some(host) = self.pcie_host.as_mut() {
            // device may write data to host, or do something at specific register write
            host.write_config(reg_idx, offset, data);
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

    fn hotplug_implemented(&self) -> bool {
        self.slot_control.is_some()
    }

    fn get_bridge_window_size(&self) -> (u64, u64) {
        if let Some(host) = &self.pcie_host {
            host.get_bridge_window_size()
        } else {
            (PCIE_RP_BR_MEM_SIZE, PCIE_RP_BR_PREF_MEM_SIZE)
        }
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
        self.trigger_hp_or_pme_interrupt();
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
        self.trigger_hp_or_pme_interrupt();

        if let Some(host) = self.pcie_host.as_mut() {
            host.hot_unplug();
        }
    }

    fn is_match(&self, host_addr: PciAddress) -> Option<u8> {
        let _ = self.slot_control?;

        if self.downstream_device.is_none()
            && ((host_addr.bus >= self.bus_range.secondary
                && host_addr.bus <= self.bus_range.subordinate)
                || self.pcie_host.is_none())
        {
            Some(self.bus_range.secondary)
        } else {
            None
        }
    }

    fn add_hotplug_device(&mut self, host_key: HostHotPlugKey, guest_addr: PciAddress) {
        if self.slot_control.is_none() {
            return;
        }

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

impl GpeNotify for PcieRootPort {
    fn notify(&mut self) {
        if self.slot_control.is_none() {
            return;
        }

        if self.pcie_host.is_some() {
            self.prepare_hotplug = true;
        }

        if self.pmc_config.should_trigger_pme() {
            self.inject_pme();
        }
    }
}

// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::str::FromStr;
use std::sync::Arc;

use base::warn;
use data_model::DataInit;
use once_cell::sync::Lazy;
use resources::Alloc;
use resources::SystemAllocator;
use sync::Mutex;

use crate::pci::pci_configuration::PciCapabilityID;
use crate::pci::pcie::pci_bridge::PciBridgeBusRange;
use crate::pci::pcie::pcie_host::PcieHostPort;
use crate::pci::pcie::*;
use crate::pci::pm::PciDevicePower;
use crate::pci::pm::PmConfig;
use crate::pci::pm::PM_CAP_CONTROL_STATE_OFFSET;
use crate::pci::MsiConfig;
use crate::pci::PciAddress;
use crate::pci::PciDeviceError;

// reserve 8MB memory window
const PCIE_BR_MEM_SIZE: u64 = 0x80_0000;
// reserve 64MB prefetch window
const PCIE_BR_PREF_MEM_SIZE: u64 = 0x400_0000;

fn trigger_interrupt(msi: &Option<Arc<Mutex<MsiConfig>>>) {
    if let Some(msi_config) = msi {
        let msi_config = msi_config.lock();
        if msi_config.is_msi_enabled() {
            msi_config.trigger()
        }
    }
}

struct PcieRootCap {
    secondary_bus_num: u8,
    subordinate_bus_num: u8,

    control: u16,
    status: u32,
    pme_pending_requester_id: Option<u16>,

    msi_config: Option<Arc<Mutex<MsiConfig>>>,
}

impl PcieRootCap {
    fn new(secondary_bus_num: u8, subordinate_bus_num: u8) -> Self {
        PcieRootCap {
            secondary_bus_num,
            subordinate_bus_num,
            control: 0,
            status: 0,
            pme_pending_requester_id: None,
            msi_config: None,
        }
    }

    fn clone_interrupt(&mut self, msi_config: Arc<Mutex<MsiConfig>>) {
        self.msi_config = Some(msi_config);
    }

    fn trigger_pme_interrupt(&self) {
        if (self.control & PCIE_ROOTCTL_PME_ENABLE) != 0
            && (self.status & PCIE_ROOTSTA_PME_STATUS) != 0
        {
            trigger_interrupt(&self.msi_config)
        }
    }
}

static PCIE_ROOTS_CAP: Lazy<Mutex<Vec<Arc<Mutex<PcieRootCap>>>>> =
    Lazy::new(|| Mutex::new(Vec::new()));

fn push_pcie_root_cap(root_cap: Arc<Mutex<PcieRootCap>>) {
    PCIE_ROOTS_CAP.lock().push(root_cap);
}

fn get_pcie_root_cap(bus_num: u8) -> Option<Arc<Mutex<PcieRootCap>>> {
    for root_cap in PCIE_ROOTS_CAP.lock().iter() {
        let root_cap_lock = root_cap.lock();
        if root_cap_lock.secondary_bus_num <= bus_num
            && root_cap_lock.subordinate_bus_num >= bus_num
        {
            return Some(root_cap.clone());
        }
    }

    None
}

pub struct PciePort {
    device_id: u16,
    debug_label: String,
    preferred_address: Option<PciAddress>,
    pci_address: Option<PciAddress>,
    bus_range: PciBridgeBusRange,
    pcie_host: Option<PcieHostPort>,
    pcie_cap_reg_idx: Option<usize>,
    pm_cap_reg_idx: Option<usize>,
    msi_config: Option<Arc<Mutex<MsiConfig>>>,
    pm_config: PmConfig,

    slot_control: Option<u16>,
    slot_status: u16,

    // For PcieRootPort, root_cap point to itself
    // For PcieDownstreamPort or PciDownstreamPort, root_cap point to PcieRootPort its behind.
    root_cap: Arc<Mutex<PcieRootCap>>,
    is_root_port: bool,

    hp_interrupt_pending: bool,
    prepare_hotplug: bool,
    removed_downstream_valid: bool,
}

impl PciePort {
    /// Constructs a new PCIE port
    pub fn new(
        device_id: u16,
        debug_label: String,
        primary_bus_num: u8,
        secondary_bus_num: u8,
        slot_implemented: bool,
        is_root_port: bool,
    ) -> Self {
        let bus_range = PciBridgeBusRange {
            primary: primary_bus_num,
            secondary: secondary_bus_num,
            subordinate: secondary_bus_num,
        };

        let root_cap = if is_root_port {
            let cap = Arc::new(Mutex::new(PcieRootCap::new(
                secondary_bus_num,
                secondary_bus_num,
            )));
            push_pcie_root_cap(cap.clone());
            cap
        } else {
            get_pcie_root_cap(primary_bus_num).expect("Pcie root port should be created at first")
        };

        PciePort {
            device_id,
            debug_label,
            preferred_address: None,
            pci_address: None,
            bus_range,
            pcie_host: None,
            pcie_cap_reg_idx: None,
            pm_cap_reg_idx: None,
            msi_config: None,
            pm_config: PmConfig::new(),

            slot_control: if slot_implemented {
                Some(PCIE_SLTCTL_PIC_OFF | PCIE_SLTCTL_AIC_OFF)
            } else {
                None
            },
            slot_status: 0,

            root_cap,
            is_root_port,

            hp_interrupt_pending: false,
            prepare_hotplug: false,
            removed_downstream_valid: false,
        }
    }

    pub fn new_from_host(
        pcie_host: PcieHostPort,
        slot_implemented: bool,
        is_root_port: bool,
    ) -> std::result::Result<Self, PciDeviceError> {
        let bus_range = pcie_host.get_bus_range();
        let host_address = PciAddress::from_str(&pcie_host.host_name())
            .map_err(|e| PciDeviceError::PciAddressParseFailure(pcie_host.host_name(), e))?;
        let root_cap = if is_root_port {
            let cap = Arc::new(Mutex::new(PcieRootCap::new(
                bus_range.secondary,
                bus_range.subordinate,
            )));
            push_pcie_root_cap(cap.clone());
            cap
        } else {
            get_pcie_root_cap(bus_range.primary).expect("Pcie root port should be created at first")
        };

        Ok(PciePort {
            device_id: pcie_host.read_device_id(),
            debug_label: pcie_host.host_name(),
            preferred_address: Some(host_address),
            pci_address: None,
            bus_range,
            pcie_host: Some(pcie_host),
            pcie_cap_reg_idx: None,
            pm_cap_reg_idx: None,
            msi_config: None,
            pm_config: PmConfig::new(),

            slot_control: if slot_implemented {
                Some(PCIE_SLTCTL_PIC_OFF | PCIE_SLTCTL_AIC_OFF)
            } else {
                None
            },
            slot_status: 0,

            root_cap,
            is_root_port,

            hp_interrupt_pending: false,
            prepare_hotplug: false,
            removed_downstream_valid: false,
        })
    }

    pub fn get_device_id(&self) -> u16 {
        self.device_id
    }

    pub fn get_address(&self) -> Option<PciAddress> {
        self.pci_address
    }

    pub fn debug_label(&self) -> String {
        self.debug_label.clone()
    }

    pub fn preferred_address(&self) -> Option<PciAddress> {
        self.preferred_address
    }

    pub fn allocate_address(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> std::result::Result<PciAddress, PciDeviceError> {
        if self.pci_address.is_none() {
            if let Some(address) = self.preferred_address {
                if resources.reserve_pci(
                    Alloc::PciBar {
                        bus: address.bus,
                        dev: address.dev,
                        func: address.func,
                        bar: 0,
                    },
                    self.debug_label(),
                ) {
                    self.pci_address = Some(address);
                } else {
                    self.pci_address = None;
                }
            } else {
                match resources.allocate_pci(self.bus_range.primary, self.debug_label()) {
                    Some(Alloc::PciBar {
                        bus,
                        dev,
                        func,
                        bar: _,
                    }) => self.pci_address = Some(PciAddress { bus, dev, func }),
                    _ => self.pci_address = None,
                }
            }
        }
        self.pci_address.ok_or(PciDeviceError::PciAllocationFailed)
    }

    fn read_pcie_cap(&self, offset: usize, data: &mut u32) {
        if offset == PCIE_SLTCTL_OFFSET {
            *data = ((self.slot_status as u32) << 16) | (self.get_slot_control() as u32);
        } else if offset == PCIE_ROOTCTL_OFFSET {
            *data = match self.is_root_port {
                true => self.root_cap.lock().control as u32,
                false => 0,
            };
        } else if offset == PCIE_ROOTSTA_OFFSET {
            *data = match self.is_root_port {
                true => self.root_cap.lock().status,
                false => 0,
            };
        }
    }

    fn write_pcie_cap(&mut self, offset: usize, data: &[u8]) {
        self.removed_downstream_valid = false;
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
                    self.removed_downstream_valid = true;
                    self.slot_status &= !PCIE_SLTSTA_PDS;
                    self.trigger_hp_interrupt();
                }

                // Guest enable hotplug interrupt and has hotplug interrupt
                // pending, inject it right row.
                if (old_control & PCIE_SLTCTL_HPIE == 0)
                    && (value & PCIE_SLTCTL_HPIE == PCIE_SLTCTL_HPIE)
                    && self.hp_interrupt_pending
                {
                    self.hp_interrupt_pending = false;
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
                Some(v) => {
                    if self.is_root_port {
                        self.root_cap.lock().control = *v;
                    } else {
                        warn!("write root control register while device isn't root port");
                    }
                }
                None => warn!("write root control isn't word, len: {}", data.len()),
            },
            PCIE_ROOTSTA_OFFSET => match u32::from_slice(data) {
                Some(v) => {
                    if self.is_root_port {
                        if *v & PCIE_ROOTSTA_PME_STATUS != 0 {
                            let mut r = self.root_cap.lock();
                            if let Some(requester_id) = r.pme_pending_requester_id {
                                r.status &= !PCIE_ROOTSTA_PME_PENDING;
                                r.status &= !PCIE_ROOTSTA_PME_REQ_ID_MASK;
                                r.status |= requester_id as u32;
                                r.status |= PCIE_ROOTSTA_PME_STATUS;
                                r.pme_pending_requester_id = None;
                                r.trigger_pme_interrupt();
                            } else {
                                r.status &= !PCIE_ROOTSTA_PME_STATUS;
                            }
                        }
                    } else {
                        warn!("write root status register while device isn't root port");
                    }
                }
                None => warn!("write root status isn't dword, len: {}", data.len()),
            },
            _ => (),
        }
    }

    pub fn read_config(&self, reg_idx: usize, data: &mut u32) {
        if let Some(pcie_cap_reg_idx) = self.pcie_cap_reg_idx {
            if reg_idx >= pcie_cap_reg_idx && reg_idx < pcie_cap_reg_idx + (PCIE_CAP_LEN / 4) {
                let offset = (reg_idx - pcie_cap_reg_idx) * 4;
                self.read_pcie_cap(offset, data);
            }
        }
        if let Some(pm_cap_reg_idx) = self.pm_cap_reg_idx {
            if reg_idx == pm_cap_reg_idx + PM_CAP_CONTROL_STATE_OFFSET {
                self.pm_config.read(data);
            }
        }
        if let Some(host) = &self.pcie_host {
            host.read_config(reg_idx, data);
        }
    }

    pub fn write_config(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        if let Some(pcie_cap_reg_idx) = self.pcie_cap_reg_idx {
            if reg_idx >= pcie_cap_reg_idx && reg_idx < pcie_cap_reg_idx + (PCIE_CAP_LEN / 4) {
                let delta = ((reg_idx - pcie_cap_reg_idx) * 4) + offset as usize;
                self.write_pcie_cap(delta, data);
            }
        }
        if let Some(pm_cap_reg_idx) = self.pm_cap_reg_idx {
            if reg_idx == pm_cap_reg_idx + PM_CAP_CONTROL_STATE_OFFSET {
                let old_status = self.pm_config.get_power_status();
                self.pm_config.write(offset, data);
                let new_status = self.pm_config.get_power_status();
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
            host.write_config(reg_idx, offset, data);
        }
    }

    pub fn set_capability_reg_idx(&mut self, id: PciCapabilityID, reg_idx: usize) {
        match id {
            PciCapabilityID::PciExpress => self.pcie_cap_reg_idx = Some(reg_idx),
            PciCapabilityID::PowerManagement => self.pm_cap_reg_idx = Some(reg_idx),
            _ => (),
        }
    }

    pub fn get_bus_range(&self) -> Option<PciBridgeBusRange> {
        Some(self.bus_range)
    }

    pub fn get_bridge_window_size(&self) -> (u64, u64) {
        if let Some(host) = &self.pcie_host {
            host.get_bridge_window_size()
        } else {
            (PCIE_BR_MEM_SIZE, PCIE_BR_PREF_MEM_SIZE)
        }
    }

    fn get_slot_control(&self) -> u16 {
        if let Some(slot_control) = self.slot_control {
            return slot_control;
        }
        0
    }

    pub fn clone_interrupt(&mut self, msi_config: Arc<Mutex<MsiConfig>>) {
        if self.is_root_port {
            self.root_cap.lock().clone_interrupt(msi_config.clone());
        }
        self.msi_config = Some(msi_config);
    }

    pub fn hotplug_implemented(&self) -> bool {
        self.slot_control.is_some()
    }

    fn trigger_cc_interrupt(&self) {
        if (self.get_slot_control() & PCIE_SLTCTL_CCIE) != 0
            && (self.slot_status & PCIE_SLTSTA_CC) != 0
        {
            trigger_interrupt(&self.msi_config)
        }
    }

    fn trigger_hp_interrupt(&mut self) {
        let slot_control = self.get_slot_control();
        if (slot_control & PCIE_SLTCTL_HPIE) != 0 {
            self.set_slot_status(PCIE_SLTSTA_PDC);
            if (self.slot_status & slot_control & (PCIE_SLTCTL_ABPE | PCIE_SLTCTL_PDCE)) != 0 {
                trigger_interrupt(&self.msi_config)
            }
        }
    }

    pub fn inject_pme(&mut self, requester_id: u16) {
        let mut r = self.root_cap.lock();
        if (r.status & PCIE_ROOTSTA_PME_STATUS) != 0 {
            r.status |= PCIE_ROOTSTA_PME_PENDING;
            r.pme_pending_requester_id = Some(requester_id);
        } else {
            r.status &= !PCIE_ROOTSTA_PME_REQ_ID_MASK;
            r.status |= requester_id as u32;
            r.pme_pending_requester_id = None;
            r.status |= PCIE_ROOTSTA_PME_STATUS;
            r.trigger_pme_interrupt();
        }
    }

    pub fn trigger_hp_or_pme_interrupt(&mut self) {
        if self.pm_config.should_trigger_pme() {
            self.hp_interrupt_pending = true;
            self.inject_pme(self.pci_address.unwrap().pme_requester_id());
        } else {
            self.trigger_hp_interrupt();
        }
    }

    pub fn is_host(&self) -> bool {
        self.pcie_host.is_some()
    }

    pub fn hot_unplug(&mut self) {
        if let Some(host) = self.pcie_host.as_mut() {
            host.hot_unplug()
        }
    }

    pub fn is_match(&self, host_addr: PciAddress) -> Option<u8> {
        if host_addr.bus == self.bus_range.secondary || self.pcie_host.is_none() {
            Some(self.bus_range.secondary)
        } else {
            None
        }
    }

    pub fn removed_downstream_valid(&self) -> bool {
        self.removed_downstream_valid
    }

    pub fn set_slot_status(&mut self, flag: u16) {
        self.slot_status |= flag;
    }

    pub fn should_trigger_pme(&mut self) -> bool {
        self.pm_config.should_trigger_pme()
    }

    pub fn prepare_hotplug(&mut self) {
        self.prepare_hotplug = true;
    }
}

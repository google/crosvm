// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

use base::error;
use resources::SystemAllocator;
use sync::Mutex;

use crate::bus::HotPlugBus;
use crate::bus::HotPlugKey;
use crate::pci::pci_configuration::PciCapabilityID;
use crate::pci::pcie::pci_bridge::PciBridgeBusRange;
use crate::pci::pcie::pcie_device::PcieCap;
use crate::pci::pcie::pcie_device::PcieDevice;
use crate::pci::pcie::pcie_port::PciePort;
use crate::pci::pcie::*;
use crate::pci::pm::PciPmCap;
use crate::pci::MsiConfig;
use crate::pci::PciAddress;
use crate::pci::PciCapability;
use crate::pci::PciDeviceError;

const PCIE_UP_DID: u16 = 0x3500;
const PCIE_DP_DID: u16 = 0x3510;

pub struct PcieUpstreamPort {
    pcie_port: PciePort,
    hotplugged: bool,
    downstream_devices: BTreeMap<PciAddress, HotPlugKey>,
}

impl PcieUpstreamPort {
    /// Constructs a new PCIE upstream port
    pub fn new(primary_bus_num: u8, secondary_bus_num: u8, hotplugged: bool) -> Self {
        PcieUpstreamPort {
            pcie_port: PciePort::new(
                PCIE_UP_DID,
                "PcieUpstreamPort".to_string(),
                primary_bus_num,
                secondary_bus_num,
                false,
                false,
            ),
            hotplugged,
            downstream_devices: BTreeMap::new(),
        }
    }

    pub fn new_from_host(
        pcie_host: PcieHostPort,
        hotplugged: bool,
    ) -> std::result::Result<Self, PciDeviceError> {
        let pcie_port = PciePort::new_from_host(pcie_host, false, false)?;
        Ok(PcieUpstreamPort {
            pcie_port,
            hotplugged,
            downstream_devices: BTreeMap::new(),
        })
    }
}

impl PcieDevice for PcieUpstreamPort {
    fn get_device_id(&self) -> u16 {
        self.pcie_port.get_device_id()
    }

    fn debug_label(&self) -> String {
        self.pcie_port.debug_label()
    }

    fn preferred_address(&self) -> Option<PciAddress> {
        self.pcie_port.preferred_address()
    }

    fn allocate_address(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> std::result::Result<PciAddress, PciDeviceError> {
        self.pcie_port.allocate_address(resources)
    }

    fn clone_interrupt(&mut self, msi_config: Arc<Mutex<MsiConfig>>) {
        self.pcie_port.clone_interrupt(msi_config);
    }

    fn read_config(&self, reg_idx: usize, data: &mut u32) {
        self.pcie_port.read_config(reg_idx, data);
    }

    fn write_config(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        self.pcie_port.write_config(reg_idx, offset, data);
    }

    fn get_caps(&self) -> Vec<Box<dyn PciCapability>> {
        vec![
            Box::new(PcieCap::new(PcieDevicePortType::UpstreamPort, false, 0)),
            Box::new(PciPmCap::new()),
        ]
    }

    fn set_capability_reg_idx(&mut self, id: PciCapabilityID, reg_idx: usize) {
        self.pcie_port.set_capability_reg_idx(id, reg_idx);
    }

    fn get_bus_range(&self) -> Option<PciBridgeBusRange> {
        self.pcie_port.get_bus_range()
    }

    fn get_removed_devices(&self) -> Vec<PciAddress> {
        Vec::new()
    }

    fn hotplug_implemented(&self) -> bool {
        false
    }

    fn hotplugged(&self) -> bool {
        self.hotplugged
    }

    fn get_bridge_window_size(&self) -> (u64, u64) {
        self.pcie_port.get_bridge_window_size()
    }
}

// Even if upstream port do not have a slot present, we still implement hotplug
// bus trait for it. Our purpose is simple. We want to store information of
// downstream devices in this upstream port, so that they could be used during
// hotplug out.
impl HotPlugBus for PcieUpstreamPort {
    // Do nothing. We are not a real hotplug bus.
    fn hot_plug(&mut self, _addr: PciAddress) {}

    // Just remove the downstream device.
    fn hot_unplug(&mut self, addr: PciAddress) {
        self.downstream_devices.remove(&addr);
    }

    fn get_secondary_bus_number(&self) -> Option<u8> {
        Some(self.pcie_port.get_bus_range()?.secondary)
    }

    fn is_match(&self, host_addr: PciAddress) -> Option<u8> {
        self.pcie_port.is_match(host_addr)
    }

    fn add_hotplug_device(&mut self, hotplug_key: HotPlugKey, guest_addr: PciAddress) {
        self.downstream_devices.insert(guest_addr, hotplug_key);
    }

    fn get_hotplug_device(&self, hotplug_key: HotPlugKey) -> Option<PciAddress> {
        for (guest_address, host_info) in self.downstream_devices.iter() {
            if hotplug_key == *host_info {
                return Some(*guest_address);
            }
        }
        None
    }

    fn is_empty(&self) -> bool {
        self.downstream_devices.is_empty()
    }

    fn get_hotplug_key(&self) -> Option<HotPlugKey> {
        if self.pcie_port.is_host() {
            match PciAddress::from_str(&self.pcie_port.debug_label()) {
                Ok(host_addr) => Some(HotPlugKey::HostUpstreamPort { host_addr }),
                Err(e) => {
                    error!(
                        "failed to get hotplug key for {}: {}",
                        self.pcie_port.debug_label(),
                        e
                    );
                    None
                }
            }
        } else {
            None
        }
    }
}

pub struct PcieDownstreamPort {
    pcie_port: PciePort,
    hotplugged: bool,
    downstream_devices: BTreeMap<PciAddress, HotPlugKey>,
    hotplug_out_begin: bool,
    removed_downstream: Vec<PciAddress>,
}

impl PcieDownstreamPort {
    /// Constructs a new PCIE downstream port
    pub fn new(primary_bus_num: u8, secondary_bus_num: u8, hotplugged: bool) -> Self {
        PcieDownstreamPort {
            pcie_port: PciePort::new(
                PCIE_DP_DID,
                "PcieDownstreamPort".to_string(),
                primary_bus_num,
                secondary_bus_num,
                false,
                false,
            ),
            hotplugged,
            downstream_devices: BTreeMap::new(),
            hotplug_out_begin: false,
            removed_downstream: Vec::new(),
        }
    }

    pub fn new_from_host(
        pcie_host: PcieHostPort,
        hotplugged: bool,
    ) -> std::result::Result<Self, PciDeviceError> {
        let pcie_port = PciePort::new_from_host(pcie_host, true, false)?;
        Ok(PcieDownstreamPort {
            pcie_port,
            hotplugged,
            downstream_devices: BTreeMap::new(),
            hotplug_out_begin: false,
            removed_downstream: Vec::new(),
        })
    }
}

impl PcieDevice for PcieDownstreamPort {
    fn get_device_id(&self) -> u16 {
        self.pcie_port.get_device_id()
    }

    fn debug_label(&self) -> String {
        self.pcie_port.debug_label()
    }

    fn preferred_address(&self) -> Option<PciAddress> {
        self.pcie_port.preferred_address()
    }

    fn allocate_address(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> std::result::Result<PciAddress, PciDeviceError> {
        self.pcie_port.allocate_address(resources)
    }

    fn clone_interrupt(&mut self, msi_config: Arc<Mutex<MsiConfig>>) {
        self.pcie_port.clone_interrupt(msi_config);
    }

    fn read_config(&self, reg_idx: usize, data: &mut u32) {
        self.pcie_port.read_config(reg_idx, data);
    }

    fn write_config(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        self.pcie_port.write_config(reg_idx, offset, data);
    }

    fn get_caps(&self) -> Vec<Box<dyn PciCapability>> {
        vec![
            Box::new(PcieCap::new(PcieDevicePortType::DownstreamPort, true, 0)),
            Box::new(PciPmCap::new()),
        ]
    }

    fn set_capability_reg_idx(&mut self, id: PciCapabilityID, reg_idx: usize) {
        self.pcie_port.set_capability_reg_idx(id, reg_idx);
    }

    fn get_bus_range(&self) -> Option<PciBridgeBusRange> {
        self.pcie_port.get_bus_range()
    }

    fn get_removed_devices(&self) -> Vec<PciAddress> {
        if self.pcie_port.removed_downstream_valid() {
            self.removed_downstream.clone()
        } else {
            Vec::new()
        }
    }

    fn hotplug_implemented(&self) -> bool {
        false
    }

    fn hotplugged(&self) -> bool {
        self.hotplugged
    }

    fn get_bridge_window_size(&self) -> (u64, u64) {
        self.pcie_port.get_bridge_window_size()
    }
}

impl HotPlugBus for PcieDownstreamPort {
    fn hot_plug(&mut self, addr: PciAddress) {
        if !self.pcie_port.hotplug_implemented() || self.downstream_devices.get(&addr).is_none() {
            return;
        }
        self.pcie_port
            .set_slot_status(PCIE_SLTSTA_PDS | PCIE_SLTSTA_ABP);
        self.pcie_port.trigger_hp_or_pme_interrupt();
    }

    fn hot_unplug(&mut self, addr: PciAddress) {
        if self.downstream_devices.remove(&addr).is_none() || !self.pcie_port.hotplug_implemented()
        {
            return;
        }

        if !self.hotplug_out_begin {
            self.removed_downstream.clear();
            self.removed_downstream.push(addr);
            // All the remaine devices will be removed also in this hotplug out interrupt
            for (guest_pci_addr, _) in self.downstream_devices.iter() {
                self.removed_downstream.push(*guest_pci_addr);
            }
            self.pcie_port.set_slot_status(PCIE_SLTSTA_ABP);
            self.pcie_port.trigger_hp_or_pme_interrupt();

            if self.pcie_port.is_host() {
                self.pcie_port.hot_unplug()
            }
        }

        self.hotplug_out_begin = true;
    }

    fn get_secondary_bus_number(&self) -> Option<u8> {
        Some(self.pcie_port.get_bus_range()?.secondary)
    }

    fn is_match(&self, host_addr: PciAddress) -> Option<u8> {
        self.pcie_port.is_match(host_addr)
    }

    fn add_hotplug_device(&mut self, hotplug_key: HotPlugKey, guest_addr: PciAddress) {
        if self.hotplug_out_begin {
            self.hotplug_out_begin = false;
            self.downstream_devices.clear();
            self.removed_downstream.clear();
        }

        self.downstream_devices.insert(guest_addr, hotplug_key);
    }

    fn get_hotplug_device(&self, hotplug_key: HotPlugKey) -> Option<PciAddress> {
        for (guest_address, host_info) in self.downstream_devices.iter() {
            if hotplug_key == *host_info {
                return Some(*guest_address);
            }
        }
        None
    }

    fn is_empty(&self) -> bool {
        self.downstream_devices.is_empty()
    }

    fn get_hotplug_key(&self) -> Option<HotPlugKey> {
        if self.pcie_port.is_host() {
            match PciAddress::from_str(&self.pcie_port.debug_label()) {
                Ok(host_addr) => Some(HotPlugKey::HostDownstreamPort { host_addr }),
                Err(e) => {
                    error!(
                        "failed to get hotplug key for {}: {}",
                        self.pcie_port.debug_label(),
                        e
                    );
                    None
                }
            }
        } else {
            None
        }
    }
}

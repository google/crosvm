// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use resources::SystemAllocator;
use sync::Mutex;
use vm_control::GpeNotify;

use crate::bus::HostHotPlugKey;
use crate::bus::HotPlugBus;
use crate::pci::pci_configuration::PciCapabilityID;
use crate::pci::pcie::pci_bridge::PciBridgeBusRange;
use crate::pci::pcie::pcie_device::PcieCap;
use crate::pci::pcie::pcie_device::PcieDevice;
use crate::pci::pcie::pcie_host::PcieHostPort;
use crate::pci::pcie::pcie_port::PciePort;
use crate::pci::pcie::*;
use crate::pci::pm::PciPmcCap;
use crate::pci::MsiConfig;
use crate::pci::PciAddress;
use crate::pci::PciCapability;
use crate::pci::PciDeviceError;

const PCIE_RP_DID: u16 = 0x3420;
pub struct PcieRootPort {
    pcie_port: PciePort,
    downstream_devices: BTreeMap<PciAddress, HostHotPlugKey>,
    hotplug_out_begin: bool,
    removed_downstream: Vec<PciAddress>,
}

impl PcieRootPort {
    /// Constructs a new PCIE root port
    pub fn new(secondary_bus_num: u8, slot_implemented: bool) -> Self {
        PcieRootPort {
            pcie_port: PciePort::new(
                PCIE_RP_DID,
                "PcieRootPort".to_string(),
                0,
                secondary_bus_num,
                slot_implemented,
                true,
            ),
            downstream_devices: BTreeMap::new(),
            hotplug_out_begin: false,
            removed_downstream: Vec::new(),
        }
    }

    /// Constructs a new PCIE root port which associated with the host physical pcie RP
    pub fn new_from_host(pcie_host: PcieHostPort, slot_implemented: bool) -> Result<Self> {
        Ok(PcieRootPort {
            pcie_port: PciePort::new_from_host(pcie_host, slot_implemented, true)
                .context("PciePort::new_from_host failed")?,
            downstream_devices: BTreeMap::new(),
            hotplug_out_begin: false,
            removed_downstream: Vec::new(),
        })
    }
}

impl PcieDevice for PcieRootPort {
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

    fn get_caps(&self) -> Vec<Box<dyn PciCapability>> {
        vec![
            Box::new(PcieCap::new(
                PcieDevicePortType::RootPort,
                self.pcie_port.hotplug_implemented(),
                0,
            )),
            Box::new(PciPmcCap::new()),
        ]
    }

    fn set_capability_reg_idx(&mut self, id: PciCapabilityID, reg_idx: usize) {
        self.pcie_port.set_capability_reg_idx(id, reg_idx);
    }

    fn read_config(&self, reg_idx: usize, data: &mut u32) {
        self.pcie_port.read_config(reg_idx, data);
    }

    fn write_config(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        self.pcie_port.write_config(reg_idx, offset, data);
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
        self.pcie_port.hotplug_implemented()
    }

    fn hotplugged(&self) -> bool {
        false
    }

    fn get_bridge_window_size(&self) -> (u64, u64) {
        self.pcie_port.get_bridge_window_size()
    }
}

impl HotPlugBus for PcieRootPort {
    fn hot_plug(&mut self, addr: PciAddress) {
        if self.downstream_devices.get(&addr).is_none() {
            return;
        }

        self.pcie_port
            .set_slot_status(PCIE_SLTSTA_PDS | PCIE_SLTSTA_ABP);
        self.pcie_port.trigger_hp_or_pme_interrupt();
    }

    fn hot_unplug(&mut self, addr: PciAddress) {
        if self.downstream_devices.remove(&addr).is_none() {
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

    fn is_match(&self, host_addr: PciAddress) -> Option<u8> {
        self.pcie_port.is_match(host_addr)
    }

    fn add_hotplug_device(&mut self, host_key: HostHotPlugKey, guest_addr: PciAddress) {
        if !self.pcie_port.hotplug_implemented() {
            return;
        }

        // Begin the next round hotplug in process
        if self.hotplug_out_begin {
            self.hotplug_out_begin = false;
            self.downstream_devices.clear();
            self.removed_downstream.clear();
        }

        self.downstream_devices.insert(guest_addr, host_key);
    }

    fn get_hotplug_device(&self, host_key: HostHotPlugKey) -> Option<PciAddress> {
        for (guest_address, host_info) in self.downstream_devices.iter() {
            if host_key == *host_info {
                return Some(*guest_address);
            }
        }
        None
    }

    fn is_empty(&self) -> bool {
        self.downstream_devices.is_empty()
    }

    fn get_hotplug_key(&self) -> Option<HostHotPlugKey> {
        None
    }
}

impl GpeNotify for PcieRootPort {
    fn notify(&mut self) {
        if !self.pcie_port.hotplug_implemented() {
            return;
        }

        if self.pcie_port.is_host() {
            self.pcie_port.prepare_hotplug();
        }

        if self.pcie_port.should_trigger_pme() {
            self.pcie_port.inject_pme();
        }
    }
}

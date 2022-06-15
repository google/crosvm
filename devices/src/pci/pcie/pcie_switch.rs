// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;
use sync::Mutex;

use crate::pci::pci_configuration::PciCapabilityID;
use crate::pci::{MsiConfig, PciAddress, PciCapability, PciDeviceError};

use crate::pci::pcie::pci_bridge::PciBridgeBusRange;
use crate::pci::pcie::pcie_device::{PciPmcCap, PcieCap, PcieDevice};
use crate::pci::pcie::pcie_port::PciePort;
use crate::pci::pcie::*;

use resources::SystemAllocator;

const PCIE_UP_DID: u16 = 0x3500;
const PCIE_DP_DID: u16 = 0x3510;

pub struct PcieUpstreamPort {
    pcie_port: PciePort,
    hotplugged: bool,
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
            ),
            hotplugged,
        }
    }

    pub fn new_from_host(pcie_host: PcieHostPort, hotplugged: bool) -> Self {
        PcieUpstreamPort {
            pcie_port: PciePort::new_from_host(pcie_host, false),
            hotplugged,
        }
    }
}

impl PcieDevice for PcieUpstreamPort {
    fn get_device_id(&self) -> u16 {
        self.pcie_port.get_device_id()
    }

    fn debug_label(&self) -> String {
        self.pcie_port.debug_label()
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
            Box::new(PciPmcCap::new()),
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

pub struct PcieDownstreamPort {
    pcie_port: PciePort,
    hotplugged: bool,
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
            ),
            hotplugged,
        }
    }

    pub fn new_from_host(pcie_host: PcieHostPort, hotplugged: bool) -> Self {
        PcieDownstreamPort {
            pcie_port: PciePort::new_from_host(pcie_host, false),
            hotplugged,
        }
    }
}

impl PcieDevice for PcieDownstreamPort {
    fn get_device_id(&self) -> u16 {
        self.pcie_port.get_device_id()
    }

    fn debug_label(&self) -> String {
        self.pcie_port.debug_label()
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
            Box::new(PcieCap::new(PcieDevicePortType::DownstreamPort, false, 0)),
            Box::new(PciPmcCap::new()),
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

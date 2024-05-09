// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::str::FromStr;

use anyhow::bail;
use base::error;
use base::Event;

use crate::bus::HotPlugBus;
use crate::bus::HotPlugKey;
use crate::pci::pcie::pcie_port::PciePort;
use crate::pci::pcie::pcie_port::PciePortVariant;
use crate::pci::pcie::*;
use crate::pci::PciAddress;
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
                PcieDevicePortType::UpstreamPort,
            ),
            hotplugged,
            downstream_devices: BTreeMap::new(),
        }
    }

    pub fn new_from_host(
        pcie_host: PcieHostPort,
        hotplugged: bool,
    ) -> std::result::Result<Self, PciDeviceError> {
        let pcie_port =
            PciePort::new_from_host(pcie_host, false, PcieDevicePortType::UpstreamPort)?;
        Ok(PcieUpstreamPort {
            pcie_port,
            hotplugged,
            downstream_devices: BTreeMap::new(),
        })
    }
}

impl PciePortVariant for PcieUpstreamPort {
    fn get_pcie_port(&self) -> &PciePort {
        &self.pcie_port
    }

    fn get_pcie_port_mut(&mut self) -> &mut PciePort {
        &mut self.pcie_port
    }

    fn get_removed_devices_impl(&self) -> Vec<PciAddress> {
        Vec::new()
    }

    fn hotplug_implemented_impl(&self) -> bool {
        false
    }

    fn hotplugged_impl(&self) -> bool {
        self.hotplugged
    }
}

// Even if upstream port do not have a slot present, we still implement hotplug
// bus trait for it. Our purpose is simple. We want to store information of
// downstream devices in this upstream port, so that they could be used during
// hotplug out.
impl HotPlugBus for PcieUpstreamPort {
    // Do nothing. We are not a real hotplug bus.
    fn hot_plug(&mut self, _addr: PciAddress) -> anyhow::Result<Option<Event>> {
        bail!("hot plug not supported on upstream port.")
    }

    // Just remove the downstream device.
    fn hot_unplug(&mut self, addr: PciAddress) -> anyhow::Result<Option<Event>> {
        self.downstream_devices.remove(&addr);
        Ok(None)
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

    fn get_address(&self) -> Option<PciAddress> {
        self.pcie_port.get_address()
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
                PcieDevicePortType::DownstreamPort,
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
        let pcie_port =
            PciePort::new_from_host(pcie_host, true, PcieDevicePortType::DownstreamPort)?;
        Ok(PcieDownstreamPort {
            pcie_port,
            hotplugged,
            downstream_devices: BTreeMap::new(),
            hotplug_out_begin: false,
            removed_downstream: Vec::new(),
        })
    }
}

impl PciePortVariant for PcieDownstreamPort {
    fn get_pcie_port(&self) -> &PciePort {
        &self.pcie_port
    }

    fn get_pcie_port_mut(&mut self) -> &mut PciePort {
        &mut self.pcie_port
    }

    fn get_removed_devices_impl(&self) -> Vec<PciAddress> {
        if self.pcie_port.removed_downstream_valid() {
            self.removed_downstream.clone()
        } else {
            Vec::new()
        }
    }

    fn hotplug_implemented_impl(&self) -> bool {
        false
    }

    fn hotplugged_impl(&self) -> bool {
        self.hotplugged
    }
}

impl HotPlugBus for PcieDownstreamPort {
    fn hot_plug(&mut self, addr: PciAddress) -> anyhow::Result<Option<Event>> {
        if !self.pcie_port.hotplug_implemented() {
            bail!("hotplug not implemented.");
        }
        if self.downstream_devices.get(&addr).is_none() {
            bail!("no downstream devices.");
        }
        self.pcie_port
            .set_slot_status(PCIE_SLTSTA_PDS | PCIE_SLTSTA_ABP);
        self.pcie_port.trigger_hp_or_pme_interrupt();
        Ok(None)
    }

    fn hot_unplug(&mut self, addr: PciAddress) -> anyhow::Result<Option<Event>> {
        if !self.pcie_port.hotplug_implemented() {
            bail!("hotplug not implemented.");
        }
        if self.downstream_devices.remove(&addr).is_none() {
            bail!("no downstream devices.");
        }

        if !self.hotplug_out_begin {
            self.removed_downstream.clear();
            self.removed_downstream.push(addr);
            // All the remaine devices will be removed also in this hotplug out interrupt
            for (guest_pci_addr, _) in self.downstream_devices.iter() {
                self.removed_downstream.push(*guest_pci_addr);
            }
            if !self.pcie_port.is_hotplug_ready() {
                // The pcie port is not enabled by the guest yet. (i.e.: before PCI enumeration)
                // Don't trigger interrupt, only flipping the presence detected bit in case the bit
                // is already flipped by an earlier hot plug on this port.
                self.pcie_port.mask_slot_status(!PCIE_SLTSTA_PDS);
                return Ok(None);
            }
            self.pcie_port.set_slot_status(PCIE_SLTSTA_ABP);
            self.pcie_port.trigger_hp_or_pme_interrupt();
            let slot_control = self.pcie_port.get_slot_control();
            match slot_control & PCIE_SLTCTL_PIC {
                PCIE_SLTCTL_PIC_ON => {
                    self.pcie_port.set_slot_status(PCIE_SLTSTA_ABP);
                    self.pcie_port.trigger_hp_or_pme_interrupt();
                }
                PCIE_SLTCTL_PIC_OFF => {
                    // Do not press attention button, as the slot is already off. Likely caused by
                    // previous hot plug failed.
                    self.pcie_port.mask_slot_status(!PCIE_SLTSTA_PDS);
                }
                _ => {
                    // Power indicator in blinking state.
                    bail!("Hot unplug fail: Power indicator is blinking.");
                }
            }

            if self.pcie_port.is_host() {
                self.pcie_port.hot_unplug()
            }
        }

        self.hotplug_out_begin = true;
        Ok(None)
    }

    fn get_address(&self) -> Option<PciAddress> {
        self.pcie_port.get_address()
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

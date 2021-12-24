// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
use std::sync::Arc;
use sync::Mutex;

use crate::pci::pci_configuration::PciCapabilityID;
use crate::pci::pcie::pci_bridge::PciBridgeBusRange;
use crate::pci::pcie::*;
use crate::pci::{MsixConfig, PciAddress, PciCapability, PciDeviceError};
use data_model::DataInit;
use resources::SystemAllocator;

pub trait PcieDevice: Send {
    fn get_device_id(&self) -> u16;
    fn debug_label(&self) -> String;
    fn allocate_address(
        &mut self,
        resources: &mut SystemAllocator,
    ) -> std::result::Result<PciAddress, PciDeviceError>;
    fn read_config(&self, reg_idx: usize, data: &mut u32);
    fn write_config(&mut self, reg_idx: usize, offset: u64, data: &[u8]);
    fn clone_interrupt(&mut self, msix_config: Arc<Mutex<MsixConfig>>);
    fn get_caps(&self) -> Vec<Box<dyn PciCapability>>;
    fn set_capability_reg_idx(&mut self, id: PciCapabilityID, reg_idx: usize);
    fn get_bus_range(&self) -> Option<PciBridgeBusRange> {
        None
    }
    fn get_removed_devices(&self) -> Vec<PciAddress>;

    /// Hotplug capability is implemented on this bridge or not.
    /// Return true, the children pci devices could be connected through hotplug
    /// Return false, the children pci devices should be connected statically
    fn hotplug_implemented(&self) -> bool;

    /// Get bridge window size to cover children's mmio size
    /// (u64, u64) -> (non_prefetchable window size, prefetchable_window_size)
    fn get_bridge_window_size(&self) -> (u64, u64);
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PcieCap {
    _cap_vndr: u8,
    _cap_next: u8,
    pcie_cap: u16,
    dev_cap: u32,
    dev_control: u16,
    dev_status: u16,
    link_cap: u32,
    link_control: u16,
    link_status: u16,
    slot_cap: u32,
    slot_control: u16,
    slot_status: u16,
    root_control: u16,
    root_cap: u16,
    root_status: u32,
    dev_cap_2: u32,
    dev_control_2: u16,
    dev_status_2: u16,
    link_cap_2: u32,
    link_control_2: u16,
    link_status_2: u16,
    slot_cap_2: u32,
    slot_control_2: u16,
    slot_status_2: u16,
}
// It is safe to implement DataInit; all members are simple numbers and any value is valid.
unsafe impl DataInit for PcieCap {}

impl PciCapability for PcieCap {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn id(&self) -> PciCapabilityID {
        PciCapabilityID::PciExpress
    }

    fn writable_bits(&self) -> Vec<u32> {
        vec![
            0u32,
            0,
            0xf_ffff,
            0,
            0x3000_0fff,
            0,
            0x11f_1fff,
            0x1f,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]
    }
}

impl PcieCap {
    pub fn new(device_type: PcieDevicePortType, slot: bool, irq_num: u16) -> Self {
        let mut pcie_cap = PCIE_CAP_VERSION;
        pcie_cap |= (device_type as u16) << PCIE_TYPE_SHIFT;
        if slot {
            pcie_cap |= 1 << PCIE_CAP_SLOT_SHIFT;
        }
        pcie_cap |= irq_num << PCIE_CAP_IRQ_NUM_SHIFT;

        let dev_cap = PCIE_DEVCAP_RBER;
        let link_cap = (PCIE_LINK_X1 | PCIE_LINK_2_5GT) as u32;
        let link_status = PCIE_LINK_X1 | PCIE_LINK_2_5GT;

        let mut slot_cap: u32 = 0;
        let mut slot_control: u16 = 0;
        if slot {
            slot_cap = PCIE_SLTCAP_ABP
                | PCIE_SLTCAP_AIP
                | PCIE_SLTCAP_PIP
                | PCIE_SLTCAP_HPS
                | PCIE_SLTCAP_HPC;
            slot_control = PCIE_SLTCTL_PIC_OFF | PCIE_SLTCTL_AIC_OFF;
        }

        PcieCap {
            _cap_vndr: 0,
            _cap_next: 0,
            pcie_cap,
            dev_cap,
            dev_control: 0,
            dev_status: 0,
            link_cap,
            link_control: 0,
            link_status,
            slot_cap,
            slot_control,
            slot_status: 0,
            root_control: 0,
            root_cap: 0,
            root_status: 0,
            dev_cap_2: 0,
            dev_control_2: 0,
            dev_status_2: 0,
            link_cap_2: 0,
            link_control_2: 0,
            link_status_2: 0,
            slot_cap_2: 0,
            slot_control_2: 0,
            slot_status_2: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PciPmcCap {
    _cap_vndr: u8,
    _cap_next: u8,
    pmc_cap: u16,
    pmc_control_status: u16,
    padding: u16,
}

// It is safe to implement DataInit; all members are simple numbers and any value is valid.
unsafe impl DataInit for PciPmcCap {}

impl PciCapability for PciPmcCap {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn id(&self) -> PciCapabilityID {
        PciCapabilityID::PowerManagement
    }

    fn writable_bits(&self) -> Vec<u32> {
        vec![0u32, 0x8103]
    }
}

impl PciPmcCap {
    pub fn new() -> Self {
        let pmc_cap: u16 = PMC_CAP_PME_SUPPORT_D0
            | PMC_CAP_PME_SUPPORT_D3_HOT
            | PMC_CAP_PME_SUPPORT_D3_COLD
            | PMC_CAP_VERSION;
        PciPmcCap {
            _cap_vndr: 0,
            _cap_next: 0,
            pmc_cap,
            pmc_control_status: 0,
            padding: 0,
        }
    }
}

pub struct PmcConfig {
    power_control_status: u16,
}

impl PmcConfig {
    pub fn new() -> Self {
        PmcConfig {
            power_control_status: 0,
        }
    }

    pub fn read(&self, data: &mut u32) {
        *data = self.power_control_status as u32;
    }

    pub fn write(&mut self, offset: u64, data: &[u8]) {
        if offset > 1 {
            return;
        }

        if offset == 0 {
            self.power_control_status &= !PMC_POWER_STATE_MASK;
            self.power_control_status |= data[0] as u16 & PMC_POWER_STATE_MASK;
        }

        let write_data = if offset == 0 && (data.len() == 2 || data.len() == 4) {
            Some((data[1] as u16) << 8)
        } else if offset == 1 && data.len() == 1 {
            Some((data[0] as u16) << 8)
        } else {
            None
        };

        if let Some(write_data) = write_data {
            if write_data & PMC_PME_STATUS != 0 {
                // clear PME_STATUS
                self.power_control_status &= !PMC_PME_STATUS;
            }

            if write_data & PMC_PME_ENABLE != 0 {
                self.power_control_status |= PMC_PME_ENABLE;
            } else {
                self.power_control_status &= !PMC_PME_ENABLE;
            }
        }
    }

    /// If device is in D3 and PME is enabled, set PME status, then device could
    /// inject a pme interrupt into guest
    pub fn should_trigger_pme(&mut self) -> bool {
        if self.power_control_status & PMC_POWER_STATE_MASK == PMC_POWER_STATE_D3
            && self.power_control_status & PMC_PME_ENABLE != 0
        {
            self.power_control_status |= PMC_PME_STATUS;

            return true;
        }

        false
    }

    /// Get device power status
    pub fn get_power_status(&self) -> PciDevicePower {
        match self.power_control_status & PMC_POWER_STATE_MASK {
            PMC_POWER_STATE_D0 => PciDevicePower::D0,
            PMC_POWER_STATE_D3 => PciDevicePower::D3,
            _ => PciDevicePower::Unsupported,
        }
    }
}

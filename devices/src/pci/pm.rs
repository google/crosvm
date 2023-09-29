// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg_attr(windows, allow(dead_code))]

use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

use crate::pci::pci_configuration::PciCapConfig;
use crate::pci::pci_configuration::PciCapConfigWriteResult;
use crate::pci::PciCapability;
use crate::pci::PciCapabilityID;

const PM_CAP_CONTROL_STATE_OFFSET: usize = 1;
pub const PM_CAP_LENGTH: usize = 8;
const PM_CAP_PME_SUPPORT_D0: u16 = 0x0800;
const PM_CAP_PME_SUPPORT_D3_HOT: u16 = 0x4000;
const PM_CAP_PME_SUPPORT_D3_COLD: u16 = 0x8000;
const PM_CAP_VERSION: u16 = 0x2;
const PM_PME_STATUS: u16 = 0x8000;
const PM_PME_ENABLE: u16 = 0x100;
const PM_POWER_STATE_MASK: u16 = 0x3;
const PM_POWER_STATE_D0: u16 = 0;
const PM_POWER_STATE_D3: u16 = 0x3;

#[derive(Eq, PartialEq)]
pub enum PciDevicePower {
    D0 = 0,
    D3 = 3,
    Unsupported = 0xFF,
}

#[repr(C)]
#[derive(Clone, Copy, AsBytes, FromZeroes, FromBytes)]
pub struct PciPmCap {
    _cap_vndr: u8,
    _cap_next: u8,
    pm_cap: u16,
    pm_control_status: u16,
    padding: u16,
}

impl PciCapability for PciPmCap {
    fn bytes(&self) -> &[u8] {
        self.as_bytes()
    }

    fn id(&self) -> PciCapabilityID {
        PciCapabilityID::PowerManagement
    }

    fn writable_bits(&self) -> Vec<u32> {
        vec![0u32, 0x8103]
    }
}

impl PciPmCap {
    pub fn new() -> Self {
        PciPmCap {
            _cap_vndr: 0,
            _cap_next: 0,
            pm_cap: Self::default_cap(),
            pm_control_status: 0,
            padding: 0,
        }
    }
    pub fn default_cap() -> u16 {
        PM_CAP_VERSION
            | PM_CAP_PME_SUPPORT_D0
            | PM_CAP_PME_SUPPORT_D3_HOT
            | PM_CAP_PME_SUPPORT_D3_COLD
    }
}

pub struct PmConfig {
    power_control_status: u16,
}

impl PmConfig {
    pub fn new() -> Self {
        PmConfig {
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
            self.power_control_status &= !PM_POWER_STATE_MASK;
            self.power_control_status |= data[0] as u16 & PM_POWER_STATE_MASK;
        }

        let write_data = if offset == 0 && (data.len() == 2 || data.len() == 4) {
            Some((data[1] as u16) << 8)
        } else if offset == 1 && data.len() == 1 {
            Some((data[0] as u16) << 8)
        } else {
            None
        };

        if let Some(write_data) = write_data {
            if write_data & PM_PME_STATUS != 0 {
                // clear PME_STATUS
                self.power_control_status &= !PM_PME_STATUS;
            }

            if write_data & PM_PME_ENABLE != 0 {
                self.power_control_status |= PM_PME_ENABLE;
            } else {
                self.power_control_status &= !PM_PME_ENABLE;
            }
        }
    }

    /// If device is in D3 and PME is enabled, set PME status, then device could
    /// inject a pme interrupt into guest
    pub fn should_trigger_pme(&mut self) -> bool {
        if self.power_control_status & PM_POWER_STATE_MASK == PM_POWER_STATE_D3
            && self.power_control_status & PM_PME_ENABLE != 0
        {
            self.power_control_status |= PM_PME_STATUS;
            return true;
        }

        false
    }

    /// Get device power status
    pub fn get_power_status(&self) -> PciDevicePower {
        match self.power_control_status & PM_POWER_STATE_MASK {
            PM_POWER_STATE_D0 => PciDevicePower::D0,
            PM_POWER_STATE_D3 => PciDevicePower::D3,
            _ => PciDevicePower::Unsupported,
        }
    }
}

pub struct PmStatusChanged {
    pub from: PciDevicePower,
    pub to: PciDevicePower,
}

impl PciCapConfigWriteResult for PmStatusChanged {}

const PM_CONFIG_READ_MASK: [u32; 2] = [0, 0xffff];

impl PciCapConfig for PmConfig {
    fn read_mask(&self) -> &'static [u32] {
        &PM_CONFIG_READ_MASK
    }

    fn read_reg(&self, reg_idx: usize) -> u32 {
        let mut data = 0;
        if reg_idx == PM_CAP_CONTROL_STATE_OFFSET {
            self.read(&mut data);
        }
        data
    }

    fn write_reg(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> Option<Box<dyn PciCapConfigWriteResult>> {
        if reg_idx == PM_CAP_CONTROL_STATE_OFFSET {
            let from = self.get_power_status();
            self.write(offset, data);
            let to = self.get_power_status();
            if from != to {
                return Some(Box::new(PmStatusChanged { from, to }));
            }
        }
        None
    }
}

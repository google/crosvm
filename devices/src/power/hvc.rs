// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::bail;
use anyhow::Context;
use hypervisor::HypercallAbi;
use sync::Mutex;
use vm_control::DeviceId;
use vm_control::PlatformDeviceId;

use crate::BusAccessInfo;
use crate::BusDevice;
use crate::BusDeviceSync;
use crate::DevicePowerManager;
use crate::Suspendable;

/// Back-end for pKVM-enabled power management, intended for physical assigned devices.
pub struct HvcDevicePowerManager {
    manager: Mutex<DevicePowerManager>,
}

impl HvcDevicePowerManager {
    pub const HVC_FUNCTION_ID: u32 = 0xc600003c;

    /// Takes ownership of the abstract `DevicePowerManager`, as a `HvcDevicePowerManager`.
    pub fn new(manager: DevicePowerManager) -> Self {
        Self {
            manager: Mutex::new(manager),
        }
    }

    fn set_power_state(&self, domain_id: usize, power_level: usize) -> anyhow::Result<()> {
        match power_level {
            0 => self.manager.lock().power_off(domain_id)?,
            _ => self.manager.lock().power_on(domain_id)?,
        };
        Ok(())
    }
}

impl BusDevice for HvcDevicePowerManager {
    fn device_id(&self) -> DeviceId {
        PlatformDeviceId::HvcDevicePowerManager.into()
    }

    fn debug_label(&self) -> String {
        "HvcDevicePowerManager".to_owned()
    }

    fn handle_hypercall(&self, abi: &mut HypercallAbi) -> anyhow::Result<()> {
        match abi.hypercall_id() as u32 {
            Self::HVC_FUNCTION_ID => {
                let domain_id = *abi.get_argument(0).unwrap();
                let power_level = *abi.get_argument(1).unwrap();

                let ok_or_err = self
                    .set_power_state(domain_id, power_level)
                    .with_context(|| {
                        format!(
                            "HvcDevicePowerManager::handle_hypercall({domain_id}, {power_level})"
                        )
                    });

                let r0 = if ok_or_err.is_ok() {
                    0 // SMCCC_SUCCESS
                } else {
                    -3i64 as _ // SMCCC_INVALID_PARAMETER
                };

                abi.set_results(&[r0, 0, 0, 0]);

                ok_or_err
            }
            fid => bail!("HvcDevicePowerManager: Call {fid:#x} is not implemented"),
        }
    }

    fn read(&mut self, _info: BusAccessInfo, _data: &mut [u8]) {
        unimplemented!("HvcDevicePowerManager: read not supported");
    }

    fn write(&mut self, _info: BusAccessInfo, _data: &[u8]) {
        unimplemented!("HvcDevicePowerManager: write not supported");
    }
}

impl BusDeviceSync for HvcDevicePowerManager {
    fn read(&self, _info: BusAccessInfo, _data: &mut [u8]) {
        unimplemented!("HvcDevicePowerManager: read not supported");
    }

    fn write(&self, _info: BusAccessInfo, _data: &[u8]) {
        unimplemented!("HvcDevicePowerManager: write not supported");
    }
}

impl Suspendable for HvcDevicePowerManager {}

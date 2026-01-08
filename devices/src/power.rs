// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Abstract device power management.

pub(crate) mod hvc;

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::bail;
use anyhow::Context;
use base::warn;
use sync::Mutex;

use crate::BusDevice;

/// A device container for routing PM requests.
pub struct DevicePowerManager {
    domains: Mutex<BTreeMap<usize, PowerDomain>>,
}

impl Default for DevicePowerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DevicePowerManager {
    pub fn new() -> Self {
        Self {
            domains: Mutex::new(BTreeMap::new()),
        }
    }

    /// Add a `device` to a power domain; domain IDs are abstract values managed by the caller.
    ///
    /// Fails if the `device`'s initial state does not match other devices in the power domain.
    pub fn attach(
        &mut self,
        device: Arc<Mutex<dyn BusDevice>>,
        domain_id: usize,
    ) -> anyhow::Result<()> {
        let domains = self.domains.get_mut();
        let domain = domains
            .entry(domain_id)
            .or_insert_with(|| PowerDomain::new(device.lock().initial_power_state()));
        domain.attach(device)
    }

    /// Powers all devices contained in a domain on.
    pub fn power_on(&self, domain_id: usize) -> anyhow::Result<()> {
        self.domains
            .lock()
            .get_mut(&domain_id)
            .with_context(|| format!("Unknown PD {domain_id:#x}"))?
            .power_on()
    }

    /// Powers all devices contained in a domain off.
    pub fn power_off(&self, domain_id: usize) -> anyhow::Result<()> {
        self.domains
            .lock()
            .get_mut(&domain_id)
            .with_context(|| format!("Unknown PD {domain_id:#x}"))?
            .power_off()
    }
}

struct PowerDomain {
    devices: Vec<Arc<Mutex<dyn BusDevice>>>,
    is_on: bool,
}

impl PowerDomain {
    fn new(is_on: bool) -> Self {
        Self {
            devices: Vec::new(),
            is_on,
        }
    }

    fn attach(&mut self, device: Arc<Mutex<dyn BusDevice>>) -> anyhow::Result<()> {
        let is_on = device.lock().initial_power_state();
        if self.is_on != is_on {
            bail!(
                "Can't attach device to PD when states don't match: device is {}, PD is {}",
                on_off_str(is_on),
                on_off_str(self.is_on)
            )
        }
        self.devices.push(device);
        Ok(())
    }

    fn power_on(&mut self) -> anyhow::Result<()> {
        self.power_on_off(true)
    }

    fn power_off(&mut self) -> anyhow::Result<()> {
        self.power_on_off(false)
    }

    fn power_on_off(&mut self, on: bool) -> anyhow::Result<()> {
        if self.is_on == on {
            warn!("Ignoring attempt to update PD: already {}", on_off_str(on));
        } else {
            Self::switch_devices(&self.devices, on)?;
            self.is_on = on;
        }

        Ok(())
    }

    fn switch_devices(devices: &[Arc<Mutex<dyn BusDevice>>], on: bool) -> anyhow::Result<()> {
        for (i, device) in devices.iter().enumerate() {
            let result = if on {
                device.lock().power_on()
            } else {
                device.lock().power_off()
            };
            if let Err(e) = result {
                warn!(
                    "Failed to switch {} device '{}': {e}",
                    on_off_str(on),
                    device.lock().debug_label()
                );
                Self::switch_devices(&devices[..i], !on).expect("PM failure during clean-up");
                return Err(e);
            }
        }

        Ok(())
    }
}

fn on_off_str(on: bool) -> &'static str {
    if on {
        "ON"
    } else {
        "OFF"
    }
}

#[cfg(test)]
mod tests {
    use vm_control::DeviceId;
    use vm_control::PlatformDeviceId;

    use super::*;
    use crate::BusDevice;
    use crate::Suspendable;

    pub struct MockPoweredDevice {
        initial_power_state: bool,
        is_on: bool,
        fail_power_on: bool,
        fail_power_off: bool,
    }

    impl MockPoweredDevice {
        fn new(initial_power_state: bool) -> Self {
            Self {
                initial_power_state,
                is_on: initial_power_state,
                fail_power_on: false,
                fail_power_off: false,
            }
        }

        fn with_failure(
            initial_power_state: bool,
            fail_power_on: bool,
            fail_power_off: bool,
        ) -> Self {
            Self {
                initial_power_state,
                is_on: initial_power_state,
                fail_power_on,
                fail_power_off,
            }
        }

        fn is_on(&self) -> bool {
            self.is_on
        }
    }

    impl BusDevice for MockPoweredDevice {
        fn device_id(&self) -> DeviceId {
            PlatformDeviceId::Mock.into()
        }

        fn debug_label(&self) -> String {
            "mock device".to_owned()
        }

        fn supports_power_management(&self) -> anyhow::Result<bool> {
            Ok(true)
        }

        fn initial_power_state(&self) -> bool {
            self.initial_power_state
        }

        fn power_on(&mut self) -> anyhow::Result<()> {
            if self.fail_power_on {
                bail!("mock fail power on");
            }
            self.is_on = true;
            Ok(())
        }

        fn power_off(&mut self) -> anyhow::Result<()> {
            if self.fail_power_off {
                bail!("mock fail power off");
            }
            self.is_on = false;
            Ok(())
        }
    }

    impl Suspendable for MockPoweredDevice {}

    #[test]
    fn domain_attaches_devices() {
        let mock_starts_on1 = MockPoweredDevice::new(true);
        let mock_starts_on2 = MockPoweredDevice::new(true);
        let mock_starts_off1 = MockPoweredDevice::new(false);
        let mock_starts_off2 = MockPoweredDevice::new(false);

        let dev_starts_on1 = Arc::new(Mutex::new(mock_starts_on1));
        let dev_starts_on2 = Arc::new(Mutex::new(mock_starts_on2));
        let dev_starts_off1 = Arc::new(Mutex::new(mock_starts_off1));
        let dev_starts_off2 = Arc::new(Mutex::new(mock_starts_off2));

        let mut pd_starts_on = PowerDomain::new(true);
        let mut pd_starts_off = PowerDomain::new(false);

        // Attach wrong device to empty domain.
        assert!(pd_starts_on.attach(dev_starts_off1.clone()).is_err());
        assert!(pd_starts_off.attach(dev_starts_on1.clone()).is_err());

        // Attach right device to empty domain.
        assert!(pd_starts_on.attach(dev_starts_on1.clone()).is_ok());
        assert!(pd_starts_off.attach(dev_starts_off1.clone()).is_ok());

        // Attach wrong device to non-empty domain.
        assert!(pd_starts_on.attach(dev_starts_off2.clone()).is_err());
        assert!(pd_starts_off.attach(dev_starts_on2.clone()).is_err());

        // Attach right device to non-empty domain.
        assert!(pd_starts_on.attach(dev_starts_on2.clone()).is_ok());
        assert!(pd_starts_off.attach(dev_starts_off2.clone()).is_ok());
    }

    #[test]
    fn manager_powers_on() {
        let mock1 = Arc::new(Mutex::new(MockPoweredDevice::new(false)));
        let mock2 = Arc::new(Mutex::new(MockPoweredDevice::new(false)));

        let mut power_manager = DevicePowerManager::new();
        power_manager.attach(mock1.clone(), 0).unwrap();
        power_manager.attach(mock2.clone(), 0).unwrap();

        power_manager.power_on(0).unwrap();

        assert!(mock1.lock().is_on());
        assert!(mock2.lock().is_on());
    }

    #[test]
    fn manager_powers_off() {
        let mock1 = Arc::new(Mutex::new(MockPoweredDevice::new(true)));
        let mock2 = Arc::new(Mutex::new(MockPoweredDevice::new(true)));

        let mut power_manager = DevicePowerManager::new();
        power_manager.attach(mock1.clone(), 0).unwrap();
        power_manager.attach(mock2.clone(), 0).unwrap();

        power_manager.power_off(0).unwrap();

        assert!(!mock1.lock().is_on());
        assert!(!mock2.lock().is_on());
    }

    #[test]
    fn manager_cleans_up_failure() {
        // mock1 succeeds, mock2 fails. mock1 should be rolled back.
        let mock1 = Arc::new(Mutex::new(MockPoweredDevice::new(false)));
        let mock2 = Arc::new(Mutex::new(MockPoweredDevice::with_failure(
            false, true, false,
        )));

        let mut power_manager = DevicePowerManager::new();
        power_manager.attach(mock1.clone(), 0).unwrap();
        power_manager.attach(mock2.clone(), 0).unwrap();

        // Expect failure when powering on
        assert!(power_manager.power_on(0).is_err());

        // mock2 failed to power on, so it should be off.
        assert!(!mock2.lock().is_on());
        // mock1 should have been powered on, then rolled back to off.
        assert!(!mock1.lock().is_on());
    }

    #[test]
    fn manager_isolates_domains() {
        let mock0_1 = Arc::new(Mutex::new(MockPoweredDevice::new(false)));
        let mock0_2 = Arc::new(Mutex::new(MockPoweredDevice::new(false)));
        let mock1_1 = Arc::new(Mutex::new(MockPoweredDevice::new(false)));

        let mut power_manager = DevicePowerManager::new();
        power_manager.attach(mock0_1.clone(), 0).unwrap();
        power_manager.attach(mock0_2.clone(), 0).unwrap();
        power_manager.attach(mock1_1.clone(), 1).unwrap();

        // Power on domain 0
        power_manager.power_on(0).unwrap();
        assert!(mock0_1.lock().is_on());
        assert!(mock0_2.lock().is_on());
        assert!(!mock1_1.lock().is_on());

        // Power on domain 1
        power_manager.power_on(1).unwrap();
        assert!(mock0_1.lock().is_on());
        assert!(mock0_2.lock().is_on());
        assert!(mock1_1.lock().is_on());

        // Power off domain 0
        power_manager.power_off(0).unwrap();
        assert!(!mock0_1.lock().is_on());
        assert!(!mock0_2.lock().is_on());
        assert!(mock1_1.lock().is_on());
    }

    #[test]
    fn manager_rejects_unknown_domain() {
        let power_manager = DevicePowerManager::new();
        assert!(power_manager.power_on(42).is_err());
        assert!(power_manager.power_off(42).is_err());
    }
}

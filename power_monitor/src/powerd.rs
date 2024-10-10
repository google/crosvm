// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Bindings for the ChromeOS `powerd` D-Bus API.
//!
//! <https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/power_manager/README.md>

use crate::protos::power_supply_properties::power_supply_properties;
use crate::protos::power_supply_properties::PowerSupplyProperties;
use crate::BatteryData;
use crate::BatteryStatus;
use crate::PowerData;

// Interface name from power_manager/dbus_bindings/org.chromium.PowerManager.xml.
pub const POWER_INTERFACE_NAME: &str = "org.chromium.PowerManager";
// Object path from power_manager/dbus_bindings/org.chromium.PowerManager.xml.
pub const POWER_OBJECT_PATH: &str = "/org/chromium/PowerManager";

pub mod client;
pub mod monitor;

impl From<PowerSupplyProperties> for PowerData {
    fn from(props: PowerSupplyProperties) -> Self {
        let ac_online = if props.has_external_power() {
            props.external_power() != power_supply_properties::ExternalPower::DISCONNECTED
        } else {
            false
        };

        let battery = if props.has_battery_state()
            && props.battery_state() != power_supply_properties::BatteryState::NOT_PRESENT
        {
            let status = match props.battery_state() {
                power_supply_properties::BatteryState::FULL => BatteryStatus::NotCharging,
                power_supply_properties::BatteryState::CHARGING => BatteryStatus::Charging,
                power_supply_properties::BatteryState::DISCHARGING => BatteryStatus::Discharging,
                _ => BatteryStatus::Unknown,
            };

            let percent = std::cmp::min(100, props.battery_percent().round() as u32);
            // Convert from volts to microvolts.
            let voltage = (props.battery_voltage() * 1_000_000f64).round() as u32;
            // Convert from amps to microamps.
            let current = (props.battery_current() * 1_000_000f64).round() as u32;
            // Convert from ampere-hours to micro ampere-hours.
            let charge_counter = (props.battery_charge() * 1_000_000f64).round() as u32;
            let charge_full = (props.battery_charge_full() * 1_000_000f64).round() as u32;

            Some(BatteryData {
                status,
                percent,
                voltage,
                current,
                charge_counter,
                charge_full,
            })
        } else {
            None
        };

        Self { ac_online, battery }
    }
}

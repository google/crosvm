// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use base::error;
use base::Descriptor;
use base::WaitContext;
use power_monitor::BatteryStatus;
use power_monitor::CreatePowerMonitorFn;
use power_monitor::PowerMonitor;
use sync::Mutex;

use crate::bat::GoldfishBatteryState;
use crate::bat::Token;
use crate::IrqLevelEvent;

const BATTERY_STATUS_VAL_CHARGING: u32 = 1;
const BATTERY_STATUS_VAL_DISCHARGING: u32 = 2;
const BATTERY_STATUS_VAL_NOT_CHARGING: u32 = 3;

pub(crate) fn create_power_monitor(
    monitor_fn: Option<Box<dyn CreatePowerMonitorFn>>,
    wait_ctx: &WaitContext<Token>,
) -> Option<Box<dyn PowerMonitor>> {
    match monitor_fn {
        Some(f) => match f() {
            Ok(p) => match wait_ctx.add(&Descriptor(p.poll_fd()), Token::Monitor) {
                Ok(()) => Some(p),
                Err(e) => {
                    error!("failed to add power monitor to poll context: {}", e);
                    None
                }
            },
            Err(e) => {
                error!("failed to create power monitor: {}", e);
                None
            }
        },
        None => None,
    }
}

pub(crate) fn handle_token_monitor(
    power_monitor: &mut Box<dyn PowerMonitor>,
    state: Arc<Mutex<GoldfishBatteryState>>,
    irq_evt: &IrqLevelEvent,
) {
    // Safe because power_monitor must be populated if Token::Monitor is triggered.
    let data = match power_monitor.read_message() {
        Ok(Some(d)) => d,
        Ok(None) => return,
        Err(e) => {
            error!("failed to read new power data: {}", e);
            return;
        }
    };

    let mut bat_state = state.lock();

    // Each set_* function called below returns true when interrupt bits
    // (*_STATUS_CHANGED) changed. If `inject_irq` is true after we attempt to
    // update each field, inject an interrupt.
    let mut inject_irq = bat_state.set_ac_online(data.ac_online.into());

    match data.battery {
        Some(battery_data) => {
            inject_irq |= bat_state.set_capacity(battery_data.percent);
            let battery_status = match battery_data.status {
                BatteryStatus::Unknown => crate::bat::BATTERY_STATUS_VAL_UNKNOWN,
                BatteryStatus::Charging => BATTERY_STATUS_VAL_CHARGING,
                BatteryStatus::Discharging => BATTERY_STATUS_VAL_DISCHARGING,
                BatteryStatus::NotCharging => BATTERY_STATUS_VAL_NOT_CHARGING,
            };
            inject_irq |= bat_state.set_status(battery_status);
            inject_irq |= bat_state.set_voltage(battery_data.voltage);
            inject_irq |= bat_state.set_current(battery_data.current);
            inject_irq |= bat_state.set_charge_counter(battery_data.charge_counter);
            inject_irq |= bat_state.set_charge_full(battery_data.charge_full);
        }
        None => {
            inject_irq |= bat_state.set_present(0);
        }
    }

    if inject_irq {
        let _ = irq_evt.trigger();
    }
}

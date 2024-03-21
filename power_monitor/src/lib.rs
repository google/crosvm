// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Power monitoring abstraction layer.

use std::error::Error;

use base::ReadNotifier;

pub trait PowerMonitor: ReadNotifier {
    fn read_message(&mut self) -> std::result::Result<Option<PowerData>, Box<dyn Error>>;
}

pub struct PowerData {
    pub ac_online: bool,
    pub battery: Option<BatteryData>,
}

#[derive(Clone, Copy)]
pub struct BatteryData {
    pub status: BatteryStatus,
    pub percent: u32,
    /// Battery voltage in microvolts.
    pub voltage: u32,
    /// Battery current in microamps.
    pub current: u32,
    /// Battery charge counter in microampere hours.
    pub charge_counter: u32,
    /// Battery full charge counter in microampere hours.
    pub charge_full: u32,
}

#[derive(Clone, Copy)]
pub enum BatteryStatus {
    Unknown,
    Charging,
    Discharging,
    NotCharging,
}

pub trait CreatePowerMonitorFn:
    Send + Fn() -> std::result::Result<Box<dyn PowerMonitor>, Box<dyn Error>>
{
}

impl<T> CreatePowerMonitorFn for T where
    T: Send + Fn() -> std::result::Result<Box<dyn PowerMonitor>, Box<dyn Error>>
{
}

#[cfg(feature = "powerd")]
pub mod powerd;

mod protos {
    include!(concat!(env!("OUT_DIR"), "/protos/generated.rs"));
}

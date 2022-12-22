// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Bindings for the ChromeOS `powerd` D-Bus API.
//!
//! <https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/power_manager/README.md>

use std::error::Error;

use base::RawDescriptor;

pub trait PowerMonitor {
    fn poll_fd(&self) -> RawDescriptor;
    fn read_message(&mut self) -> std::result::Result<Option<PowerData>, Box<dyn Error>>;
}

pub struct PowerData {
    pub ac_online: bool,
    pub battery: Option<BatteryData>,
}

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

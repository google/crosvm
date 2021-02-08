// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::error::Error;
use std::os::unix::io::RawFd;

pub trait PowerMonitor {
    fn poll_fd(&self) -> RawFd;
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

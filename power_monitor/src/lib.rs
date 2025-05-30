// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Power monitoring abstraction layer.

use std::error::Error;
use std::time::SystemTime;

use base::ReadNotifier;

pub trait PowerMonitor: ReadNotifier {
    fn read_message(&mut self) -> std::result::Result<Option<PowerData>, Box<dyn Error>>;
}

pub trait PowerClient: Send {
    fn get_power_data(&mut self) -> std::result::Result<PowerData, Box<dyn Error>>;

    /// Returns timestamp that this client sends a DBus request.
    fn last_request_timestamp(&self) -> Option<SystemTime>;
}

#[derive(Debug)]
pub struct PowerData {
    pub ac_online: bool,
    pub battery: Option<BatteryData>,
}

#[derive(Clone, Copy, Debug)]
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

#[derive(Clone, Copy, Debug)]
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

pub trait CreatePowerClientFn:
    Send + Fn() -> std::result::Result<Box<dyn PowerClient>, Box<dyn Error>>
{
}

impl<T> CreatePowerClientFn for T where
    T: Send + Fn() -> std::result::Result<Box<dyn PowerClient>, Box<dyn Error>>
{
}

#[cfg(feature = "powerd")]
pub mod powerd;

#[cfg(feature = "powerd")]
mod protos {
    include!(concat!(env!("OUT_DIR"), "/protos/generated.rs"));
}

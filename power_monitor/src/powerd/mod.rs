// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::{BatteryData, BatteryStatus, PowerData, PowerMonitor};

mod proto;
use proto::system_api::power_supply_properties::{
    PowerSupplyProperties, PowerSupplyProperties_BatteryState, PowerSupplyProperties_ExternalPower,
};

use dbus::{BusType, Connection, ConnectionItem, WatchEvent};

use protobuf::error::ProtobufError;
use protobuf::Message;

use std::error::Error;
use std::fmt;
use std::os::unix::io::RawFd;

// Interface name from power_manager/dbus_bindings/org.chromium.PowerManager.xml.
const POWER_INTERFACE_NAME: &str = "org.chromium.PowerManager";

// Signal name from power_manager/dbus_constants.h.
const POLL_SIGNAL_NAME: &str = "PowerSupplyPoll";

impl From<PowerSupplyProperties> for PowerData {
    fn from(props: PowerSupplyProperties) -> Self {
        let ac_online = if props.has_external_power() {
            props.get_external_power() != PowerSupplyProperties_ExternalPower::DISCONNECTED
        } else {
            false
        };

        let battery = if props.has_battery_state()
            && props.get_battery_state() != PowerSupplyProperties_BatteryState::NOT_PRESENT
        {
            let status = match props.get_battery_state() {
                PowerSupplyProperties_BatteryState::FULL => BatteryStatus::NotCharging,
                PowerSupplyProperties_BatteryState::CHARGING => BatteryStatus::Charging,
                PowerSupplyProperties_BatteryState::DISCHARGING => BatteryStatus::Discharging,
                _ => BatteryStatus::Unknown,
            };

            let percent = std::cmp::min(100, props.get_battery_percent().round() as u32);
            // Convert from volts to microvolts.
            let voltage = (props.get_battery_voltage() * 1_000_000f64).round() as u32;
            // Convert from amps to microamps.
            let current = (props.get_battery_current() * 1_000_000f64).round() as u32;
            // Convert from ampere-hours to micro ampere-hours.
            let charge_counter = (props.get_battery_charge() * 1_000_000f64).round() as u32;
            let charge_full = (props.get_battery_charge_full() * 1_000_000f64).round() as u32;

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

#[derive(Debug)]
pub enum DBusMonitorError {
    DBusConnect(dbus::Error),
    DBusAddMatch(dbus::Error),
    NoDBusFd,
    MultipleDBusFd,
    DBusRead(dbus::arg::TypeMismatchError),
    ConvertProtobuf(ProtobufError),
}

impl Error for DBusMonitorError {}

impl fmt::Display for DBusMonitorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::DBusMonitorError::*;
        match self {
            DBusConnect(e) => write!(f, "failed to connect to D-Bus: {}", e),
            DBusAddMatch(e) => write!(f, "failed to add D-Bus match rule: {}", e),
            NoDBusFd => write!(f, "no D-Bus fd"),
            MultipleDBusFd => write!(f, "multiple D-Bus fds"),
            DBusRead(e) => write!(f, "failed to read D-Bus message: {}", e),
            ConvertProtobuf(e) => write!(f, "failed to convert protobuf message: {}", e),
        }
    }
}

pub struct DBusMonitor {
    connection: Connection,
    connection_fd: RawFd,
}

impl DBusMonitor {
    /// Connects and configures a new D-Bus connection to listen for powerd's PowerSupplyPoll
    /// signal.
    pub fn connect() -> std::result::Result<Box<dyn PowerMonitor>, Box<dyn Error>> {
        let connection =
            Connection::get_private(BusType::System).map_err(DBusMonitorError::DBusConnect)?;
        connection
            .add_match(&format!(
                "interface='{}',member='{}'",
                POWER_INTERFACE_NAME, POLL_SIGNAL_NAME
            ))
            .map_err(DBusMonitorError::DBusAddMatch)?;
        // Get the D-Bus connection's fd for async I/O. This should always return a single fd.
        let fds: Vec<RawFd> = connection
            .watch_fds()
            .into_iter()
            .filter(|w| w.readable())
            .map(|w| w.fd())
            .collect();
        if fds.is_empty() {
            return Err(DBusMonitorError::NoDBusFd.into());
        }
        if fds.len() > 1 {
            return Err(DBusMonitorError::MultipleDBusFd.into());
        }
        Ok(Box::new(Self {
            connection,
            connection_fd: fds[0],
        }))
    }
}

impl PowerMonitor for DBusMonitor {
    /// Returns the newest pending `PowerData` message, if any.
    /// Callers should poll `PowerMonitor` to determine when messages are available.
    fn read_message(&mut self) -> std::result::Result<Option<PowerData>, Box<dyn Error>> {
        // Select the newest available power message before converting to protobuf.
        let newest_message: Option<dbus::Message> = self
            .connection
            .watch_handle(
                self.connection_fd,
                WatchEvent::Readable as std::os::raw::c_uint,
            )
            .fold(None, |last, item| match item {
                ConnectionItem::Signal(message) => {
                    // Ignore non-matching signals: although match rules are configured, some system
                    // signals can still get through, eg. NameAcquired.
                    let interface = match message.interface() {
                        Some(i) => i,
                        None => {
                            return last;
                        }
                    };

                    let interface_name = match interface.as_cstr().to_str() {
                        Ok(s) => s,
                        Err(_) => {
                            return last;
                        }
                    };

                    if interface_name != POWER_INTERFACE_NAME {
                        return last;
                    }

                    let member = match message.member() {
                        Some(m) => m,
                        None => {
                            return last;
                        }
                    };

                    let member_name = match member.as_cstr().to_str() {
                        Ok(s) => s,
                        Err(_) => {
                            return last;
                        }
                    };

                    if member_name != POLL_SIGNAL_NAME {
                        return last;
                    }

                    Some(message)
                }
                _ => last,
            });

        match newest_message {
            Some(message) => {
                let data_bytes: Vec<u8> = message.read1().map_err(DBusMonitorError::DBusRead)?;
                let mut props = PowerSupplyProperties::new();
                props
                    .merge_from_bytes(&data_bytes)
                    .map_err(DBusMonitorError::ConvertProtobuf)?;
                Ok(Some(props.into()))
            }
            None => Ok(None),
        }
    }

    fn poll_fd(&self) -> RawFd {
        self.connection_fd
    }
}

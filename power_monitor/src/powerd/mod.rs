// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::BatteryData;
use crate::BatteryStatus;
use crate::PowerData;
use crate::PowerMonitor;

use std::error::Error;
use std::os::unix::io::RawFd;

use dbus::ffidisp::BusType;
use dbus::ffidisp::Connection;
use dbus::ffidisp::ConnectionItem;
use dbus::ffidisp::WatchEvent;
use protobuf::error::ProtobufError;
use protobuf::Message;
use remain::sorted;
use thiserror::Error;

use crate::protos::power_supply_properties::PowerSupplyProperties;
use crate::protos::power_supply_properties::PowerSupplyProperties_BatteryState;
use crate::protos::power_supply_properties::PowerSupplyProperties_ExternalPower;

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

#[sorted]
#[derive(Error, Debug)]
pub enum DBusMonitorError {
    #[error("failed to convert protobuf message: {0}")]
    ConvertProtobuf(ProtobufError),
    #[error("failed to add D-Bus match rule: {0}")]
    DBusAddMatch(dbus::Error),
    #[error("failed to connect to D-Bus: {0}")]
    DBusConnect(dbus::Error),
    #[error("failed to read D-Bus message: {0}")]
    DBusRead(dbus::arg::TypeMismatchError),
    #[error("multiple D-Bus fds")]
    MultipleDBusFd,
    #[error("no D-Bus fd")]
    NoDBusFd,
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

                    if &*interface != POWER_INTERFACE_NAME {
                        return last;
                    }

                    let member = match message.member() {
                        Some(m) => m,
                        None => {
                            return last;
                        }
                    };

                    if &*member != POLL_SIGNAL_NAME {
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

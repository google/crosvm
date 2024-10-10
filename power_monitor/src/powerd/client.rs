// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Dbus client for sending request to powerd to get power properties.

use std::error::Error;
use std::time::Duration;

use dbus::blocking::Connection;
use protobuf::Message;
use remain::sorted;
use system_api::client::OrgChromiumPowerManager;
use thiserror::Error;

use crate::powerd::POWER_INTERFACE_NAME;
use crate::powerd::POWER_OBJECT_PATH;
use crate::protos::power_supply_properties::PowerSupplyProperties;
use crate::PowerClient;
use crate::PowerData;

// 25 seconds is the default timeout for dbus-send.
const DEFAULT_DBUS_TIMEOUT: Duration = Duration::from_secs(25);

pub struct DBusClient {
    connection: Connection,
}

#[sorted]
#[derive(Error, Debug)]
pub enum DBusClientError {
    #[error("failed to convert protobuf message: {0}")]
    ConvertProtobuf(protobuf::Error),
    #[error("failed to connect to D-Bus: {0}")]
    DBusConnect(dbus::Error),
    #[error("failed to read D-Bus message: {0}")]
    DBusRead(dbus::Error),
}

impl DBusClient {
    /// Creates a new blocking dbus connection to system bus.
    pub fn connect() -> std::result::Result<Box<dyn PowerClient>, Box<dyn Error>> {
        let channel = dbus::channel::Channel::get_private(dbus::channel::BusType::System)
            .map_err(DBusClientError::DBusConnect)?;

        let connection = dbus::blocking::Connection::from(channel);

        Ok(Box::new(Self { connection }))
    }
}

// Send GetPowerSupplyProperties dbus request to power_manager(powerd), blocks until it gets
// response, and converts the response into PowerData.
impl PowerClient for DBusClient {
    fn get_power_data(&mut self) -> std::result::Result<PowerData, Box<dyn Error>> {
        let proxy = self.connection.with_proxy(
            POWER_INTERFACE_NAME,
            POWER_OBJECT_PATH,
            DEFAULT_DBUS_TIMEOUT,
        );
        let data_bytes = proxy
            .get_power_supply_properties()
            .map_err(DBusClientError::DBusRead)?;
        let mut props = PowerSupplyProperties::new();
        props
            .merge_from_bytes(&data_bytes)
            .map_err(DBusClientError::ConvertProtobuf)?;
        let data: PowerData = props.into();
        Ok(data)
    }
}

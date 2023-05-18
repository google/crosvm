// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! vTPM Proxy backend using the vtpmd on ChromeOS to virtualize TPM commands.

use std::time::Duration;

use base::error;
use protobuf::Message;
use remain::sorted;
use system_api::client::OrgChromiumVtpm;
use system_api::vtpm_interface::SendCommandRequest;
use system_api::vtpm_interface::SendCommandResponse;
use thiserror::Error;

use super::virtio::TpmBackend;

// 5 minutes is the default timeout for tpm commands.
const VTPM_DBUS_TIMEOUT: Duration = Duration::from_secs(300);

// The response of TPM_RC_INSUFFICIENT
const TPM_RC_INSUFFICIENT_RESPONSE: &[u8] = &[
    0x80, 0x01, // TPM_ST_NO_SESSIONS
    0x00, 0x00, 0x00, 0x0A, // Header Size = 10
    0x00, 0x00, 0x00, 0x9A, // TPM_RC_INSUFFICIENT
];

// The response of TPM_RC_FAILURE
const TPM_RC_FAILURE_RESPONSE: &[u8] = &[
    0x80, 0x01, // TPM_ST_NO_SESSIONS
    0x00, 0x00, 0x00, 0x0A, // Header Size = 10
    0x00, 0x00, 0x01, 0x01, // TPM_RC_FAILURE
];

/// A proxy object that connects to the vtpmd on ChromeOS.
pub struct VtpmProxy {
    dbus_connection: Option<dbus::blocking::Connection>,
    buf: Vec<u8>,
}

impl VtpmProxy {
    /// Returns a proxy that can be connected to the vtpmd.
    pub fn new() -> Self {
        VtpmProxy {
            dbus_connection: None,
            buf: Vec::new(),
        }
    }

    fn get_or_create_dbus_connection(
        &mut self,
    ) -> anyhow::Result<&dbus::blocking::Connection, dbus::Error> {
        return match self.dbus_connection {
            Some(ref dbus_connection) => Ok(dbus_connection),
            None => {
                let dbus_connection = dbus::blocking::Connection::new_system()?;
                self.dbus_connection = Some(dbus_connection);
                return self.get_or_create_dbus_connection();
            }
        };
    }

    fn try_execute_command(&mut self, command: &[u8]) -> anyhow::Result<(), Error> {
        let dbus_connection = self
            .get_or_create_dbus_connection()
            .map_err(Error::DBusError)?;

        let proxy = dbus_connection.with_proxy(
            "org.chromium.Vtpm",
            "/org/chromium/Vtpm",
            VTPM_DBUS_TIMEOUT,
        );

        let mut proto = SendCommandRequest::new();
        proto.set_command(command.to_vec());

        let bytes = proto.write_to_bytes().map_err(Error::ProtobufError)?;

        let resp_bytes = proxy.send_command(bytes).map_err(Error::DBusError)?;

        let response =
            SendCommandResponse::parse_from_bytes(&resp_bytes).map_err(Error::ProtobufError)?;

        self.buf = response.response().to_vec();

        Ok(())
    }
}

impl Default for VtpmProxy {
    fn default() -> Self {
        Self::new()
    }
}

impl TpmBackend for VtpmProxy {
    fn execute_command<'a>(&'a mut self, command: &[u8]) -> &'a [u8] {
        match self.try_execute_command(command) {
            Ok(()) => &self.buf,
            Err(e) => {
                error!("{:#}", e);
                match e {
                    Error::ProtobufError(_) => TPM_RC_INSUFFICIENT_RESPONSE,
                    Error::DBusError(_) => TPM_RC_FAILURE_RESPONSE,
                }
            }
        }
    }
}

#[sorted]
#[derive(Error, Debug)]
enum Error {
    #[error("D-Bus failure: {0:#}")]
    DBusError(dbus::Error),
    #[error("protocol buffers failure: {0:#}")]
    ProtobufError(protobuf::Error),
}

// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt::{self, Display};
use std::fs::OpenOptions;
use std::io::{self, stdin, stdout};
use std::path::PathBuf;

use base::{error, open_file, syslog, AsRawDescriptor, Event, FileSync, RawDescriptor};
use hypervisor::ProtectionType;
use remain::sorted;
use serde::{Deserialize, Serialize};
use thiserror::Error as ThisError;

pub use crate::sys::serial_device::SerialDevice;
use crate::sys::serial_device::*;

#[sorted]
#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Unable to clone an Event: {0}")]
    CloneEvent(base::Error),
    #[error("Unable to open/create file: {0}")]
    FileError(std::io::Error),
    #[error("Serial device path is invalid")]
    InvalidPath,
    #[error("Invalid serial hardware: {0}")]
    InvalidSerialHardware(String),
    #[error("Invalid serial type: {0}")]
    InvalidSerialType(String),
    #[error("Serial device type file requires a path")]
    PathRequired,
    #[error("Failed to create unbound socket")]
    SocketCreateFailed,
    #[error("Unable to open system type serial: {0}")]
    SystemTypeError(std::io::Error),
    #[error("Serial device type {0} not implemented")]
    Unimplemented(SerialType),
}

/// Enum for possible type of serial devices
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SerialType {
    File,
    Stdout,
    Sink,
    Syslog,
    #[cfg_attr(unix, serde(rename = "unix"))]
    #[cfg_attr(windows, serde(rename = "namedpipe"))]
    SystemSerialType,
}

impl Default for SerialType {
    fn default() -> Self {
        Self::Sink
    }
}

impl Display for SerialType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match &self {
            SerialType::File => "File".to_string(),
            SerialType::Stdout => "Stdout".to_string(),
            SerialType::Sink => "Sink".to_string(),
            SerialType::Syslog => "Syslog".to_string(),
            SerialType::SystemSerialType => SYSTEM_SERIAL_TYPE_NAME.to_string(),
        };

        write!(f, "{}", s)
    }
}

/// Serial device hardware types
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SerialHardware {
    Serial,        // Standard PC-style (8250/16550 compatible) UART
    VirtioConsole, // virtio-console device
}

impl Default for SerialHardware {
    fn default() -> Self {
        Self::Serial
    }
}

impl Display for SerialHardware {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match &self {
            SerialHardware::Serial => "serial".to_string(),
            SerialHardware::VirtioConsole => "virtio-console".to_string(),
        };

        write!(f, "{}", s)
    }
}

fn serial_parameters_default_num() -> u8 {
    1
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SerialParameters {
    #[serde(rename = "type")]
    pub type_: SerialType,
    pub hardware: SerialHardware,
    pub path: Option<PathBuf>,
    pub input: Option<PathBuf>,
    #[serde(default = "serial_parameters_default_num")]
    pub num: u8,
    pub console: bool,
    pub earlycon: bool,
    pub stdin: bool,
    pub out_timestamp: bool,
}

impl SerialParameters {
    /// Helper function to create a serial device from the defined parameters.
    ///
    /// # Arguments
    /// * `evt` - event used for interrupt events
    /// * `keep_rds` - Vector of FDs required by this device if it were sandboxed in a child
    ///                process. `evt` will always be added to this vector by this function.
    pub fn create_serial_device<T: SerialDevice>(
        &self,
        protected_vm: ProtectionType,
        evt: &Event,
        keep_rds: &mut Vec<RawDescriptor>,
    ) -> std::result::Result<T, Error> {
        let evt = evt.try_clone().map_err(Error::CloneEvent)?;
        keep_rds.push(evt.as_raw_descriptor());
        let input: Option<Box<dyn io::Read + Send>> = if let Some(input_path) = &self.input {
            let input_path = input_path.as_path();

            let input_file = open_file(input_path, OpenOptions::new().read(true))
                .map_err(|e| Error::FileError(e.into()))?;

            keep_rds.push(input_file.as_raw_descriptor());
            Some(Box::new(input_file))
        } else if self.stdin {
            keep_rds.push(stdin().as_raw_descriptor());
            Some(Box::new(ConsoleInput))
        } else {
            None
        };
        let (output, sync): (
            Option<Box<dyn io::Write + Send>>,
            Option<Box<dyn FileSync + Send>>,
        ) = match self.type_ {
            SerialType::Stdout => {
                keep_rds.push(stdout().as_raw_descriptor());
                (Some(Box::new(stdout())), None)
            }
            SerialType::Sink => (None, None),
            SerialType::Syslog => {
                syslog::push_descriptors(keep_rds);
                (
                    Some(Box::new(syslog::Syslogger::new(
                        syslog::Priority::Info,
                        syslog::Facility::Daemon,
                    ))),
                    None,
                )
            }
            SerialType::File => match &self.path {
                Some(path) => {
                    let file = open_file(path, OpenOptions::new().append(true).create(true))
                        .map_err(|e| Error::FileError(e.into()))?;
                    let sync = file.try_clone().map_err(Error::FileError)?;

                    keep_rds.push(file.as_raw_descriptor());
                    keep_rds.push(sync.as_raw_descriptor());

                    (Some(Box::new(file)), Some(Box::new(sync)))
                }
                None => return Err(Error::PathRequired),
            },
            SerialType::SystemSerialType => {
                return create_system_type_serial_device(self, protected_vm, evt, input, keep_rds);
            }
        };
        Ok(T::new(
            protected_vm,
            evt,
            input,
            output,
            sync,
            self.out_timestamp,
            keep_rds.to_vec(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_keyvalue::*;

    fn from_serial_arg(options: &str) -> Result<SerialParameters, ParseError> {
        from_key_values(options)
    }

    #[test]
    fn params_from_key_values() {
        // Defaults
        let params = from_serial_arg("").unwrap();
        assert_eq!(
            params,
            SerialParameters {
                type_: SerialType::Sink,
                hardware: SerialHardware::Serial,
                path: None,
                input: None,
                num: 1,
                console: false,
                earlycon: false,
                stdin: false,
                out_timestamp: false,
            }
        );

        // type parameter
        let params = from_serial_arg("type=file").unwrap();
        assert_eq!(params.type_, SerialType::File);
        let params = from_serial_arg("type=stdout").unwrap();
        assert_eq!(params.type_, SerialType::Stdout);
        let params = from_serial_arg("type=sink").unwrap();
        assert_eq!(params.type_, SerialType::Sink);
        let params = from_serial_arg("type=syslog").unwrap();
        assert_eq!(params.type_, SerialType::Syslog);
        #[cfg(unix)]
        let opt = "type=unix";
        #[cfg(window)]
        let opt = "type=namedpipe";
        let params = from_serial_arg(opt).unwrap();
        assert_eq!(params.type_, SerialType::SystemSerialType);
        let params = from_serial_arg("type=foobar");
        assert!(params.is_err());

        // hardware parameter
        let params = from_serial_arg("hardware=serial").unwrap();
        assert_eq!(params.hardware, SerialHardware::Serial);
        let params = from_serial_arg("hardware=virtio-console").unwrap();
        assert_eq!(params.hardware, SerialHardware::VirtioConsole);
        let params = from_serial_arg("hardware=foobar");
        assert!(params.is_err());

        // path parameter
        let params = from_serial_arg("path=/test/path").unwrap();
        assert_eq!(params.path, Some("/test/path".into()));
        let params = from_serial_arg("path");
        assert!(params.is_err());

        // input parameter
        let params = from_serial_arg("input=/path/to/input").unwrap();
        assert_eq!(params.input, Some("/path/to/input".into()));
        let params = from_serial_arg("input");
        assert!(params.is_err());

        // console parameter
        let params = from_serial_arg("console").unwrap();
        assert!(params.console);
        let params = from_serial_arg("console=true").unwrap();
        assert!(params.console);
        let params = from_serial_arg("console=false").unwrap();
        assert!(!params.console);
        let params = from_serial_arg("console=foobar");
        assert!(params.is_err());

        // earlycon parameter
        let params = from_serial_arg("earlycon").unwrap();
        assert!(params.earlycon);
        let params = from_serial_arg("earlycon=true").unwrap();
        assert!(params.earlycon);
        let params = from_serial_arg("earlycon=false").unwrap();
        assert!(!params.earlycon);
        let params = from_serial_arg("earlycon=foobar");
        assert!(params.is_err());

        // stdin parameter
        let params = from_serial_arg("stdin").unwrap();
        assert!(params.stdin);
        let params = from_serial_arg("stdin=true").unwrap();
        assert!(params.stdin);
        let params = from_serial_arg("stdin=false").unwrap();
        assert!(!params.stdin);
        let params = from_serial_arg("stdin=foobar");
        assert!(params.is_err());

        // all together
        let params = from_serial_arg("type=stdout,path=/some/path,hardware=virtio-console,num=5,earlycon,console,stdin,input=/some/input,out_timestamp").unwrap();
        assert_eq!(
            params,
            SerialParameters {
                type_: SerialType::Stdout,
                hardware: SerialHardware::VirtioConsole,
                path: Some("/some/path".into()),
                input: Some("/some/input".into()),
                num: 5,
                console: true,
                earlycon: true,
                stdin: true,
                out_timestamp: true,
            }
        );

        // invalid field
        let params = from_serial_arg("type=stdout,foo=bar");
        assert!(params.is_err());
    }
}

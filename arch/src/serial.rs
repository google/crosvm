// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::fmt::{self, Display};
use std::fs::File;
use std::io::{self, stdin, stdout};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use devices::{Bus, ProxyDevice, Serial, SerialDevice};
use io_jail::Minijail;
use sync::Mutex;
use sys_util::{read_raw_stdin, syslog, EventFd};

use crate::DeviceRegistrationError;

#[derive(Debug)]
pub enum Error {
    CloneEventFd(sys_util::Error),
    FileError(std::io::Error),
    InvalidSerialType(String),
    PathRequired,
    Unimplemented(SerialType),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            CloneEventFd(e) => write!(f, "unable to clone an EventFd: {}", e),
            FileError(e) => write!(f, "unable to open/create file: {}", e),
            InvalidSerialType(e) => write!(f, "invalid serial type: {}", e),
            PathRequired => write!(f, "serial device type file requires a path"),
            Unimplemented(e) => write!(f, "serial device type {} not implemented", e.to_string()),
        }
    }
}

/// Enum for possible type of serial devices
#[derive(Debug)]
pub enum SerialType {
    File,
    Stdout,
    Sink,
    Syslog,
    UnixSocket, // NOT IMPLEMENTED
}

impl Display for SerialType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match &self {
            SerialType::File => "File".to_string(),
            SerialType::Stdout => "Stdout".to_string(),
            SerialType::Sink => "Sink".to_string(),
            SerialType::Syslog => "Syslog".to_string(),
            SerialType::UnixSocket => "UnixSocket".to_string(),
        };

        write!(f, "{}", s)
    }
}

impl FromStr for SerialType {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "file" | "File" => Ok(SerialType::File),
            "stdout" | "Stdout" => Ok(SerialType::Stdout),
            "sink" | "Sink" => Ok(SerialType::Sink),
            "syslog" | "Syslog" => Ok(SerialType::Syslog),
            "unix" | "UnixSocket" => Ok(SerialType::UnixSocket),
            _ => Err(Error::InvalidSerialType(s.to_string())),
        }
    }
}

/// Holds the parameters for a serial device
#[derive(Debug)]
pub struct SerialParameters {
    pub type_: SerialType,
    pub path: Option<PathBuf>,
    pub input: Option<PathBuf>,
    pub num: u8,
    pub console: bool,
    pub stdin: bool,
}

impl SerialParameters {
    /// Helper function to create a serial device from the defined parameters.
    ///
    /// # Arguments
    /// * `evt_fd` - eventfd used for interrupt events
    /// * `keep_fds` - Vector of FDs required by this device if it were sandboxed in a child
    ///                process. `evt_fd` will always be added to this vector by this function.
    pub fn create_serial_device<T: SerialDevice>(
        &self,
        evt_fd: &EventFd,
        keep_fds: &mut Vec<RawFd>,
    ) -> std::result::Result<T, Error> {
        let evt_fd = evt_fd.try_clone().map_err(Error::CloneEventFd)?;
        keep_fds.push(evt_fd.as_raw_fd());
        let input: Option<Box<dyn io::Read + Send>> = if let Some(input_path) = &self.input {
            let input_file = File::open(input_path.as_path()).map_err(Error::FileError)?;
            keep_fds.push(input_file.as_raw_fd());
            Some(Box::new(input_file))
        } else if self.stdin {
            keep_fds.push(stdin().as_raw_fd());
            // This wrapper is used in place of the libstd native version because we don't want
            // buffering for stdin.
            struct StdinWrapper;
            impl io::Read for StdinWrapper {
                fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                    read_raw_stdin(out).map_err(|e| e.into())
                }
            }
            Some(Box::new(StdinWrapper))
        } else {
            None
        };
        let output: Option<Box<dyn io::Write + Send>> = match self.type_ {
            SerialType::Stdout => {
                keep_fds.push(stdout().as_raw_fd());
                Some(Box::new(stdout()))
            }
            SerialType::Sink => None,
            SerialType::Syslog => {
                syslog::push_fds(keep_fds);
                Some(Box::new(syslog::Syslogger::new(
                    syslog::Priority::Info,
                    syslog::Facility::Daemon,
                )))
            }
            SerialType::File => match &self.path {
                Some(path) => {
                    let file = File::create(path.as_path()).map_err(Error::FileError)?;
                    keep_fds.push(file.as_raw_fd());
                    Some(Box::new(file))
                }
                None => return Err(Error::PathRequired),
            },
            SerialType::UnixSocket => return Err(Error::Unimplemented(SerialType::UnixSocket)),
        };
        Ok(T::new(evt_fd, input, output, keep_fds.to_vec()))
    }
}

// Structure for holding the default configuration of the serial devices.
const DEFAULT_SERIAL_PARAMS: [SerialParameters; 4] = [
    SerialParameters {
        type_: SerialType::Stdout,
        path: None,
        input: None,
        num: 1,
        console: true,
        stdin: true,
    },
    SerialParameters {
        type_: SerialType::Sink,
        path: None,
        input: None,
        num: 2,
        console: false,
        stdin: false,
    },
    SerialParameters {
        type_: SerialType::Sink,
        path: None,
        input: None,
        num: 3,
        console: false,
        stdin: false,
    },
    SerialParameters {
        type_: SerialType::Sink,
        path: None,
        input: None,
        num: 4,
        console: false,
        stdin: false,
    },
];

/// Address for Serial ports in x86
pub const SERIAL_ADDR: [u64; 4] = [0x3f8, 0x2f8, 0x3e8, 0x2e8];

/// String representations of serial devices
const SERIAL_TTY_STRINGS: [&str; 4] = ["ttyS0", "ttyS1", "ttyS2", "ttyS3"];

/// Helper function to get the tty string of a serial device based on the port number. Will default
///  to ttyS0 if an invalid number is given.
pub fn get_serial_tty_string(stdio_serial_num: u8) -> String {
    stdio_serial_num
        .checked_sub(1)
        .and_then(|i| SERIAL_TTY_STRINGS.get(i as usize))
        .unwrap_or(&SERIAL_TTY_STRINGS[0])
        .to_string()
}

/// Adds serial devices to the provided bus based on the serial parameters given. Returns the serial
///  port number and serial device to be used for stdout if defined.
///
/// # Arguments
///
/// * `io_bus` - Bus to add the devices to
/// * `com_evt_1_3` - eventfd for com1 and com3
/// * `com_evt_1_4` - eventfd for com2 and com4
/// * `io_bus` - Bus to add the devices to
/// * `serial_parameters` - definitions of serial parameter configuationis. If a setting is not
///     provided for a port, then it will use the default configuation.
pub fn add_serial_devices(
    io_bus: &mut Bus,
    com_evt_1_3: &EventFd,
    com_evt_2_4: &EventFd,
    serial_parameters: &BTreeMap<u8, SerialParameters>,
    serial_jail: Option<Minijail>,
) -> Result<Option<u8>, DeviceRegistrationError> {
    let mut stdio_serial_num = None;

    for x in 0..=3 {
        let com_evt = match x {
            0 => com_evt_1_3,
            1 => com_evt_2_4,
            2 => com_evt_1_3,
            3 => com_evt_2_4,
            _ => com_evt_1_3,
        };

        let param = serial_parameters
            .get(&(x + 1))
            .unwrap_or(&DEFAULT_SERIAL_PARAMS[x as usize]);

        if param.console {
            stdio_serial_num = Some(x + 1);
        }

        let mut preserved_fds = Vec::new();
        let com = param
            .create_serial_device::<Serial>(&com_evt, &mut preserved_fds)
            .map_err(DeviceRegistrationError::CreateSerialDevice)?;

        match serial_jail.as_ref() {
            Some(jail) => {
                let com = Arc::new(Mutex::new(
                    ProxyDevice::new(com, &jail, preserved_fds)
                        .map_err(DeviceRegistrationError::ProxyDeviceCreation)?,
                ));
                io_bus
                    .insert(com.clone(), SERIAL_ADDR[x as usize], 0x8, false)
                    .unwrap();
            }
            None => {
                let com = Arc::new(Mutex::new(com));
                io_bus
                    .insert(com.clone(), SERIAL_ADDR[x as usize], 0x8, false)
                    .unwrap();
            }
        }
    }

    Ok(stdio_serial_num)
}

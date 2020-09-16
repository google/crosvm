// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::fmt::{self, Display};
use std::fs::{File, OpenOptions};
use std::io::{self, stdin, stdout, ErrorKind};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use base::{error, info, read_raw_stdin, syslog, Event};
use devices::{Bus, ProxyDevice, Serial, SerialDevice};
use minijail::Minijail;
use sync::Mutex;

use crate::DeviceRegistrationError;

#[derive(Debug)]
pub enum Error {
    CloneEvent(base::Error),
    FileError(std::io::Error),
    InvalidSerialHardware(String),
    InvalidSerialType(String),
    PathRequired,
    SocketCreateFailed,
    Unimplemented(SerialType),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            CloneEvent(e) => write!(f, "unable to clone an Event: {}", e),
            FileError(e) => write!(f, "unable to open/create file: {}", e),
            InvalidSerialHardware(e) => write!(f, "invalid serial hardware: {}", e),
            InvalidSerialType(e) => write!(f, "invalid serial type: {}", e),
            PathRequired => write!(f, "serial device type file requires a path"),
            SocketCreateFailed => write!(f, "failed to create unbound socket"),
            Unimplemented(e) => write!(f, "serial device type {} not implemented", e.to_string()),
        }
    }
}

/// Enum for possible type of serial devices
#[derive(Clone, Debug)]
pub enum SerialType {
    File,
    Stdout,
    Sink,
    Syslog,
    UnixSocket,
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

/// Serial device hardware types
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SerialHardware {
    Serial,        // Standard PC-style (8250/16550 compatible) UART
    VirtioConsole, // virtio-console device
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

impl FromStr for SerialHardware {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "serial" => Ok(SerialHardware::Serial),
            "virtio-console" => Ok(SerialHardware::VirtioConsole),
            _ => Err(Error::InvalidSerialHardware(s.to_string())),
        }
    }
}

struct WriteSocket {
    sock: UnixDatagram,
    path: PathBuf,
    buf: String,
}

const BUF_CAPACITY: usize = 1024;

impl WriteSocket {
    pub fn new(s: UnixDatagram, p: PathBuf) -> WriteSocket {
        WriteSocket {
            sock: s,
            path: p,
            buf: String::with_capacity(BUF_CAPACITY),
        }
    }

    // |send_buf| uses an immutable |self|, even though its |sock| is possibly
    // going be modified. This is needed to allow the mutating of |buf| between
    // calls to |send_buf| in the io::Write impl.
    pub fn send_buf(&self, buf: &[u8]) -> io::Result<usize> {
        // It's possible we aren't yet connected to the socket. Always try once
        // to reconnect if sending fails.
        const SEND_RETRY: usize = 2;
        let mut sent = 0;
        for _ in 0..SEND_RETRY {
            match self.sock.send(&buf[..]) {
                Ok(bytes_sent) => {
                    sent = bytes_sent;
                    break;
                }
                Err(e) => match e.kind() {
                    ErrorKind::ConnectionRefused
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::NotConnected
                    | ErrorKind::Other => match self.sock.connect(self.path.as_path()) {
                        Ok(_) => {}
                        Err(e) => {
                            info!("Couldn't connect {:?}", e);
                            break;
                        }
                    },
                    _ => {
                        info!("Send error: {:?}", e);
                    }
                },
            }
        }
        Ok(sent)
    }
}

impl io::Write for WriteSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let parsed_str = String::from_utf8_lossy(buf);

        let last_newline_idx = match parsed_str.rfind('\n') {
            Some(newline_idx) => Some(self.buf.len() + newline_idx),
            None => None,
        };
        self.buf.push_str(&parsed_str);

        match last_newline_idx {
            Some(last_newline_idx) => {
                for line in (self.buf[..last_newline_idx]).lines() {
                    if self.send_buf(line.as_bytes()).is_err() {
                        break;
                    }
                }
                self.buf.drain(..=last_newline_idx);
            }
            None => {
                if self.buf.len() >= BUF_CAPACITY {
                    if let Err(e) = self.send_buf(self.buf.as_bytes()) {
                        info!("Couldn't send full buffer. {:?}", e);
                    }
                    self.buf.clear();
                }
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Holds the parameters for a serial device
#[derive(Clone, Debug)]
pub struct SerialParameters {
    pub type_: SerialType,
    pub hardware: SerialHardware,
    pub path: Option<PathBuf>,
    pub input: Option<PathBuf>,
    pub num: u8,
    pub console: bool,
    pub earlycon: bool,
    pub stdin: bool,
}

impl SerialParameters {
    /// Helper function to create a serial device from the defined parameters.
    ///
    /// # Arguments
    /// * `evt` - event used for interrupt events
    /// * `keep_fds` - Vector of FDs required by this device if it were sandboxed in a child
    ///                process. `evt` will always be added to this vector by this function.
    pub fn create_serial_device<T: SerialDevice>(
        &self,
        evt: &Event,
        keep_fds: &mut Vec<RawFd>,
    ) -> std::result::Result<T, Error> {
        let evt = evt.try_clone().map_err(Error::CloneEvent)?;
        keep_fds.push(evt.as_raw_fd());
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
                    let file = OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open(path.as_path())
                        .map_err(Error::FileError)?;
                    keep_fds.push(file.as_raw_fd());
                    Some(Box::new(file))
                }
                None => return Err(Error::PathRequired),
            },
            SerialType::UnixSocket => match &self.path {
                Some(path) => {
                    let sock = match UnixDatagram::bind(path).map_err(Error::FileError) {
                        Ok(sock) => sock,
                        Err(e) => {
                            error!("Couldn't bind: {:?}", e);
                            UnixDatagram::unbound().map_err(Error::FileError)?
                        }
                    };
                    keep_fds.push(sock.as_raw_fd());
                    Some(Box::new(WriteSocket::new(sock, path.to_path_buf())))
                }
                None => return Err(Error::PathRequired),
            },
        };
        Ok(T::new(evt, input, output, keep_fds.to_vec()))
    }

    pub fn add_bind_mounts(&self, jail: &mut Minijail) -> Result<(), minijail::Error> {
        if let Some(path) = &self.path {
            match self.type_ {
                SerialType::UnixSocket => {
                    if let Some(parent) = path.as_path().parent() {
                        if parent.exists() {
                            info!("Bind mounting dir {}", parent.display());
                            jail.mount_bind(parent, parent, true)?;
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Add the default serial parameters for serial ports that have not already been specified.
///
/// This ensures that `serial_parameters` will contain parameters for each of the four PC-style
/// serial ports (COM1-COM4).
///
/// It also sets the first `SerialHardware::Serial` to be the default console device if no other
/// serial parameters exist with console=true and the first serial device has not already been
/// configured explicitly.
pub fn set_default_serial_parameters(
    serial_parameters: &mut BTreeMap<(SerialHardware, u8), SerialParameters>,
) {
    // If no console device exists and the first serial port has not been specified,
    // set the first serial port as a stdout+stdin console.
    let default_console = (SerialHardware::Serial, 1);
    if !serial_parameters.iter().any(|(_, p)| p.console) {
        serial_parameters
            .entry(default_console)
            .or_insert(SerialParameters {
                type_: SerialType::Stdout,
                hardware: SerialHardware::Serial,
                path: None,
                input: None,
                num: 1,
                console: true,
                earlycon: false,
                stdin: true,
            });
    }

    // Ensure all four of the COM ports exist.
    // If one of these four SerialHardware::Serial port was not configured by the user,
    // set it up as a sink.
    for num in 1..=4 {
        let key = (SerialHardware::Serial, num);
        serial_parameters.entry(key).or_insert(SerialParameters {
            type_: SerialType::Sink,
            hardware: SerialHardware::Serial,
            path: None,
            input: None,
            num,
            console: false,
            earlycon: false,
            stdin: false,
        });
    }
}

/// Address for Serial ports in x86
pub const SERIAL_ADDR: [u64; 4] = [0x3f8, 0x2f8, 0x3e8, 0x2e8];

/// Adds serial devices to the provided bus based on the serial parameters given.
///
/// Only devices with hardware type `SerialHardware::Serial` are added by this function.
///
/// # Arguments
///
/// * `io_bus` - Bus to add the devices to
/// * `com_evt_1_3` - event for com1 and com3
/// * `com_evt_1_4` - event for com2 and com4
/// * `io_bus` - Bus to add the devices to
/// * `serial_parameters` - definitions of serial parameter configurations.
///   All four of the traditional PC-style serial ports (COM1-COM4) must be specified.
pub fn add_serial_devices(
    io_bus: &mut Bus,
    com_evt_1_3: &Event,
    com_evt_2_4: &Event,
    serial_parameters: &BTreeMap<(SerialHardware, u8), SerialParameters>,
    serial_jail: Option<Minijail>,
) -> Result<(), DeviceRegistrationError> {
    for x in 0..=3 {
        let com_evt = match x {
            0 => com_evt_1_3,
            1 => com_evt_2_4,
            2 => com_evt_1_3,
            3 => com_evt_2_4,
            _ => com_evt_1_3,
        };

        let param = serial_parameters
            .get(&(SerialHardware::Serial, x + 1))
            .ok_or(DeviceRegistrationError::MissingRequiredSerialDevice(x + 1))?;

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

    Ok(())
}

#[derive(Debug)]
pub enum GetSerialCmdlineError {
    KernelCmdline(kernel_cmdline::Error),
    UnsupportedEarlyconHardware(SerialHardware),
}

impl Display for GetSerialCmdlineError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::GetSerialCmdlineError::*;

        match self {
            KernelCmdline(e) => write!(f, "error appending to cmdline: {}", e),
            UnsupportedEarlyconHardware(hw) => {
                write!(f, "hardware {} not supported as earlycon", hw)
            }
        }
    }
}

pub type GetSerialCmdlineResult<T> = std::result::Result<T, GetSerialCmdlineError>;

/// Add serial options to the provided `cmdline` based on `serial_parameters`.
/// `serial_io_type` should be "io" if the platform uses x86-style I/O ports for serial devices
/// or "mmio" if the serial ports are memory mapped.
pub fn get_serial_cmdline(
    cmdline: &mut kernel_cmdline::Cmdline,
    serial_parameters: &BTreeMap<(SerialHardware, u8), SerialParameters>,
    serial_io_type: &str,
) -> GetSerialCmdlineResult<()> {
    match serial_parameters
        .iter()
        .filter(|(_, p)| p.console)
        .map(|(k, _)| k)
        .next()
    {
        Some((SerialHardware::Serial, num)) => {
            cmdline
                .insert("console", &format!("ttyS{}", num - 1))
                .map_err(GetSerialCmdlineError::KernelCmdline)?;
        }
        Some((SerialHardware::VirtioConsole, num)) => {
            cmdline
                .insert("console", &format!("hvc{}", num - 1))
                .map_err(GetSerialCmdlineError::KernelCmdline)?;
        }
        None => {}
    }

    match serial_parameters
        .iter()
        .filter(|(_, p)| p.earlycon)
        .map(|(k, _)| k)
        .next()
    {
        Some((SerialHardware::Serial, num)) => {
            if let Some(addr) = SERIAL_ADDR.get(*num as usize - 1) {
                cmdline
                    .insert(
                        "earlycon",
                        &format!("uart8250,{},0x{:x}", serial_io_type, addr),
                    )
                    .map_err(GetSerialCmdlineError::KernelCmdline)?;
            }
        }
        Some((hw, _num)) => {
            return Err(GetSerialCmdlineError::UnsupportedEarlyconHardware(*hw));
        }
        None => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_cmdline::Cmdline;

    #[test]
    fn get_serial_cmdline_default() {
        let mut cmdline = Cmdline::new(4096);
        let mut serial_parameters = BTreeMap::new();

        set_default_serial_parameters(&mut serial_parameters);
        get_serial_cmdline(&mut cmdline, &serial_parameters, "io")
            .expect("get_serial_cmdline failed");

        let cmdline_str = cmdline.as_str();
        assert!(cmdline_str.contains("console=ttyS0"));
    }

    #[test]
    fn get_serial_cmdline_virtio_console() {
        let mut cmdline = Cmdline::new(4096);
        let mut serial_parameters = BTreeMap::new();

        // Add a virtio-console device with console=true.
        serial_parameters.insert(
            (SerialHardware::VirtioConsole, 1),
            SerialParameters {
                type_: SerialType::Stdout,
                hardware: SerialHardware::VirtioConsole,
                path: None,
                input: None,
                num: 1,
                console: true,
                earlycon: false,
                stdin: true,
            },
        );

        set_default_serial_parameters(&mut serial_parameters);
        get_serial_cmdline(&mut cmdline, &serial_parameters, "io")
            .expect("get_serial_cmdline failed");

        let cmdline_str = cmdline.as_str();
        assert!(cmdline_str.contains("console=hvc0"));
    }

    #[test]
    fn get_serial_cmdline_virtio_console_serial_earlycon() {
        let mut cmdline = Cmdline::new(4096);
        let mut serial_parameters = BTreeMap::new();

        // Add a virtio-console device with console=true.
        serial_parameters.insert(
            (SerialHardware::VirtioConsole, 1),
            SerialParameters {
                type_: SerialType::Stdout,
                hardware: SerialHardware::VirtioConsole,
                path: None,
                input: None,
                num: 1,
                console: true,
                earlycon: false,
                stdin: true,
            },
        );

        // Override the default COM1 with an earlycon device.
        serial_parameters.insert(
            (SerialHardware::Serial, 1),
            SerialParameters {
                type_: SerialType::Stdout,
                hardware: SerialHardware::Serial,
                path: None,
                input: None,
                num: 1,
                console: false,
                earlycon: true,
                stdin: false,
            },
        );

        set_default_serial_parameters(&mut serial_parameters);
        get_serial_cmdline(&mut cmdline, &serial_parameters, "io")
            .expect("get_serial_cmdline failed");

        let cmdline_str = cmdline.as_str();
        assert!(cmdline_str.contains("console=hvc0"));
        assert!(cmdline_str.contains("earlycon=uart8250,io,0x3f8"));
    }

    #[test]
    fn get_serial_cmdline_virtio_console_invalid_earlycon() {
        let mut cmdline = Cmdline::new(4096);
        let mut serial_parameters = BTreeMap::new();

        // Try to add a virtio-console device with earlycon=true (unsupported).
        serial_parameters.insert(
            (SerialHardware::VirtioConsole, 1),
            SerialParameters {
                type_: SerialType::Stdout,
                hardware: SerialHardware::VirtioConsole,
                path: None,
                input: None,
                num: 1,
                console: false,
                earlycon: true,
                stdin: true,
            },
        );

        set_default_serial_parameters(&mut serial_parameters);
        get_serial_cmdline(&mut cmdline, &serial_parameters, "io")
            .expect_err("get_serial_cmdline succeeded");
    }
}

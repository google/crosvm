// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::borrow::Cow;
use std::fmt::{self, Display};
use std::fs::{File, OpenOptions};
use std::io::{self, stdin, stdout, ErrorKind};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use base::{
    error, info, read_raw_stdin, safe_descriptor_from_path, syslog, AsRawDescriptor, Event,
    RawDescriptor,
};
use hypervisor::ProtectionType;
use minijail::Minijail;
use remain::sorted;
use thiserror::Error as ThisError;

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
    #[error("Serial device type {0} not implemented")]
    Unimplemented(SerialType),
}

/// Abstraction over serial-like devices that can be created given an event and optional input and
/// output streams.
pub trait SerialDevice {
    fn new(
        protected_vm: ProtectionType,
        interrupt_evt: Event,
        input: Option<Box<dyn io::Read + Send>>,
        output: Option<Box<dyn io::Write + Send>>,
        keep_rds: Vec<RawDescriptor>,
    ) -> Self;
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
    buf: String,
}

const BUF_CAPACITY: usize = 1024;

impl WriteSocket {
    pub fn new(s: UnixDatagram) -> WriteSocket {
        WriteSocket {
            sock: s,
            buf: String::with_capacity(BUF_CAPACITY),
        }
    }

    pub fn send_buf(&self, buf: &[u8]) -> io::Result<usize> {
        const SEND_RETRY: usize = 2;
        let mut sent = 0;
        for _ in 0..SEND_RETRY {
            match self.sock.send(buf) {
                Ok(bytes_sent) => {
                    sent = bytes_sent;
                    break;
                }
                Err(e) => info!("Send error: {:?}", e),
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

// The maximum length of a path that can be used as the address of a
// unix socket. Note that this includes the null-terminator.
const MAX_SOCKET_PATH_LENGTH: usize = 108;

impl SerialParameters {
    /// Helper function to create a serial device from the defined parameters.
    ///
    /// # Arguments
    /// * `evt` - event used for interrupt events
    /// * `keep_rds` - Vector of descriptors required by this device if it were sandboxed
    ///                in a child process. `evt` will always be added to this vector by
    ///                this function.
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
            let input_file = if let Some(fd) =
                safe_descriptor_from_path(input_path).map_err(|e| Error::FileError(e.into()))?
            {
                fd.into()
            } else {
                File::open(input_path).map_err(Error::FileError)?
            };
            keep_rds.push(input_file.as_raw_descriptor());
            Some(Box::new(input_file))
        } else if self.stdin {
            keep_rds.push(stdin().as_raw_descriptor());
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
                keep_rds.push(stdout().as_raw_descriptor());
                Some(Box::new(stdout()))
            }
            SerialType::Sink => None,
            SerialType::Syslog => {
                syslog::push_descriptors(keep_rds);
                Some(Box::new(syslog::Syslogger::new(
                    syslog::Priority::Info,
                    syslog::Facility::Daemon,
                )))
            }
            SerialType::File => match &self.path {
                Some(path) => {
                    let path = path.as_path();
                    let file = if let Some(fd) =
                        safe_descriptor_from_path(path).map_err(|e| Error::FileError(e.into()))?
                    {
                        fd.into()
                    } else {
                        OpenOptions::new()
                            .append(true)
                            .create(true)
                            .open(path)
                            .map_err(Error::FileError)?
                    };
                    keep_rds.push(file.as_raw_descriptor());
                    Some(Box::new(file))
                }
                None => return Err(Error::PathRequired),
            },
            SerialType::UnixSocket => {
                match &self.path {
                    Some(path) => {
                        // If the path is longer than 107 characters,
                        // then we won't be able to connect directly
                        // to it. Instead we can shorten the path by
                        // opening the containing directory and using
                        // /proc/self/fd/*/ to access it via a shorter
                        // path.
                        let mut path_cow = Cow::<Path>::Borrowed(path);
                        let mut _dir_fd = None;
                        if path.as_os_str().len() >= MAX_SOCKET_PATH_LENGTH {
                            let mut short_path = PathBuf::with_capacity(MAX_SOCKET_PATH_LENGTH);
                            short_path.push("/proc/self/fd/");

                            // We don't actually want to open this
                            // directory for reading, but the stdlib
                            // requires all files be opened as at
                            // least one of readable, writeable, or
                            // appeandable.
                            let dir = OpenOptions::new()
                                .read(true)
                                .open(path.parent().ok_or(Error::InvalidPath)?)
                                .map_err(Error::FileError)?;

                            short_path.push(dir.as_raw_descriptor().to_string());
                            short_path.push(path.file_name().ok_or(Error::InvalidPath)?);
                            path_cow = Cow::Owned(short_path);
                            _dir_fd = Some(dir);
                        }

                        // The shortened path may still be too long,
                        // in which case we must give up here.
                        if path_cow.as_os_str().len() >= MAX_SOCKET_PATH_LENGTH {
                            return Err(Error::InvalidPath);
                        }

                        // There's a race condition between
                        // vmlog_forwarder making the logging socket and
                        // crosvm starting up, so we loop here until it's
                        // available.
                        let sock = UnixDatagram::unbound().map_err(Error::FileError)?;
                        loop {
                            match sock.connect(&path_cow) {
                                Ok(_) => break,
                                Err(e) => {
                                    match e.kind() {
                                        ErrorKind::NotFound | ErrorKind::ConnectionRefused => {
                                            // logging socket doesn't
                                            // exist yet, sleep for 10 ms
                                            // and try again.
                                            thread::sleep(Duration::from_millis(10))
                                        }
                                        _ => {
                                            error!("Unexpected error connecting to logging socket: {:?}", e);
                                            return Err(Error::FileError(e));
                                        }
                                    }
                                }
                            };
                        }
                        keep_rds.push(sock.as_raw_descriptor());
                        Some(Box::new(WriteSocket::new(sock)))
                    }
                    None => return Err(Error::PathRequired),
                }
            }
        };
        Ok(T::new(protected_vm, evt, input, output, keep_rds.to_vec()))
    }

    pub fn add_bind_mounts(&self, jail: &mut Minijail) -> Result<(), minijail::Error> {
        if let Some(path) = &self.path {
            if let SerialType::UnixSocket = self.type_ {
                if let Some(parent) = path.as_path().parent() {
                    if parent.exists() {
                        info!("Bind mounting dir {}", parent.display());
                        jail.mount_bind(parent, parent, true)?;
                    }
                }
            }
        }
        Ok(())
    }
}

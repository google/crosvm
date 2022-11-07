// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::borrow::Cow;
use std::fs::OpenOptions;
use std::io;
use std::io::ErrorKind;
use std::io::Write;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use base::error;
use base::info;
use base::read_raw_stdin;
use base::AsRawDescriptor;
use base::Event;
use base::FileSync;
use base::RawDescriptor;
use base::ReadNotifier;
use hypervisor::ProtectionType;

use crate::serial_device::Error;
use crate::serial_device::SerialInput;
use crate::serial_device::SerialParameters;

pub const SYSTEM_SERIAL_TYPE_NAME: &str = "UnixSocket";

// This wrapper is used in place of the libstd native version because we don't want
// buffering for stdin.
pub struct ConsoleInput(std::io::Stdin);

impl ConsoleInput {
    pub fn new() -> Self {
        Self(std::io::stdin())
    }
}

impl io::Read for ConsoleInput {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        read_raw_stdin(out).map_err(|e| e.into())
    }
}

impl ReadNotifier for ConsoleInput {
    fn get_read_notifier(&self) -> &dyn AsRawDescriptor {
        &self.0
    }
}

impl SerialInput for ConsoleInput {}

/// Abstraction over serial-like devices that can be created given an event and optional input and
/// output streams.
pub trait SerialDevice {
    fn new(
        protection_type: ProtectionType,
        interrupt_evt: Event,
        input: Option<Box<dyn SerialInput>>,
        output: Option<Box<dyn io::Write + Send>>,
        sync: Option<Box<dyn FileSync + Send>>,
        out_timestamp: bool,
        keep_rds: Vec<RawDescriptor>,
    ) -> Self;
}

// The maximum length of a path that can be used as the address of a
// unix socket. Note that this includes the null-terminator.
pub const MAX_SOCKET_PATH_LENGTH: usize = 108;

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

pub(crate) fn create_system_type_serial_device<T: SerialDevice>(
    param: &SerialParameters,
    protection_type: ProtectionType,
    evt: Event,
    input: Option<Box<dyn SerialInput>>,
    keep_rds: &mut Vec<RawDescriptor>,
) -> std::result::Result<T, Error> {
    match &param.path {
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

                let parent_path = path
                    .parent()
                    .ok_or_else(|| Error::InvalidPath(path.clone()))?;
                let file_name = path
                    .file_name()
                    .ok_or_else(|| Error::InvalidPath(path.clone()))?;

                // We don't actually want to open this
                // directory for reading, but the stdlib
                // requires all files be opened as at
                // least one of readable, writeable, or
                // appeandable.
                let dir = OpenOptions::new()
                    .read(true)
                    .open(parent_path)
                    .map_err(|e| Error::FileOpen(e, parent_path.into()))?;

                short_path.push(dir.as_raw_descriptor().to_string());
                short_path.push(file_name);
                path_cow = Cow::Owned(short_path);
                _dir_fd = Some(dir);
            }

            // The shortened path may still be too long,
            // in which case we must give up here.
            if path_cow.as_os_str().len() >= MAX_SOCKET_PATH_LENGTH {
                return Err(Error::InvalidPath(path_cow.into()));
            }

            // There's a race condition between
            // vmlog_forwarder making the logging socket and
            // crosvm starting up, so we loop here until it's
            // available.
            let sock = UnixDatagram::unbound().map_err(Error::SocketCreate)?;
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
                                return Err(Error::SocketConnect(e));
                            }
                        }
                    }
                };
            }
            keep_rds.push(sock.as_raw_descriptor());
            let output: Option<Box<dyn Write + Send>> = Some(Box::new(WriteSocket::new(sock)));
            Ok(T::new(
                protection_type,
                evt,
                input,
                output,
                None,
                false,
                keep_rds.to_vec(),
            ))
        }
        None => Err(Error::PathRequired),
    }
}

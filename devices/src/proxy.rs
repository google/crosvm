// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Runs hardware devices in child processes.

use std::fmt::{self, Display};
use std::os::unix::io::{AsRawFd, RawFd};
use std::process;
use std::time::Duration;
use std::{self, io};

use io_jail::{self, Minijail};
use libc::pid_t;
use msg_socket::{MsgOnSocket, MsgReceiver, MsgSender, MsgSocket};
use sys_util::{error, net::UnixSeqpacket};

use crate::BusDevice;

/// Errors for proxy devices.
#[derive(Debug)]
pub enum Error {
    ForkingJail(io_jail::Error),
    Io(io::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            ForkingJail(e) => write!(f, "Failed to fork jail process: {}", e),
            Io(e) => write!(f, "IO error configuring proxy device {}.", e),
        }
    }
}

const SOCKET_TIMEOUT_MS: u64 = 2000;

#[derive(MsgOnSocket)]
enum Command {
    Read {
        len: u32,
        offset: u64,
    },
    Write {
        len: u32,
        offset: u64,
        data: [u8; 8],
    },
    ReadConfig(u32),
    WriteConfig {
        reg_idx: u32,
        offset: u32,
        len: u32,
        data: [u8; 4],
    },
    Shutdown,
}

#[derive(MsgOnSocket)]
enum CommandResult {
    Ok,
    ReadResult([u8; 8]),
    ReadConfigResult(u32),
}

fn child_proc(sock: UnixSeqpacket, device: &mut dyn BusDevice) {
    let mut running = true;
    let sock = MsgSocket::<CommandResult, Command>::new(sock);

    while running {
        let cmd = match sock.recv() {
            Ok(cmd) => cmd,
            Err(err) => {
                error!("child device process failed recv: {}", err);
                break;
            }
        };

        let res = match cmd {
            Command::Read { len, offset } => {
                let mut buffer = [0u8; 8];
                device.read(offset, &mut buffer[0..len as usize]);
                sock.send(&CommandResult::ReadResult(buffer))
            }
            Command::Write { len, offset, data } => {
                let len = len as usize;
                device.write(offset, &data[0..len]);
                sock.send(&CommandResult::Ok)
            }
            Command::ReadConfig(idx) => {
                let val = device.config_register_read(idx as usize);
                sock.send(&CommandResult::ReadConfigResult(val))
            }
            Command::WriteConfig {
                reg_idx,
                offset,
                len,
                data,
            } => {
                let len = len as usize;
                device.config_register_write(reg_idx as usize, offset as u64, &data[0..len]);
                sock.send(&CommandResult::Ok)
            }
            Command::Shutdown => {
                running = false;
                sock.send(&CommandResult::Ok)
            }
        };
        if let Err(e) = res {
            error!("child device process failed send: {}", e);
        }
    }
}

/// Wraps an inner `BusDevice` that is run inside a child process via fork.
///
/// Because forks are very unfriendly to destructors and all memory mappings and file descriptors
/// are inherited, this should be used as early as possible in the main process.
pub struct ProxyDevice {
    sock: MsgSocket<Command, CommandResult>,
    pid: pid_t,
    debug_label: String,
}

impl ProxyDevice {
    /// Takes the given device and isolates it into another process via fork before returning.
    ///
    /// The forked process will automatically be terminated when this is dropped, so be sure to keep
    /// a reference.
    ///
    /// # Arguments
    /// * `device` - The device to isolate to another process.
    /// * `keep_fds` - File descriptors that will be kept open in the child
    pub fn new<D: BusDevice>(
        mut device: D,
        jail: &Minijail,
        mut keep_fds: Vec<RawFd>,
    ) -> Result<ProxyDevice> {
        let debug_label = device.debug_label();
        let (child_sock, parent_sock) = UnixSeqpacket::pair().map_err(Error::Io)?;

        keep_fds.push(child_sock.as_raw_fd());
        // Forking here is safe as long as the program is still single threaded.
        let pid = unsafe {
            match jail.fork(Some(&keep_fds)).map_err(Error::ForkingJail)? {
                0 => {
                    device.on_sandboxed();
                    child_proc(child_sock, &mut device);
                    // ! Never returns
                    process::exit(0);
                }
                p => p,
            }
        };

        parent_sock
            .set_write_timeout(Some(Duration::from_millis(SOCKET_TIMEOUT_MS)))
            .map_err(Error::Io)?;
        parent_sock
            .set_read_timeout(Some(Duration::from_millis(SOCKET_TIMEOUT_MS)))
            .map_err(Error::Io)?;
        Ok(ProxyDevice {
            sock: MsgSocket::<Command, CommandResult>::new(parent_sock),
            pid,
            debug_label,
        })
    }

    pub fn pid(&self) -> pid_t {
        self.pid
    }

    fn sync_send(&self, cmd: Command) -> Option<CommandResult> {
        let res = self.sock.send(&cmd);
        if let Err(e) = res {
            error!(
                "failed write to child device process {}: {}",
                self.debug_label, e,
            );
        };
        match self.sock.recv() {
            Err(e) => {
                error!(
                    "failed read from child device process {}: {}",
                    self.debug_label, e,
                );
                None
            }
            Ok(r) => Some(r),
        }
    }
}

impl BusDevice for ProxyDevice {
    fn debug_label(&self) -> String {
        self.debug_label.clone()
    }

    fn config_register_write(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        let len = data.len() as u32;
        let mut buffer = [0u8; 4];
        buffer[0..data.len()].clone_from_slice(data);
        let reg_idx = reg_idx as u32;
        let offset = offset as u32;
        self.sync_send(Command::WriteConfig {
            reg_idx,
            offset,
            len,
            data: buffer,
        });
    }

    fn config_register_read(&self, reg_idx: usize) -> u32 {
        let res = self.sync_send(Command::ReadConfig(reg_idx as u32));
        if let Some(CommandResult::ReadConfigResult(val)) = res {
            val
        } else {
            0
        }
    }

    fn read(&mut self, offset: u64, data: &mut [u8]) {
        let len = data.len() as u32;
        if let Some(CommandResult::ReadResult(buffer)) =
            self.sync_send(Command::Read { len, offset })
        {
            let len = data.len();
            data.clone_from_slice(&buffer[0..len]);
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        let mut buffer = [0u8; 8];
        let len = data.len() as u32;
        buffer[0..data.len()].clone_from_slice(data);
        self.sync_send(Command::Write {
            len,
            offset,
            data: buffer,
        });
    }
}

impl Drop for ProxyDevice {
    fn drop(&mut self) {
        self.sync_send(Command::Shutdown);
    }
}

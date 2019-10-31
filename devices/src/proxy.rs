// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Runs hardware devices in child processes.

use std::fmt::{self, Display};
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;
use std::{self, io};

use io_jail::{self, Minijail};
use libc::{self, pid_t};
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

#[derive(Debug, MsgOnSocket)]
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
    RunUserCommand,
}

#[derive(MsgOnSocket)]
enum CommandResult {
    Ok,
    ReadResult([u8; 8]),
    ReadConfigResult(u32),
}

fn child_proc<D: BusDevice, F: FnMut(&mut D)>(
    sock: UnixSeqpacket,
    device: &mut D,
    mut user_command: F,
) {
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
                // Command::Write does not have a result.
                Ok(())
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
                // Command::WriteConfig does not have a result.
                Ok(())
            }
            Command::Shutdown => {
                running = false;
                sock.send(&CommandResult::Ok)
            }
            Command::RunUserCommand => {
                user_command(device);
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
    /// * `jail` - The jail to use for isolating the given device.
    /// * `keep_fds` - File descriptors that will be kept open in the child.
    pub fn new<D: BusDevice>(
        device: D,
        jail: &Minijail,
        keep_fds: Vec<RawFd>,
    ) -> Result<ProxyDevice> {
        Self::new_with_user_command(device, jail, keep_fds, |_| {})
    }

    /// Similar to `ProxyDevice::new`, but adds an additional custom command to be run in the forked
    /// process when `run_user_command` is called.
    ///
    /// Note that the custom command closure is run in the main thread of the child process, which
    /// also services `BusDevice` requests. Therefore, do not run blocking calls in the closure
    /// without a timeout, or you will block any VCPU which touches this device, and every other
    /// thread which needs to lock this device's mutex.
    ///
    /// # Arguments
    /// * `device` - The device to isolate to another process.
    /// * `jail` - The jail to use for isolating the given device.
    /// * `keep_fds` - File descriptors that will be kept open in the child.
    /// * `user_command` - Closure to be run in the forked process.
    pub fn new_with_user_command<D: BusDevice, F: FnMut(&mut D)>(
        mut device: D,
        jail: &Minijail,
        mut keep_fds: Vec<RawFd>,
        user_command: F,
    ) -> Result<ProxyDevice> {
        let debug_label = device.debug_label();
        let (child_sock, parent_sock) = UnixSeqpacket::pair().map_err(Error::Io)?;

        keep_fds.push(child_sock.as_raw_fd());
        // Forking here is safe as long as the program is still single threaded.
        let pid = unsafe {
            match jail.fork(Some(&keep_fds)).map_err(Error::ForkingJail)? {
                0 => {
                    device.on_sandboxed();
                    child_proc(child_sock, &mut device, user_command);

                    // We're explicitly not using std::process::exit here to avoid the cleanup of
                    // stdout/stderr globals. This can cause cascading panics and SIGILL if a worker
                    // thread attempts to log to stderr after at_exit handlers have been run.
                    // TODO(crbug.com/992494): Remove this once device shutdown ordering is clearly
                    // defined.
                    //
                    // exit() is trivially safe.
                    // ! Never returns
                    libc::exit(0);
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

    /// Runs the callback given in `new_with_custom_command` in the child device process.
    pub fn run_user_command(&self) {
        self.sync_send(&Command::RunUserCommand);
    }

    /// Send a command that does not expect a response from the child device process.
    fn send_no_result(&self, cmd: &Command) {
        let res = self.sock.send(cmd);
        if let Err(e) = res {
            error!(
                "failed write to child device process {}: {}",
                self.debug_label, e,
            );
        }
    }

    /// Send a command and read its response from the child device process.
    fn sync_send(&self, cmd: &Command) -> Option<CommandResult> {
        self.send_no_result(cmd);
        match self.sock.recv() {
            Err(e) => {
                error!(
                    "failed to read result of {:?} from child device process {}: {}",
                    cmd, self.debug_label, e,
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
        self.send_no_result(&Command::WriteConfig {
            reg_idx,
            offset,
            len,
            data: buffer,
        });
    }

    fn config_register_read(&self, reg_idx: usize) -> u32 {
        let res = self.sync_send(&Command::ReadConfig(reg_idx as u32));
        if let Some(CommandResult::ReadConfigResult(val)) = res {
            val
        } else {
            0
        }
    }

    fn read(&mut self, offset: u64, data: &mut [u8]) {
        let len = data.len() as u32;
        if let Some(CommandResult::ReadResult(buffer)) =
            self.sync_send(&Command::Read { len, offset })
        {
            let len = data.len();
            data.clone_from_slice(&buffer[0..len]);
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        let mut buffer = [0u8; 8];
        let len = data.len() as u32;
        buffer[0..data.len()].clone_from_slice(data);
        self.send_no_result(&Command::Write {
            len,
            offset,
            data: buffer,
        });
    }
}

impl Drop for ProxyDevice {
    fn drop(&mut self) {
        self.sync_send(&Command::Shutdown);
    }
}

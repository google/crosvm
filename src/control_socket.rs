// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Helper for sending and receiving control socket commands

use std::fs::remove_file;
use std::io::Result;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::path::Path;

use libc::getpid;

use sys_util::Pollable;

#[derive(Debug, PartialEq)]
/// The set of commands that can be sent over a control socket.
pub enum Command {
    /// A command that could not be identified.
    Unknown,
    /// Stop the process in an orderly fashion.
    Stop,
}

impl Command {
    fn decode(data: &[u8]) -> Command {
        if data.is_empty() {
            return Command::Unknown;
        }
        if data[0] == b's' {
            return Command::Stop;
        }
        Command::Unknown
    }

    fn encode(&self, data: &mut [u8]) {
        if data.is_empty() {
            return;
        }
        match *self {
            Command::Unknown => data[0] = 0,
            Command::Stop => data[0] = b's',
        }
    }
}

/// The receiving side of a control socket.
pub struct ControlSocketRecv {
    s: UnixDatagram,
}

impl ControlSocketRecv {
    /// Binds a new control socket at `path`.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<ControlSocketRecv> {
        let path = path.as_ref();
        let control_socket = if path.is_dir() {
            // Getting the pid is always safe and never fails.
            let pid = unsafe { getpid() };
            UnixDatagram::bind(path.join(format!("crosvm-{}.sock", pid)))?
        } else {
            UnixDatagram::bind(path)?
        };
        Ok(ControlSocketRecv { s: control_socket })
    }

    /// Use the already connected `socket` as a control socket.
    pub fn with_socket(socket: UnixDatagram) -> ControlSocketRecv {
        ControlSocketRecv { s: socket }
    }

    /// Receives a command on this control socket.
    ///
    /// Note that this will block if there is no command waiting.
    pub fn recv(&self) -> Result<Command> {
        let mut buf = [0; 32];
        self.s.recv(&mut buf)?;
        Ok(Command::decode(&buf))
    }
}


// Safe because we return a genuine pollable fd that never changes and shares our lifetime.
unsafe impl Pollable for ControlSocketRecv {
    fn pollable_fd(&self) -> RawFd {
        self.s.as_raw_fd()
    }
}

impl Drop for ControlSocketRecv {
    fn drop(&mut self) {
        if let Ok(addr) = self.s.local_addr() {
            if let Some(path) = addr.as_pathname() {
                if let Err(e) = remove_file(path) {
                    println!("failed to remove control socket file: {:?}", e);
                }
            }
        }
    }
}

/// The sending side of the control socket.
pub struct ControlSocketSend {
    s: UnixDatagram,
}

impl ControlSocketSend {
    /// Connect to a control socket at `path`.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<ControlSocketSend> {
        let s = UnixDatagram::unbound()?;
        s.connect(path)?;
        Ok(ControlSocketSend { s: s })
    }

    /// Use the already connected `socket` as a control socket.
    pub fn with_socket(socket: UnixDatagram) -> ControlSocketSend {
        ControlSocketSend { s: socket }
    }

    /// Send a command to this control socket.
    pub fn send(&self, cmd: &Command) -> Result<()> {
        let mut buf = [0; 32];
        cmd.encode(&mut buf);
        self.s.send(&buf).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;
    use sys_util::Poller;

    #[test]
    fn send_recv() {
        let (s1, s2) = UnixDatagram::pair().expect("failed to create socket pair");
        let send = ControlSocketSend::with_socket(s1);
        let recv = ControlSocketRecv::with_socket(s2);
        send.send(&Command::Stop)
            .expect("failed to send stop command");
        let cmd = recv.recv().expect("failed to recv stop command");
        assert_eq!(cmd, Command::Stop);
    }

    #[test]
    fn poll_recv() {
        let (s1, s2) = UnixDatagram::pair().expect("failed to create socket pair");
        let send = ControlSocketSend::with_socket(s1);
        let recv = ControlSocketRecv::with_socket(s2);
        send.send(&Command::Stop)
            .expect("failed to send stop command");

        let mut poller = Poller::new(1);
        let polled = poller
            .poll(&[(0, &recv)])
            .expect("failed to poll recv socket");
        assert_eq!(polled, [0].as_ref());

        let cmd = recv.recv().expect("failed to recv stop command");
        assert_eq!(cmd, Command::Stop);
    }

    #[test]
    fn unknown() {
        let (s1, s2) = UnixDatagram::pair().expect("failed to create socket pair");
        let send = ControlSocketSend::with_socket(s1);
        let recv = ControlSocketRecv::with_socket(s2);
        send.send(&Command::Unknown)
            .expect("failed to send command");
        let cmd = recv.recv().expect("failed to recv command");
        assert_eq!(cmd, Command::Unknown);
    }

    #[test]
    fn recv_socket_remove_on_drop() {
        let pid = unsafe { getpid() };
        let mut temp_file = temp_dir();
        temp_file.push(format!("control_socket_drop_recv_socket_{}", pid));
        assert!(!temp_file.exists());
        {
            let recv = ControlSocketRecv::new(temp_file.to_str().unwrap());
            assert!(temp_file.exists());
        }
        assert!(!temp_file.exists());
    }
}

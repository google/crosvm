// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Runs hardware devices in child processes.

use std::process;
use std::io::{Error, ErrorKind, Result};
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

use libc::fork;

use byteorder::{NativeEndian, ByteOrder};

use hw::BusDevice;

const SOCKET_TIMEOUT_MS: u64 = 2000;
const MSG_SIZE: usize = 24;
const CHILD_SIGNATURE: [u8; MSG_SIZE] = [0x7f; MSG_SIZE];

/// Macro that retries the given expression every time it returns an `std::io::Error` whose kind is
/// `ErrorKind::Interrupted`. This is useful for operations prone to being spuriously interrupted by
/// signals.
macro_rules! handle_intr {
    ($x:expr) => (
        {
            let res;
            loop {
                match $x {
                    Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
                    v => {
                        res = v;
                        break;
                    }
                }
            }
            res
        }
    )
}

enum Command {
    Read = 0,
    Write = 1,
    Shutdown = 2,
}

fn child_proc(sock: UnixDatagram, device: &mut BusDevice) -> ! {
    let mut running = true;

    let res = handle_intr!(sock.send(&CHILD_SIGNATURE));
    if let Err(e) = res {
        println!("error: failed to send child started signal: {}", e);
        running = false;
    }

    while running {
        let mut buf = [0; MSG_SIZE];
        match handle_intr!(sock.recv(&mut buf)) {
            Ok(c) if c != buf.len() => {
                println!("error: child device process incorrect recv size: got {}, expected {}",
                         c,
                         buf.len());
                break;
            }
            Err(e) => {
                println!("error: child device process failed recv: {}", e);
                break;
            }
            _ => {}
        }

        let cmd = NativeEndian::read_u32(&buf[0..]);
        let len = NativeEndian::read_u32(&buf[4..]) as usize;
        let offset = NativeEndian::read_u64(&buf[8..]);

        let res = if cmd == Command::Read as u32 {
            device.read(offset, &mut buf[16..16 + len]);
            handle_intr!(sock.send(&buf))
        } else if cmd == Command::Write as u32 {
            device.write(offset, &buf[16..16 + len]);
            handle_intr!(sock.send(&buf))
        } else if cmd == Command::Shutdown as u32 {
            running = false;
            handle_intr!(sock.send(&buf))
        } else {
            println!("child device process unknown command: {}", cmd);
            break;
        };

        if let Err(e) = res {
            println!("error: child device process failed send: {}", e);
            break;
        }
    }

    // ! Never returns
    process::exit(0);
}

/// Wraps an inner `hw::BusDevice` that is run inside a child process via fork.
///
/// Because forks are very unfriendly to destructors and all memory mappings and file descriptors
/// are inherited, this should be used as early as possible in the main process.
pub struct ProxyDevice {
    sock: UnixDatagram,
}

impl ProxyDevice {
    /// Takes the given device and isolates it into another process via fork before returning.
    ///
    /// The forked process will automatically be terminated when this is dropped, so be sure to keep
    /// a reference.
    pub fn new<D: BusDevice>(mut device: D) -> Result<ProxyDevice> {
        let (child_sock, parent_sock) = UnixDatagram::pair()?;

        let ret = unsafe { fork() };
        if ret == 0 {
            // ! Never returns
            child_proc(child_sock, &mut device);
        } else if ret == -1 {
            return Err(Error::last_os_error());
        }

        let mut buf = [0; MSG_SIZE];
        parent_sock
            .set_write_timeout(Some(Duration::from_millis(SOCKET_TIMEOUT_MS)))?;
        parent_sock
            .set_read_timeout(Some(Duration::from_millis(SOCKET_TIMEOUT_MS)))?;
        handle_intr!(parent_sock.recv(&mut buf))?;
        assert_eq!(buf, CHILD_SIGNATURE);
        Ok(ProxyDevice { sock: parent_sock })
    }

    fn send_cmd(&self, cmd: Command, offset: u64, len: u32, data: &[u8]) -> Result<()> {
        let mut buf = [0; MSG_SIZE];
        NativeEndian::write_u32(&mut buf[0..], cmd as u32);
        NativeEndian::write_u32(&mut buf[4..], len);
        NativeEndian::write_u64(&mut buf[8..], offset);
        buf[16..16 + data.len()].clone_from_slice(data);
        handle_intr!(self.sock.send(&buf)).map(|_| ())
    }

    fn recv_resp(&self, data: &mut [u8]) -> Result<()> {
        let mut buf = [0; MSG_SIZE];
        handle_intr!(self.sock.recv(&mut buf))?;
        let len = data.len();
        data.clone_from_slice(&buf[16..16 + len]);
        Ok(())
    }

    fn wait(&self) -> Result<()> {
        let mut buf = [0; MSG_SIZE];
        handle_intr!(self.sock.recv(&mut buf)).map(|_| ())
    }
}

impl BusDevice for ProxyDevice {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        let res = self.send_cmd(Command::Read, offset, data.len() as u32, &[])
            .and_then(|_| self.recv_resp(data));
        if let Err(e) = res {
            println!("error: failed read from child device process: {}", e);
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        let res = self.send_cmd(Command::Write, offset, data.len() as u32, data)
            .and_then(|_| self.wait());
        if let Err(e) = res {
            println!("error: failed write to child device process: {}", e);
        }
    }
}

impl Drop for ProxyDevice {
    fn drop(&mut self) {
        let res = self.send_cmd(Command::Shutdown, 0, 0, &[]);
        if let Err(e) = res {
            println!("error: failed to shutdown child device process: {}", e);
        }
    }
}

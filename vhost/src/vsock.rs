// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libc;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};

use sys_util::{ioctl_with_ref, GuestMemory};
use virtio_sys::{VHOST_VSOCK_SET_GUEST_CID, VHOST_VSOCK_SET_RUNNING};

use super::{ioctl_result, Error, Result, Vhost};

static DEVICE: &'static str = "/dev/vhost-vsock";

/// Handle for running VHOST_VSOCK ioctls.
pub struct Vsock {
    fd: File,
    mem: GuestMemory,
}

impl Vsock {
    /// Open a handle to a new VHOST_VSOCK instance.
    pub fn new(mem: &GuestMemory) -> Result<Vsock> {
        Ok(Vsock {
            fd: OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(DEVICE)
                .map_err(Error::VhostOpen)?,
            mem: mem.clone(),
        })
    }

    /// Set the CID for the guest.  This number is used for routing all data destined for
    /// programs
    /// running in the guest.
    ///
    /// # Arguments
    /// * `cid` - CID to assign to the guest
    pub fn set_cid(&self, cid: u64) -> Result<()> {
        let ret = unsafe { ioctl_with_ref(&self.fd, VHOST_VSOCK_SET_GUEST_CID(), &cid) };
        if ret < 0 {
            return ioctl_result();
        }
        Ok(())
    }

    /// Tell the VHOST driver to start performing data transfer.
    pub fn start(&self) -> Result<()> {
        self.set_running(true)
    }

    /// Tell the VHOST driver to stop performing data transfer.
    pub fn stop(&self) -> Result<()> {
        self.set_running(false)
    }

    fn set_running(&self, running: bool) -> Result<()> {
        let on: ::std::os::raw::c_int = if running { 1 } else { 0 };
        let ret = unsafe { ioctl_with_ref(&self.fd, VHOST_VSOCK_SET_RUNNING(), &on) };

        if ret < 0 {
            return ioctl_result();
        }
        Ok(())
    }
}

impl Vhost for Vsock {
    fn mem(&self) -> &GuestMemory {
        &self.mem
    }
}

impl AsRawFd for Vsock {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

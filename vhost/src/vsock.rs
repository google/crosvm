// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;

use base::ioctl_with_ref;
use base::AsRawDescriptor;
use base::RawDescriptor;
use virtio_sys::VHOST_VSOCK_SET_GUEST_CID;
use virtio_sys::VHOST_VSOCK_SET_RUNNING;

use super::ioctl_result;
use super::Result;
use super::Vhost;

/// Handle for running VHOST_VSOCK ioctls.
pub struct Vsock {
    descriptor: File,
}

impl Vsock {
    /// Open a handle to a new VHOST_VSOCK instance.
    pub fn new(vhost_vsock_file: File) -> Vsock {
        Vsock {
            descriptor: vhost_vsock_file,
        }
    }

    /// Set the CID for the guest.  This number is used for routing all data destined for
    /// programs
    /// running in the guest.
    ///
    /// # Arguments
    /// * `cid` - CID to assign to the guest
    pub fn set_cid(&self, cid: u64) -> Result<()> {
        let ret = unsafe { ioctl_with_ref(&self.descriptor, VHOST_VSOCK_SET_GUEST_CID(), &cid) };
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
        let on = ::std::os::raw::c_int::from(running);
        let ret = unsafe { ioctl_with_ref(&self.descriptor, VHOST_VSOCK_SET_RUNNING(), &on) };

        if ret < 0 {
            return ioctl_result();
        }
        Ok(())
    }
}

impl Vhost for Vsock {}

impl AsRawDescriptor for Vsock {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.descriptor.as_raw_descriptor()
    }
}

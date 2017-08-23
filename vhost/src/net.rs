// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libc;
use net_util;
use std::ffi::CString;
use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use virtio_sys;

use sys_util::{ioctl_with_ref, Error as SysError, GuestMemory};

use super::{ioctl_result, Error, Result, Vhost};

static DEVICE: &'static str = "/dev/vhost-net";

/// Handle to run VHOST_NET ioctls.
///
/// This provides a simple wrapper around a VHOST_NET file descriptor and
/// methods that safely run ioctls on that file descriptor.
pub struct Net {
    // fd must be dropped first, which will stop and tear down the
    // vhost-net worker before GuestMemory can potentially be unmapped.
    fd: File,
    mem: GuestMemory,
}

impl Net {
    /// Opens /dev/vhost-net and holds a file descriptor open for it.
    ///
    /// # Arguments
    /// * `mem` - Guest memory mapping.
    pub fn new(mem: &GuestMemory) -> Result<Net> {
        // Open calls are safe because we give a constant nul-terminated
        // string and verify the result.  The CString unwrap is safe because
        // DEVICE does not have any embedded '\0' characters.
        let fd = unsafe {
            libc::open(CString::new(DEVICE).unwrap().as_ptr(),
                       libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC)
        };
        if fd < 0 {
            return Err(Error::VhostOpen(SysError::last()));
        }
        Ok(Net {
            // There are no other users of this fd, so this is safe.
            fd: unsafe { File::from_raw_fd(fd) },
            mem: mem.clone(),
        })
    }

    /// Set the tap file descriptor that will serve as the VHOST_NET backend.
    /// This will start the vhost worker for the given queue.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `fd` - Tap interface that will be used as the backend.
    pub fn set_backend(&self, queue_index: usize, fd: &net_util::Tap) -> Result<()> {
        let vring_file = virtio_sys::vhost_vring_file {
            index: queue_index as u32,
            fd: fd.as_raw_fd(),
        };

        // This ioctl is called on a valid vhost_net fd and has its
        // return value checked.
        let ret = unsafe {
            ioctl_with_ref(&self.fd,
                           virtio_sys::VHOST_NET_SET_BACKEND(),
                           &vring_file)
        };
        if ret < 0 {
            return ioctl_result();
        }
        Ok(())
    }
}

impl Vhost for Net {
    fn mem(&self) -> &GuestMemory {
        &self.mem
    }
}

impl AsRawFd for Net {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

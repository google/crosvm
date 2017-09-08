// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libc;
use net_util;
use std::ffi::CString;
use std::fs::File;
use std::io::Error as IoError;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use virtio_sys;

use sys_util::{ioctl_with_ref, GuestMemory};

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

pub trait NetT {
    /// Set the tap file descriptor that will serve as the VHOST_NET backend.
    /// This will start the vhost worker for the given queue.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `fd` - Tap interface that will be used as the backend.
    fn set_backend(&self, queue_index: usize, fd: &net_util::Tap) -> Result<()>;
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
            return Err(Error::VhostOpen(IoError::last_os_error()));
        }
        Ok(Net {
            // There are no other users of this fd, so this is safe.
            fd: unsafe { File::from_raw_fd(fd) },
            mem: mem.clone(),
        })
    }
}

impl NetT for Net {
    fn set_backend(&self, queue_index: usize, fd: &net_util::Tap) -> Result<()> {
        let vring_file = virtio_sys::vhost_vring_file {
            index: queue_index as u32,
            fd: fd.as_raw_fd(),
        };

        // This ioctl is called on a valid vhost_net fd and has its
        // return value checked.
        let ret =
            unsafe { ioctl_with_ref(&self.fd, virtio_sys::VHOST_NET_SET_BACKEND(), &vring_file) };
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::fs::remove_file;

    const TMP_FILE: &str = "/tmp/crosvm_vhost_test_file";

    pub struct FakeNet {
        fd: File,
        mem: GuestMemory,
    }

    impl FakeNet {
        pub fn new(mem: &GuestMemory) -> Result<FakeNet> {
            Ok(FakeNet {
                fd: OpenOptions::new()
                    .read(true)
                    .append(true)
                    .create(true)
                    .open(TMP_FILE)
                    .unwrap(),
                mem: mem.clone()
            })
        }
    }

    impl Drop for FakeNet {
        fn drop(&mut self) {
            let _ = remove_file(TMP_FILE);
        }
    }

    impl NetT for FakeNet {
        fn set_backend(&self, _queue_index: usize, _fd: &net_util::Tap) -> Result<()> {
            Ok(())
        }
    }

    impl Vhost for FakeNet {
        fn mem(&self) -> &GuestMemory {
            &self.mem
        }
    }

    impl AsRawFd for FakeNet {
        fn as_raw_fd(&self) -> RawFd {
            self.fd.as_raw_fd()
        }
    }
}

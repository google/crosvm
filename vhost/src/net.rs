// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libc;
use net_util::TapT;
use std::fs::{File, OpenOptions};
use std::marker::PhantomData;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use virtio_sys;

use sys_util::{ioctl_with_ref, GuestMemory};

use super::{ioctl_result, Error, Result, Vhost};

static DEVICE: &'static str = "/dev/vhost-net";

/// Handle to run VHOST_NET ioctls.
///
/// This provides a simple wrapper around a VHOST_NET file descriptor and
/// methods that safely run ioctls on that file descriptor.
pub struct Net<T> {
    // fd must be dropped first, which will stop and tear down the
    // vhost-net worker before GuestMemory can potentially be unmapped.
    fd: File,
    mem: GuestMemory,
    phantom: PhantomData<T>,
}

pub trait NetT<T: TapT>: Vhost + AsRawFd + Send + Sized {
    /// Create a new NetT instance
    fn new(mem: &GuestMemory) -> Result<Self>;

    /// Set the tap file descriptor that will serve as the VHOST_NET backend.
    /// This will start the vhost worker for the given queue.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `fd` - Tap interface that will be used as the backend.
    fn set_backend(&self, queue_index: usize, fd: &T) -> Result<()>;
}

impl<T> NetT<T> for Net<T>
where
    T: TapT,
{
    /// Opens /dev/vhost-net and holds a file descriptor open for it.
    ///
    /// # Arguments
    /// * `mem` - Guest memory mapping.
    fn new(mem: &GuestMemory) -> Result<Net<T>> {
        Ok(Net::<T> {
            fd: OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(DEVICE)
                .map_err(Error::VhostOpen)?,
            mem: mem.clone(),
            phantom: PhantomData,
        })
    }

    fn set_backend(&self, queue_index: usize, fd: &T) -> Result<()> {
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

impl<T> Vhost for Net<T> {
    fn mem(&self) -> &GuestMemory {
        &self.mem
    }
}

impl<T> AsRawFd for Net<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

pub mod fakes {
    use super::*;
    use std::fs::remove_file;
    use std::fs::OpenOptions;

    const TMP_FILE: &str = "/tmp/crosvm_vhost_test_file";

    pub struct FakeNet<T> {
        fd: File,
        mem: GuestMemory,
        phantom: PhantomData<T>,
    }

    impl<T> Drop for FakeNet<T> {
        fn drop(&mut self) {
            let _ = remove_file(TMP_FILE);
        }
    }

    impl<T> NetT<T> for FakeNet<T>
    where
        T: TapT,
    {
        fn new(mem: &GuestMemory) -> Result<FakeNet<T>> {
            Ok(FakeNet::<T> {
                fd: OpenOptions::new()
                    .read(true)
                    .append(true)
                    .create(true)
                    .open(TMP_FILE)
                    .unwrap(),
                mem: mem.clone(),
                phantom: PhantomData,
            })
        }

        fn set_backend(&self, _queue_index: usize, _fd: &T) -> Result<()> {
            Ok(())
        }
    }

    impl<T> Vhost for FakeNet<T> {
        fn mem(&self) -> &GuestMemory {
            &self.mem
        }
    }

    impl<T> AsRawFd for FakeNet<T> {
        fn as_raw_fd(&self) -> RawFd {
            self.fd.as_raw_fd()
        }
    }
}

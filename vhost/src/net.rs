// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::fs::OpenOptions;
use std::marker::PhantomData;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use base::ioctl_with_ref;
use base::AsRawDescriptor;
use base::RawDescriptor;
use net_util::TapT;

use super::ioctl_result;
use super::Error;
use super::Result;
use super::Vhost;

/// Handle to run VHOST_NET ioctls.
///
/// This provides a simple wrapper around a VHOST_NET file descriptor and
/// methods that safely run ioctls on that file descriptor.
pub struct Net<T> {
    // descriptor must be dropped first, which will stop and tear down the
    // vhost-net worker before GuestMemory can potentially be unmapped.
    descriptor: File,
    phantom: PhantomData<T>,
}

pub trait NetT<T: TapT>: Vhost + AsRawDescriptor + Send + Sized {
    /// Create a new NetT instance
    fn new(vhost_net_device_path: &Path) -> Result<Self>;

    /// Set the tap file descriptor that will serve as the VHOST_NET backend.
    /// This will start the vhost worker for the given queue.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `descriptor` - Tap interface that will be used as the backend.
    fn set_backend(&self, queue_index: usize, descriptor: Option<&T>) -> Result<()>;
}

impl<T> NetT<T> for Net<T>
where
    T: TapT,
{
    /// Opens /dev/vhost-net and holds a file descriptor open for it.
    ///
    /// # Arguments
    /// * `mem` - Guest memory mapping.
    fn new(vhost_net_device_path: &Path) -> Result<Net<T>> {
        Ok(Net::<T> {
            descriptor: OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(vhost_net_device_path)
                .map_err(Error::VhostOpen)?,
            phantom: PhantomData,
        })
    }

    fn set_backend(&self, queue_index: usize, event: Option<&T>) -> Result<()> {
        let vring_file = virtio_sys::vhost::vhost_vring_file {
            index: queue_index as u32,
            fd: event.map_or(-1, |event| event.as_raw_descriptor()),
        };

        // SAFETY:
        // This ioctl is called on a valid vhost_net descriptor and has its
        // return value checked.
        let ret = unsafe {
            ioctl_with_ref(
                &self.descriptor,
                virtio_sys::VHOST_NET_SET_BACKEND(),
                &vring_file,
            )
        };
        if ret < 0 {
            return ioctl_result();
        }
        Ok(())
    }
}

impl<T> Vhost for Net<T> {}

impl<T> AsRawDescriptor for Net<T> {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.descriptor.as_raw_descriptor()
    }
}

pub mod fakes {
    use std::fs::remove_file;
    use std::fs::OpenOptions;

    use super::*;

    const TMP_FILE: &str = "/tmp/crosvm_vhost_test_file";

    pub struct FakeNet<T> {
        descriptor: File,
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
        fn new(_vhost_net_device_path: &Path) -> Result<FakeNet<T>> {
            Ok(FakeNet::<T> {
                descriptor: OpenOptions::new()
                    .read(true)
                    .append(true)
                    .create(true)
                    .open(TMP_FILE)
                    .unwrap(),
                phantom: PhantomData,
            })
        }

        fn set_backend(&self, _queue_index: usize, _fd: Option<&T>) -> Result<()> {
            Ok(())
        }
    }

    impl<T> Vhost for FakeNet<T> {}

    impl<T> AsRawDescriptor for FakeNet<T> {
        fn as_raw_descriptor(&self) -> RawDescriptor {
            self.descriptor.as_raw_descriptor()
        }
    }
}

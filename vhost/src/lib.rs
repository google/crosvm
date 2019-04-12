// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod net;
mod vsock;

pub use crate::net::Net;
pub use crate::net::NetT;
pub use crate::vsock::Vsock;

use std::alloc::Layout;
use std::fmt::{self, Display};
use std::io::Error as IoError;
use std::mem;
use std::os::unix::io::AsRawFd;
use std::ptr::null;

use assertions::const_assert;
use sys_util::{ioctl, ioctl_with_mut_ref, ioctl_with_ptr, ioctl_with_ref};
use sys_util::{EventFd, GuestAddress, GuestMemory, GuestMemoryError, LayoutAllocation};

#[derive(Debug)]
pub enum Error {
    /// Error opening vhost device.
    VhostOpen(IoError),
    /// Error while running ioctl.
    IoctlError(IoError),
    /// Invalid queue.
    InvalidQueue,
    /// Invalid descriptor table address.
    DescriptorTableAddress(GuestMemoryError),
    /// Invalid used address.
    UsedAddress(GuestMemoryError),
    /// Invalid available address.
    AvailAddress(GuestMemoryError),
    /// Invalid log address.
    LogAddress(GuestMemoryError),
}
pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            VhostOpen(e) => write!(f, "failed to open vhost device: {}", e),
            IoctlError(e) => write!(f, "failed to run ioctl: {}", e),
            InvalidQueue => write!(f, "invalid queue"),
            DescriptorTableAddress(e) => write!(f, "invalid descriptor table address: {}", e),
            UsedAddress(e) => write!(f, "invalid used address: {}", e),
            AvailAddress(e) => write!(f, "invalid available address: {}", e),
            LogAddress(e) => write!(f, "invalid log address: {}", e),
        }
    }
}

fn ioctl_result<T>() -> Result<T> {
    Err(Error::IoctlError(IoError::last_os_error()))
}

/// An interface for setting up vhost-based virtio devices.  Vhost-based devices are different
/// from regular virtio devices because the host kernel takes care of handling all the data
/// transfer.  The device itself only needs to deal with setting up the kernel driver and
/// managing the control channel.
pub trait Vhost: AsRawFd + std::marker::Sized {
    /// Get the guest memory mapping.
    fn mem(&self) -> &GuestMemory;

    /// Set the current process as the owner of this file descriptor.
    /// This must be run before any other vhost ioctls.
    fn set_owner(&self) -> Result<()> {
        // This ioctl is called on a valid vhost_net fd and has its
        // return value checked.
        let ret = unsafe { ioctl(self, virtio_sys::VHOST_SET_OWNER()) };
        if ret < 0 {
            return ioctl_result();
        }
        Ok(())
    }

    /// Get a bitmask of supported virtio/vhost features.
    fn get_features(&self) -> Result<u64> {
        let mut avail_features: u64 = 0;
        // This ioctl is called on a valid vhost_net fd and has its
        // return value checked.
        let ret = unsafe {
            ioctl_with_mut_ref(self, virtio_sys::VHOST_GET_FEATURES(), &mut avail_features)
        };
        if ret < 0 {
            return ioctl_result();
        }
        Ok(avail_features)
    }

    /// Inform the vhost subsystem which features to enable. This should be a subset of
    /// supported features from VHOST_GET_FEATURES.
    ///
    /// # Arguments
    /// * `features` - Bitmask of features to set.
    fn set_features(&self, features: u64) -> Result<()> {
        // This ioctl is called on a valid vhost_net fd and has its
        // return value checked.
        let ret = unsafe { ioctl_with_ref(self, virtio_sys::VHOST_SET_FEATURES(), &features) };
        if ret < 0 {
            return ioctl_result();
        }
        Ok(())
    }

    /// Set the guest memory mappings for vhost to use.
    fn set_mem_table(&self) -> Result<()> {
        const SIZE_OF_MEMORY: usize = mem::size_of::<virtio_sys::vhost_memory>();
        const SIZE_OF_REGION: usize = mem::size_of::<virtio_sys::vhost_memory_region>();
        const ALIGN_OF_MEMORY: usize = mem::align_of::<virtio_sys::vhost_memory>();
        const ALIGN_OF_REGION: usize = mem::align_of::<virtio_sys::vhost_memory_region>();
        const_assert!(ALIGN_OF_MEMORY >= ALIGN_OF_REGION);

        let num_regions = self.mem().num_regions() as usize;
        let size = SIZE_OF_MEMORY + num_regions * SIZE_OF_REGION;
        let layout = Layout::from_size_align(size, ALIGN_OF_MEMORY).expect("impossible layout");
        let mut allocation = LayoutAllocation::zeroed(layout);

        // Safe to obtain an exclusive reference because there are no other
        // references to the allocation yet and all-zero is a valid bit pattern.
        let vhost_memory = unsafe { allocation.as_mut::<virtio_sys::vhost_memory>() };

        vhost_memory.nregions = num_regions as u32;
        // regions is a zero-length array, so taking a mut slice requires that
        // we correctly specify the size to match the amount of backing memory.
        let vhost_regions = unsafe { vhost_memory.regions.as_mut_slice(num_regions as usize) };

        let _ = self
            .mem()
            .with_regions::<_, ()>(|index, guest_addr, size, host_addr, _| {
                vhost_regions[index] = virtio_sys::vhost_memory_region {
                    guest_phys_addr: guest_addr.offset() as u64,
                    memory_size: size as u64,
                    userspace_addr: host_addr as u64,
                    flags_padding: 0u64,
                };
                Ok(())
            });

        // This ioctl is called with a pointer that is valid for the lifetime
        // of this function. The kernel will make its own copy of the memory
        // tables. As always, check the return value.
        let ret = unsafe { ioctl_with_ptr(self, virtio_sys::VHOST_SET_MEM_TABLE(), vhost_memory) };
        if ret < 0 {
            return ioctl_result();
        }

        Ok(())

        // vhost_memory allocation is deallocated.
    }

    /// Set the number of descriptors in the vring.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to set descriptor count for.
    /// * `num` - Number of descriptors in the queue.
    fn set_vring_num(&self, queue_index: usize, num: u16) -> Result<()> {
        let vring_state = virtio_sys::vhost_vring_state {
            index: queue_index as u32,
            num: num as u32,
        };

        // This ioctl is called on a valid vhost_net fd and has its
        // return value checked.
        let ret = unsafe { ioctl_with_ref(self, virtio_sys::VHOST_SET_VRING_NUM(), &vring_state) };
        if ret < 0 {
            return ioctl_result();
        }
        Ok(())
    }

    // TODO(smbarber): This is copypasta. Eliminate the copypasta.
    #[allow(clippy::if_same_then_else)]
    fn is_valid(
        &self,
        queue_max_size: u16,
        queue_size: u16,
        desc_addr: GuestAddress,
        avail_addr: GuestAddress,
        used_addr: GuestAddress,
    ) -> bool {
        let desc_table_size = 16 * queue_size as usize;
        let avail_ring_size = 6 + 2 * queue_size as usize;
        let used_ring_size = 6 + 8 * queue_size as usize;
        if queue_size > queue_max_size || queue_size == 0 || (queue_size & (queue_size - 1)) != 0 {
            false
        } else if desc_addr
            .checked_add(desc_table_size as u64)
            .map_or(true, |v| !self.mem().address_in_range(v))
        {
            false
        } else if avail_addr
            .checked_add(avail_ring_size as u64)
            .map_or(true, |v| !self.mem().address_in_range(v))
        {
            false
        } else if used_addr
            .checked_add(used_ring_size as u64)
            .map_or(true, |v| !self.mem().address_in_range(v))
        {
            false
        } else {
            true
        }
    }

    /// Set the addresses for a given vring.
    ///
    /// # Arguments
    /// * `queue_max_size` - Maximum queue size supported by the device.
    /// * `queue_size` - Actual queue size negotiated by the driver.
    /// * `queue_index` - Index of the queue to set addresses for.
    /// * `flags` - Bitmask of vring flags.
    /// * `desc_addr` - Descriptor table address.
    /// * `used_addr` - Used ring buffer address.
    /// * `avail_addr` - Available ring buffer address.
    /// * `log_addr` - Optional address for logging.
    fn set_vring_addr(
        &self,
        queue_max_size: u16,
        queue_size: u16,
        queue_index: usize,
        flags: u32,
        desc_addr: GuestAddress,
        used_addr: GuestAddress,
        avail_addr: GuestAddress,
        log_addr: Option<GuestAddress>,
    ) -> Result<()> {
        // TODO(smbarber): Refactor out virtio from crosvm so we can
        // validate a Queue struct directly.
        if !self.is_valid(queue_max_size, queue_size, desc_addr, used_addr, avail_addr) {
            return Err(Error::InvalidQueue);
        }

        let desc_addr = self
            .mem()
            .get_host_address(desc_addr)
            .map_err(Error::DescriptorTableAddress)?;
        let used_addr = self
            .mem()
            .get_host_address(used_addr)
            .map_err(Error::UsedAddress)?;
        let avail_addr = self
            .mem()
            .get_host_address(avail_addr)
            .map_err(Error::AvailAddress)?;
        let log_addr = match log_addr {
            None => null(),
            Some(a) => self.mem().get_host_address(a).map_err(Error::LogAddress)?,
        };

        let vring_addr = virtio_sys::vhost_vring_addr {
            index: queue_index as u32,
            flags,
            desc_user_addr: desc_addr as u64,
            used_user_addr: used_addr as u64,
            avail_user_addr: avail_addr as u64,
            log_guest_addr: log_addr as u64,
        };

        // This ioctl is called on a valid vhost_net fd and has its
        // return value checked.
        let ret = unsafe { ioctl_with_ref(self, virtio_sys::VHOST_SET_VRING_ADDR(), &vring_addr) };
        if ret < 0 {
            return ioctl_result();
        }
        Ok(())
    }

    /// Set the first index to look for available descriptors.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `num` - Index where available descriptors start.
    fn set_vring_base(&self, queue_index: usize, num: u16) -> Result<()> {
        let vring_state = virtio_sys::vhost_vring_state {
            index: queue_index as u32,
            num: num as u32,
        };

        // This ioctl is called on a valid vhost_net fd and has its
        // return value checked.
        let ret = unsafe { ioctl_with_ref(self, virtio_sys::VHOST_SET_VRING_BASE(), &vring_state) };
        if ret < 0 {
            return ioctl_result();
        }
        Ok(())
    }

    /// Set the eventfd to trigger when buffers have been used by the host.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `fd` - EventFd to trigger.
    fn set_vring_call(&self, queue_index: usize, fd: &EventFd) -> Result<()> {
        let vring_file = virtio_sys::vhost_vring_file {
            index: queue_index as u32,
            fd: fd.as_raw_fd(),
        };

        // This ioctl is called on a valid vhost_net fd and has its
        // return value checked.
        let ret = unsafe { ioctl_with_ref(self, virtio_sys::VHOST_SET_VRING_CALL(), &vring_file) };
        if ret < 0 {
            return ioctl_result();
        }
        Ok(())
    }

    /// Set the eventfd that will be signaled by the guest when buffers are
    /// available for the host to process.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `fd` - EventFd that will be signaled from guest.
    fn set_vring_kick(&self, queue_index: usize, fd: &EventFd) -> Result<()> {
        let vring_file = virtio_sys::vhost_vring_file {
            index: queue_index as u32,
            fd: fd.as_raw_fd(),
        };

        // This ioctl is called on a valid vhost_net fd and has its
        // return value checked.
        let ret = unsafe { ioctl_with_ref(self, virtio_sys::VHOST_SET_VRING_KICK(), &vring_file) };
        if ret < 0 {
            return ioctl_result();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::net::fakes::FakeNet;
    use net_util::fakes::FakeTap;
    use std::result;
    use sys_util::{GuestAddress, GuestMemory, GuestMemoryError};

    fn create_guest_memory() -> result::Result<GuestMemory, GuestMemoryError> {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        GuestMemory::new(&vec![(start_addr1, 0x1000), (start_addr2, 0x4000)])
    }

    fn assert_ok_or_known_failure<T>(res: Result<T>) {
        match &res {
            // FakeNet won't respond to ioctl's
            Ok(_t) => {}
            Err(Error::IoctlError(ioe)) if ioe.raw_os_error().unwrap() == 25 => {}
            Err(e) => panic!("Unexpected Error:\n{}", e),
        }
    }

    fn create_fake_vhost_net() -> FakeNet<FakeTap> {
        let gm = create_guest_memory().unwrap();
        FakeNet::<FakeTap>::new(&gm).unwrap()
    }

    #[test]
    fn test_create_fake_vhost_net() {
        create_fake_vhost_net();
    }

    #[test]
    fn set_owner() {
        let vhost_net = create_fake_vhost_net();
        let res = vhost_net.set_owner();
        assert_ok_or_known_failure(res);
    }

    #[test]
    fn get_features() {
        let vhost_net = create_fake_vhost_net();
        let res = vhost_net.get_features();
        assert_ok_or_known_failure(res);
    }

    #[test]
    fn set_features() {
        let vhost_net = create_fake_vhost_net();
        let res = vhost_net.set_features(0);
        assert_ok_or_known_failure(res);
    }

    #[test]
    fn set_mem_table() {
        let vhost_net = create_fake_vhost_net();
        let res = vhost_net.set_mem_table();
        assert_ok_or_known_failure(res);
    }

    #[test]
    fn set_vring_num() {
        let vhost_net = create_fake_vhost_net();
        let res = vhost_net.set_vring_num(0, 1);
        assert_ok_or_known_failure(res);
    }

    #[test]
    fn set_vring_addr() {
        let vhost_net = create_fake_vhost_net();
        let res = vhost_net.set_vring_addr(
            1,
            1,
            0,
            0x0,
            GuestAddress(0x0),
            GuestAddress(0x0),
            GuestAddress(0x0),
            None,
        );
        assert_ok_or_known_failure(res);
    }

    #[test]
    fn set_vring_base() {
        let vhost_net = create_fake_vhost_net();
        let res = vhost_net.set_vring_base(0, 1);
        assert_ok_or_known_failure(res);
    }

    #[test]
    fn set_vring_call() {
        let vhost_net = create_fake_vhost_net();
        let res = vhost_net.set_vring_call(0, &EventFd::new().unwrap());
        assert_ok_or_known_failure(res);
    }

    #[test]
    fn set_vring_kick() {
        let vhost_net = create_fake_vhost_net();
        let res = vhost_net.set_vring_kick(0, &EventFd::new().unwrap());
        assert_ok_or_known_failure(res);
    }
}

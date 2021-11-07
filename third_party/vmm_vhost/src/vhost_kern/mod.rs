// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-Google file.

//! Traits and structs to control Linux in-kernel vhost drivers.
//!
//! The initial vhost implementation is a part of the Linux kernel and uses ioctl interface to
//! communicate with userspace applications. This sub module provides ioctl based interfaces to
//! control the in-kernel net, scsi, vsock vhost drivers.

use std::os::unix::io::{AsRawFd, RawFd};

use sys_util::ioctl::{ioctl, ioctl_with_mut_ref, ioctl_with_ptr, ioctl_with_ref};
use sys_util::EventFd;
use vm_memory::{Address, GuestAddress, GuestAddressSpace, GuestMemory, GuestUsize};

use super::{
    Error, Result, VhostBackend, VhostUserMemoryRegionInfo, VringConfigData,
    VHOST_MAX_MEMORY_REGIONS,
};

pub mod vhost_binding;
use self::vhost_binding::*;

#[cfg(feature = "vhost-vsock")]
pub mod vsock;

#[inline]
fn ioctl_result<T>(rc: i32, res: T) -> Result<T> {
    if rc < 0 {
        Err(Error::IoctlError(std::io::Error::last_os_error()))
    } else {
        Ok(res)
    }
}

/// Represent an in-kernel vhost device backend.
pub trait VhostKernBackend: AsRawFd {
    /// Associated type to access guest memory.
    type AS: GuestAddressSpace;

    /// Get the object to access the guest's memory.
    fn mem(&self) -> &Self::AS;

    /// Check whether the ring configuration is valid.
    fn is_valid(&self, config_data: &VringConfigData) -> bool {
        let queue_size = config_data.queue_size;
        if queue_size > config_data.queue_max_size
            || queue_size == 0
            || (queue_size & (queue_size - 1)) != 0
        {
            return false;
        }

        let m = self.mem().memory();
        let desc_table_size = 16 * u64::from(queue_size) as GuestUsize;
        let avail_ring_size = 6 + 2 * u64::from(queue_size) as GuestUsize;
        let used_ring_size = 6 + 8 * u64::from(queue_size) as GuestUsize;
        if GuestAddress(config_data.desc_table_addr)
            .checked_add(desc_table_size)
            .map_or(true, |v| !m.address_in_range(v))
        {
            return false;
        }
        if GuestAddress(config_data.avail_ring_addr)
            .checked_add(avail_ring_size)
            .map_or(true, |v| !m.address_in_range(v))
        {
            return false;
        }
        if GuestAddress(config_data.used_ring_addr)
            .checked_add(used_ring_size)
            .map_or(true, |v| !m.address_in_range(v))
        {
            return false;
        }

        config_data.is_log_addr_valid()
    }
}

impl<T: VhostKernBackend> VhostBackend for T {
    /// Get a bitmask of supported virtio/vhost features.
    fn get_features(&self) -> Result<u64> {
        let mut avail_features: u64 = 0;
        // This ioctl is called on a valid vhost fd and has its return value checked.
        let ret = unsafe { ioctl_with_mut_ref(self, VHOST_GET_FEATURES(), &mut avail_features) };
        ioctl_result(ret, avail_features)
    }

    /// Inform the vhost subsystem which features to enable. This should be a subset of
    /// supported features from VHOST_GET_FEATURES.
    ///
    /// # Arguments
    /// * `features` - Bitmask of features to set.
    fn set_features(&self, features: u64) -> Result<()> {
        // This ioctl is called on a valid vhost fd and has its return value checked.
        let ret = unsafe { ioctl_with_ref(self, VHOST_SET_FEATURES(), &features) };
        ioctl_result(ret, ())
    }

    /// Set the current process as the owner of this file descriptor.
    /// This must be run before any other vhost ioctls.
    fn set_owner(&self) -> Result<()> {
        // This ioctl is called on a valid vhost fd and has its return value checked.
        let ret = unsafe { ioctl(self, VHOST_SET_OWNER()) };
        ioctl_result(ret, ())
    }

    fn reset_owner(&self) -> Result<()> {
        // This ioctl is called on a valid vhost fd and has its return value checked.
        let ret = unsafe { ioctl(self, VHOST_RESET_OWNER()) };
        ioctl_result(ret, ())
    }

    /// Set the guest memory mappings for vhost to use.
    fn set_mem_table(&self, regions: &[VhostUserMemoryRegionInfo]) -> Result<()> {
        if regions.is_empty() || regions.len() > VHOST_MAX_MEMORY_REGIONS {
            return Err(Error::InvalidGuestMemory);
        }

        let mut vhost_memory = VhostMemory::new(regions.len() as u16);
        for (index, region) in regions.iter().enumerate() {
            vhost_memory.set_region(
                index as u32,
                &vhost_memory_region {
                    guest_phys_addr: region.guest_phys_addr,
                    memory_size: region.memory_size,
                    userspace_addr: region.userspace_addr,
                    flags_padding: 0u64,
                },
            )?;
        }

        // This ioctl is called with a pointer that is valid for the lifetime
        // of this function. The kernel will make its own copy of the memory
        // tables. As always, check the return value.
        let ret = unsafe { ioctl_with_ptr(self, VHOST_SET_MEM_TABLE(), vhost_memory.as_ptr()) };
        ioctl_result(ret, ())
    }

    /// Set base address for page modification logging.
    ///
    /// # Arguments
    /// * `base` - Base address for page modification logging.
    fn set_log_base(&self, base: u64, fd: Option<RawFd>) -> Result<()> {
        if fd.is_some() {
            return Err(Error::LogAddress);
        }

        // This ioctl is called on a valid vhost fd and has its return value checked.
        let ret = unsafe { ioctl_with_ref(self, VHOST_SET_LOG_BASE(), &base) };
        ioctl_result(ret, ())
    }

    /// Specify an eventfd file descriptor to signal on log write.
    fn set_log_fd(&self, fd: RawFd) -> Result<()> {
        // This ioctl is called on a valid vhost fd and has its return value checked.
        let val: i32 = fd;
        let ret = unsafe { ioctl_with_ref(self, VHOST_SET_LOG_FD(), &val) };
        ioctl_result(ret, ())
    }

    /// Set the number of descriptors in the vring.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to set descriptor count for.
    /// * `num` - Number of descriptors in the queue.
    fn set_vring_num(&self, queue_index: usize, num: u16) -> Result<()> {
        let vring_state = vhost_vring_state {
            index: queue_index as u32,
            num: u32::from(num),
        };

        // This ioctl is called on a valid vhost fd and has its return value checked.
        let ret = unsafe { ioctl_with_ref(self, VHOST_SET_VRING_NUM(), &vring_state) };
        ioctl_result(ret, ())
    }

    /// Set the addresses for a given vring.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to set addresses for.
    /// * `config_data` - Vring config data.
    fn set_vring_addr(&self, queue_index: usize, config_data: &VringConfigData) -> Result<()> {
        if !self.is_valid(config_data) {
            return Err(Error::InvalidQueue);
        }

        let vring_addr = vhost_vring_addr {
            index: queue_index as u32,
            flags: config_data.flags,
            desc_user_addr: config_data.desc_table_addr,
            used_user_addr: config_data.used_ring_addr,
            avail_user_addr: config_data.avail_ring_addr,
            log_guest_addr: config_data.get_log_addr(),
        };

        // This ioctl is called on a valid vhost fd and has its
        // return value checked.
        let ret = unsafe { ioctl_with_ref(self, VHOST_SET_VRING_ADDR(), &vring_addr) };
        ioctl_result(ret, ())
    }

    /// Set the first index to look for available descriptors.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `num` - Index where available descriptors start.
    fn set_vring_base(&self, queue_index: usize, base: u16) -> Result<()> {
        let vring_state = vhost_vring_state {
            index: queue_index as u32,
            num: u32::from(base),
        };

        // This ioctl is called on a valid vhost fd and has its return value checked.
        let ret = unsafe { ioctl_with_ref(self, VHOST_SET_VRING_BASE(), &vring_state) };
        ioctl_result(ret, ())
    }

    /// Get a bitmask of supported virtio/vhost features.
    fn get_vring_base(&self, queue_index: usize) -> Result<u32> {
        let vring_state = vhost_vring_state {
            index: queue_index as u32,
            num: 0,
        };
        // This ioctl is called on a valid vhost fd and has its return value checked.
        let ret = unsafe { ioctl_with_ref(self, VHOST_GET_VRING_BASE(), &vring_state) };
        ioctl_result(ret, vring_state.num)
    }

    /// Set the eventfd to trigger when buffers have been used by the host.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `fd` - EventFd to trigger.
    fn set_vring_call(&self, queue_index: usize, fd: &EventFd) -> Result<()> {
        let vring_file = vhost_vring_file {
            index: queue_index as u32,
            fd: fd.as_raw_fd(),
        };

        // This ioctl is called on a valid vhost fd and has its return value checked.
        let ret = unsafe { ioctl_with_ref(self, VHOST_SET_VRING_CALL(), &vring_file) };
        ioctl_result(ret, ())
    }

    /// Set the eventfd that will be signaled by the guest when buffers are
    /// available for the host to process.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `fd` - EventFd that will be signaled from guest.
    fn set_vring_kick(&self, queue_index: usize, fd: &EventFd) -> Result<()> {
        let vring_file = vhost_vring_file {
            index: queue_index as u32,
            fd: fd.as_raw_fd(),
        };

        // This ioctl is called on a valid vhost fd and has its return value checked.
        let ret = unsafe { ioctl_with_ref(self, VHOST_SET_VRING_KICK(), &vring_file) };
        ioctl_result(ret, ())
    }

    /// Set the eventfd to signal an error from the vhost backend.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `fd` - EventFd that will be signaled from the backend.
    fn set_vring_err(&self, queue_index: usize, fd: &EventFd) -> Result<()> {
        let vring_file = vhost_vring_file {
            index: queue_index as u32,
            fd: fd.as_raw_fd(),
        };

        // This ioctl is called on a valid vhost fd and has its return value checked.
        let ret = unsafe { ioctl_with_ref(self, VHOST_SET_VRING_ERR(), &vring_file) };
        ioctl_result(ret, ())
    }
}

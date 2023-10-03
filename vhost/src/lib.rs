// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Linux vhost kernel API wrapper.

#![cfg(any(target_os = "android", target_os = "linux"))]

pub mod net;
#[cfg(any(target_os = "android", target_os = "linux"))]
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
mod scmi;
mod vsock;

use std::alloc::Layout;
use std::io::Error as IoError;
use std::ptr::null;

use base::ioctl;
use base::ioctl_with_mut_ref;
use base::ioctl_with_ptr;
use base::ioctl_with_ref;
use base::AsRawDescriptor;
use base::Event;
use base::LayoutAllocation;
use remain::sorted;
use static_assertions::const_assert;
use thiserror::Error;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use vm_memory::GuestMemoryError;

#[cfg(any(target_os = "android", target_os = "linux"))]
pub use crate::net::Net;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use crate::net::NetT;
#[cfg(any(target_os = "android", target_os = "linux"))]
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub use crate::scmi::Scmi;
pub use crate::vsock::Vsock;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    /// Invalid available address.
    #[error("invalid available address: {0}")]
    AvailAddress(GuestMemoryError),
    /// Invalid descriptor table address.
    #[error("invalid descriptor table address: {0}")]
    DescriptorTableAddress(GuestMemoryError),
    /// Invalid queue.
    #[error("invalid queue")]
    InvalidQueue,
    /// Error while running ioctl.
    #[error("failed to run ioctl: {0}")]
    IoctlError(IoError),
    /// Invalid log address.
    #[error("invalid log address: {0}")]
    LogAddress(GuestMemoryError),
    /// Invalid used address.
    #[error("invalid used address: {0}")]
    UsedAddress(GuestMemoryError),
    /// Error opening vhost device.
    #[error("failed to open vhost device: {0}")]
    VhostOpen(IoError),
}

pub type Result<T> = std::result::Result<T, Error>;

fn ioctl_result<T>() -> Result<T> {
    Err(Error::IoctlError(IoError::last_os_error()))
}

/// An interface for setting up vhost-based virtio devices.  Vhost-based devices are different
/// from regular virtio devices because the host kernel takes care of handling all the data
/// transfer.  The device itself only needs to deal with setting up the kernel driver and
/// managing the control channel.
pub trait Vhost: AsRawDescriptor + std::marker::Sized {
    /// Set the current process as the owner of this file descriptor.
    /// This must be run before any other vhost ioctls.
    fn set_owner(&self) -> Result<()> {
        // This ioctl is called on a valid vhost_net descriptor and has its
        // return value checked.
        let ret = unsafe { ioctl(self, virtio_sys::VHOST_SET_OWNER()) };
        if ret < 0 {
            return ioctl_result();
        }
        Ok(())
    }

    /// Give up ownership and reset the device to default values. Allows a subsequent call to
    /// `set_owner` to succeed.
    fn reset_owner(&self) -> Result<()> {
        // This ioctl is called on a valid vhost fd and has its
        // return value checked.
        let ret = unsafe { ioctl(self, virtio_sys::VHOST_RESET_OWNER()) };
        if ret < 0 {
            return ioctl_result();
        }
        Ok(())
    }

    /// Get a bitmask of supported virtio/vhost features.
    fn get_features(&self) -> Result<u64> {
        let mut avail_features: u64 = 0;
        // This ioctl is called on a valid vhost_net descriptor and has its
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
        // This ioctl is called on a valid vhost_net descriptor and has its
        // return value checked.
        let ret = unsafe { ioctl_with_ref(self, virtio_sys::VHOST_SET_FEATURES(), &features) };
        if ret < 0 {
            return ioctl_result();
        }
        Ok(())
    }

    /// Set the guest memory mappings for vhost to use.
    fn set_mem_table(&self, mem: &GuestMemory) -> Result<()> {
        const SIZE_OF_MEMORY: usize = std::mem::size_of::<virtio_sys::vhost::vhost_memory>();
        const SIZE_OF_REGION: usize = std::mem::size_of::<virtio_sys::vhost::vhost_memory_region>();
        const ALIGN_OF_MEMORY: usize = std::mem::align_of::<virtio_sys::vhost::vhost_memory>();
        const_assert!(
            ALIGN_OF_MEMORY >= std::mem::align_of::<virtio_sys::vhost::vhost_memory_region>()
        );

        let num_regions = mem.num_regions() as usize;
        let size = SIZE_OF_MEMORY + num_regions * SIZE_OF_REGION;
        let layout = Layout::from_size_align(size, ALIGN_OF_MEMORY).expect("impossible layout");
        let mut allocation = LayoutAllocation::zeroed(layout);

        // Safe to obtain an exclusive reference because there are no other
        // references to the allocation yet and all-zero is a valid bit pattern.
        let vhost_memory = unsafe { allocation.as_mut::<virtio_sys::vhost::vhost_memory>() };

        vhost_memory.nregions = num_regions as u32;
        // regions is a zero-length array, so taking a mut slice requires that
        // we correctly specify the size to match the amount of backing memory.
        let vhost_regions = unsafe { vhost_memory.regions.as_mut_slice(num_regions) };

        for region in mem.regions() {
            vhost_regions[region.index] = virtio_sys::vhost::vhost_memory_region {
                guest_phys_addr: region.guest_addr.offset(),
                memory_size: region.size as u64,
                userspace_addr: region.host_addr as u64,
                flags_padding: 0u64,
            };
        }

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
        let vring_state = virtio_sys::vhost::vhost_vring_state {
            index: queue_index as u32,
            num: num as u32,
        };

        // This ioctl is called on a valid vhost_net descriptor and has its
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
        mem: &GuestMemory,
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
            .map_or(true, |v| !mem.address_in_range(v))
        {
            false
        } else if avail_addr
            .checked_add(avail_ring_size as u64)
            .map_or(true, |v| !mem.address_in_range(v))
        {
            false
        } else if used_addr
            .checked_add(used_ring_size as u64)
            .map_or(true, |v| !mem.address_in_range(v))
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
        mem: &GuestMemory,
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
        if !self.is_valid(
            mem,
            queue_max_size,
            queue_size,
            desc_addr,
            used_addr,
            avail_addr,
        ) {
            return Err(Error::InvalidQueue);
        }

        let desc_addr = mem
            .get_host_address(desc_addr)
            .map_err(Error::DescriptorTableAddress)?;
        let used_addr = mem
            .get_host_address(used_addr)
            .map_err(Error::UsedAddress)?;
        let avail_addr = mem
            .get_host_address(avail_addr)
            .map_err(Error::AvailAddress)?;
        let log_addr = match log_addr {
            None => null(),
            Some(a) => mem.get_host_address(a).map_err(Error::LogAddress)?,
        };

        let vring_addr = virtio_sys::vhost::vhost_vring_addr {
            index: queue_index as u32,
            flags,
            desc_user_addr: desc_addr as u64,
            used_user_addr: used_addr as u64,
            avail_user_addr: avail_addr as u64,
            log_guest_addr: log_addr as u64,
        };

        // This ioctl is called on a valid vhost_net descriptor and has its
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
        let vring_state = virtio_sys::vhost::vhost_vring_state {
            index: queue_index as u32,
            num: num as u32,
        };

        // This ioctl is called on a valid vhost_net descriptor and has its
        // return value checked.
        let ret = unsafe { ioctl_with_ref(self, virtio_sys::VHOST_SET_VRING_BASE(), &vring_state) };
        if ret < 0 {
            return ioctl_result();
        }
        Ok(())
    }

    /// Gets the index of the next available descriptor in the queue.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to query.
    fn get_vring_base(&self, queue_index: usize) -> Result<u16> {
        let mut vring_state = virtio_sys::vhost::vhost_vring_state {
            index: queue_index as u32,
            num: 0,
        };

        // Safe because this will only modify `vring_state` and we check the return value.
        let ret = unsafe {
            ioctl_with_mut_ref(self, virtio_sys::VHOST_GET_VRING_BASE(), &mut vring_state)
        };
        if ret < 0 {
            return ioctl_result();
        }

        Ok(vring_state.num as u16)
    }

    /// Set the event to trigger when buffers have been used by the host.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `event` - Event to trigger.
    fn set_vring_call(&self, queue_index: usize, event: &Event) -> Result<()> {
        let vring_file = virtio_sys::vhost::vhost_vring_file {
            index: queue_index as u32,
            fd: event.as_raw_descriptor(),
        };

        // This ioctl is called on a valid vhost_net descriptor and has its
        // return value checked.
        let ret = unsafe { ioctl_with_ref(self, virtio_sys::VHOST_SET_VRING_CALL(), &vring_file) };
        if ret < 0 {
            return ioctl_result();
        }
        Ok(())
    }

    /// Set the event to trigger to signal an error.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `event` - Event to trigger.
    fn set_vring_err(&self, queue_index: usize, event: &Event) -> Result<()> {
        let vring_file = virtio_sys::vhost::vhost_vring_file {
            index: queue_index as u32,
            fd: event.as_raw_descriptor(),
        };

        // This ioctl is called on a valid vhost_net fd and has its
        // return value checked.
        let ret = unsafe { ioctl_with_ref(self, virtio_sys::VHOST_SET_VRING_ERR(), &vring_file) };
        if ret < 0 {
            return ioctl_result();
        }
        Ok(())
    }

    /// Set the event that will be signaled by the guest when buffers are
    /// available for the host to process.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `event` - Event that will be signaled from guest.
    fn set_vring_kick(&self, queue_index: usize, event: &Event) -> Result<()> {
        let vring_file = virtio_sys::vhost::vhost_vring_file {
            index: queue_index as u32,
            fd: event.as_raw_descriptor(),
        };

        // This ioctl is called on a valid vhost_net descriptor and has its
        // return value checked.
        let ret = unsafe { ioctl_with_ref(self, virtio_sys::VHOST_SET_VRING_KICK(), &vring_file) };
        if ret < 0 {
            return ioctl_result();
        }
        Ok(())
    }
}

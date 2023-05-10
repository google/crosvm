// Copyright (C) 2019-2021 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-Google file.

//! Common traits and structs for vhost-user backend drivers.

use std::cell::RefCell;
use std::sync::RwLock;

use base::Event;
use base::RawDescriptor;
use base::INVALID_DESCRIPTOR;

use crate::Result;

/// Maximum number of memory regions supported.
pub const VHOST_MAX_MEMORY_REGIONS: usize = 255;

/// Vring configuration data.
pub struct VringConfigData {
    /// Maximum queue size supported by the driver.
    pub queue_max_size: u16,
    /// Actual queue size negotiated by the driver.
    pub queue_size: u16,
    /// Bitmask of vring flags.
    pub flags: u32,
    /// Descriptor table address.
    pub desc_table_addr: u64,
    /// Used ring buffer address.
    pub used_ring_addr: u64,
    /// Available ring buffer address.
    pub avail_ring_addr: u64,
    /// Optional address for logging.
    pub log_addr: Option<u64>,
}

impl VringConfigData {
    /// Check whether the log (flag, address) pair is valid.
    pub fn is_log_addr_valid(&self) -> bool {
        if self.flags & 0x1 != 0 && self.log_addr.is_none() {
            return false;
        }

        true
    }

    /// Get the log address, default to zero if not available.
    pub fn get_log_addr(&self) -> u64 {
        if self.flags & 0x1 != 0 && self.log_addr.is_some() {
            self.log_addr.unwrap()
        } else {
            0
        }
    }
}

/// Memory region configuration data.
#[derive(Clone, Copy)]
pub struct VhostUserMemoryRegionInfo {
    /// Guest physical address of the memory region.
    pub guest_phys_addr: u64,
    /// Size of the memory region.
    pub memory_size: u64,
    /// Virtual address in the current process.
    pub userspace_addr: u64,
    /// Optional offset where region starts in the mapped memory.
    pub mmap_offset: u64,
    /// Optional file descriptor for mmap.
    pub mmap_handle: RawDescriptor,
}

// We cannot derive default because windows Handle does not implement a default.
impl Default for VhostUserMemoryRegionInfo {
    fn default() -> Self {
        VhostUserMemoryRegionInfo {
            guest_phys_addr: u64::default(),
            memory_size: u64::default(),
            userspace_addr: u64::default(),
            mmap_offset: u64::default(),
            mmap_handle: INVALID_DESCRIPTOR,
        }
    }
}

/// An interface for setting up vhost-based backend drivers with interior mutability.
///
/// Vhost devices are subset of virtio devices, which improve virtio device's performance by
/// delegating data plane operations to dedicated IO service processes. Vhost devices use the
/// same virtqueue layout as virtio devices to allow vhost devices to be mapped directly to
/// virtio devices.
///
/// The purpose of vhost is to implement a subset of a virtio device's functionality outside the
/// VMM process. Typically fast paths for IO operations are delegated to the dedicated IO service
/// processes, and slow path for device configuration are still handled by the VMM process. It may
/// also be used to control access permissions of virtio backend devices.
pub trait VhostBackend: std::marker::Sized {
    /// Get a bitmask of supported virtio/vhost features.
    fn get_features(&self) -> Result<u64>;

    /// Inform the vhost subsystem which features to enable.
    /// This should be a subset of supported features from get_features().
    ///
    /// # Arguments
    /// * `features` - Bitmask of features to set.
    fn set_features(&self, features: u64) -> Result<()>;

    /// Set the current process as the owner of the vhost backend.
    /// This must be run before any other vhost commands.
    fn set_owner(&self) -> Result<()>;

    /// Used to be sent to request disabling all rings
    /// This is no longer used.
    fn reset_owner(&self) -> Result<()>;

    /// Set the guest memory mappings for vhost to use.
    fn set_mem_table(&self, regions: &[VhostUserMemoryRegionInfo]) -> Result<()>;

    /// Set base address for page modification logging.
    fn set_log_base(&self, base: u64, fd: Option<RawDescriptor>) -> Result<()>;

    /// Specify an event file descriptor to signal on log write.
    fn set_log_fd(&self, fd: RawDescriptor) -> Result<()>;

    /// Set the number of descriptors in the vring.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to set descriptor count for.
    /// * `num` - Number of descriptors in the queue.
    fn set_vring_num(&self, queue_index: usize, num: u16) -> Result<()>;

    /// Set the addresses for a given vring.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to set addresses for.
    /// * `config_data` - Configuration data for a vring.
    fn set_vring_addr(&self, queue_index: usize, config_data: &VringConfigData) -> Result<()>;

    /// Set the first index to look for available descriptors.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `num` - Index where available descriptors start.
    fn set_vring_base(&self, queue_index: usize, base: u16) -> Result<()>;

    /// Get the available vring base offset.
    fn get_vring_base(&self, queue_index: usize) -> Result<u32>;

    /// Set the event to trigger when buffers have been used by the host.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `event` - Event to trigger.
    fn set_vring_call(&self, queue_index: usize, event: &Event) -> Result<()>;

    /// Set the event that will be signaled by the guest when buffers are
    /// available for the host to process.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `event` - Event that will be signaled from guest.
    fn set_vring_kick(&self, queue_index: usize, event: &Event) -> Result<()>;

    /// Set the event that will be signaled by the guest when error happens.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `event` - Event that will be signaled from guest.
    fn set_vring_err(&self, queue_index: usize, event: &Event) -> Result<()>;

    /// Put the device to sleep.
    fn sleep(&self) -> Result<()>;
}

/// An interface for setting up vhost-based backend drivers.
///
/// Vhost devices are subset of virtio devices, which improve virtio device's performance by
/// delegating data plane operations to dedicated IO service processes. Vhost devices use the
/// same virtqueue layout as virtio devices to allow vhost devices to be mapped directly to
/// virtio devices.
///
/// The purpose of vhost is to implement a subset of a virtio device's functionality outside the
/// VMM process. Typically fast paths for IO operations are delegated to the dedicated IO service
/// processes, and slow path for device configuration are still handled by the VMM process. It may
/// also be used to control access permissions of virtio backend devices.
pub trait VhostBackendMut: std::marker::Sized {
    /// Get a bitmask of supported virtio/vhost features.
    fn get_features(&mut self) -> Result<u64>;

    /// Inform the vhost subsystem which features to enable.
    /// This should be a subset of supported features from get_features().
    ///
    /// # Arguments
    /// * `features` - Bitmask of features to set.
    fn set_features(&mut self, features: u64) -> Result<()>;

    /// Set the current process as the owner of the vhost backend.
    /// This must be run before any other vhost commands.
    fn set_owner(&mut self) -> Result<()>;

    /// Used to be sent to request disabling all rings
    /// This is no longer used.
    fn reset_owner(&mut self) -> Result<()>;

    /// Set the guest memory mappings for vhost to use.
    fn set_mem_table(&mut self, regions: &[VhostUserMemoryRegionInfo]) -> Result<()>;

    /// Set base address for page modification logging.
    fn set_log_base(&mut self, base: u64, fd: Option<RawDescriptor>) -> Result<()>;

    /// Specify an event file descriptor to signal on log write.
    fn set_log_fd(&mut self, fd: RawDescriptor) -> Result<()>;

    /// Set the number of descriptors in the vring.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to set descriptor count for.
    /// * `num` - Number of descriptors in the queue.
    fn set_vring_num(&mut self, queue_index: usize, num: u16) -> Result<()>;

    /// Set the addresses for a given vring.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to set addresses for.
    /// * `config_data` - Configuration data for a vring.
    fn set_vring_addr(&mut self, queue_index: usize, config_data: &VringConfigData) -> Result<()>;

    /// Set the first index to look for available descriptors.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `num` - Index where available descriptors start.
    fn set_vring_base(&mut self, queue_index: usize, base: u16) -> Result<()>;

    /// Get the available vring base offset.
    fn get_vring_base(&mut self, queue_index: usize) -> Result<u32>;

    /// Set the event to trigger when buffers have been used by the host.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `event` - Event to trigger.
    fn set_vring_call(&mut self, queue_index: usize, event: &Event) -> Result<()>;

    /// Set the event that will be signaled by the guest when buffers are
    /// available for the host to process.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `event` - Event that will be signaled from guest.
    fn set_vring_kick(&mut self, queue_index: usize, event: &Event) -> Result<()>;

    /// Set the event that will be signaled by the guest when error happens.
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `event` - Event that will be signaled from guest.
    fn set_vring_err(&mut self, queue_index: usize, event: &Event) -> Result<()>;

    /// Put the device to sleep.
    fn sleep(&mut self) -> Result<()>;
}

impl<T: VhostBackendMut> VhostBackend for RwLock<T> {
    fn get_features(&self) -> Result<u64> {
        self.write().unwrap().get_features()
    }

    fn set_features(&self, features: u64) -> Result<()> {
        self.write().unwrap().set_features(features)
    }

    fn set_owner(&self) -> Result<()> {
        self.write().unwrap().set_owner()
    }

    fn reset_owner(&self) -> Result<()> {
        self.write().unwrap().reset_owner()
    }

    fn set_mem_table(&self, regions: &[VhostUserMemoryRegionInfo]) -> Result<()> {
        self.write().unwrap().set_mem_table(regions)
    }

    fn set_log_base(&self, base: u64, fd: Option<RawDescriptor>) -> Result<()> {
        self.write().unwrap().set_log_base(base, fd)
    }

    fn set_log_fd(&self, fd: RawDescriptor) -> Result<()> {
        self.write().unwrap().set_log_fd(fd)
    }

    fn set_vring_num(&self, queue_index: usize, num: u16) -> Result<()> {
        self.write().unwrap().set_vring_num(queue_index, num)
    }

    fn set_vring_addr(&self, queue_index: usize, config_data: &VringConfigData) -> Result<()> {
        self.write()
            .unwrap()
            .set_vring_addr(queue_index, config_data)
    }

    fn set_vring_base(&self, queue_index: usize, base: u16) -> Result<()> {
        self.write().unwrap().set_vring_base(queue_index, base)
    }

    fn get_vring_base(&self, queue_index: usize) -> Result<u32> {
        self.write().unwrap().get_vring_base(queue_index)
    }

    fn set_vring_call(&self, queue_index: usize, event: &Event) -> Result<()> {
        self.write().unwrap().set_vring_call(queue_index, event)
    }

    fn set_vring_kick(&self, queue_index: usize, event: &Event) -> Result<()> {
        self.write().unwrap().set_vring_kick(queue_index, event)
    }

    fn set_vring_err(&self, queue_index: usize, event: &Event) -> Result<()> {
        self.write().unwrap().set_vring_err(queue_index, event)
    }

    fn sleep(&self) -> Result<()> {
        self.write().unwrap().sleep()
    }
}

impl<T: VhostBackendMut> VhostBackend for RefCell<T> {
    fn get_features(&self) -> Result<u64> {
        self.borrow_mut().get_features()
    }

    fn set_features(&self, features: u64) -> Result<()> {
        self.borrow_mut().set_features(features)
    }

    fn set_owner(&self) -> Result<()> {
        self.borrow_mut().set_owner()
    }

    fn reset_owner(&self) -> Result<()> {
        self.borrow_mut().reset_owner()
    }

    fn set_mem_table(&self, regions: &[VhostUserMemoryRegionInfo]) -> Result<()> {
        self.borrow_mut().set_mem_table(regions)
    }

    fn set_log_base(&self, base: u64, fd: Option<RawDescriptor>) -> Result<()> {
        self.borrow_mut().set_log_base(base, fd)
    }

    fn set_log_fd(&self, fd: RawDescriptor) -> Result<()> {
        self.borrow_mut().set_log_fd(fd)
    }

    fn set_vring_num(&self, queue_index: usize, num: u16) -> Result<()> {
        self.borrow_mut().set_vring_num(queue_index, num)
    }

    fn set_vring_addr(&self, queue_index: usize, config_data: &VringConfigData) -> Result<()> {
        self.borrow_mut().set_vring_addr(queue_index, config_data)
    }

    fn set_vring_base(&self, queue_index: usize, base: u16) -> Result<()> {
        self.borrow_mut().set_vring_base(queue_index, base)
    }

    fn get_vring_base(&self, queue_index: usize) -> Result<u32> {
        self.borrow_mut().get_vring_base(queue_index)
    }

    fn set_vring_call(&self, queue_index: usize, event: &Event) -> Result<()> {
        self.borrow_mut().set_vring_call(queue_index, event)
    }

    fn set_vring_kick(&self, queue_index: usize, event: &Event) -> Result<()> {
        self.borrow_mut().set_vring_kick(queue_index, event)
    }

    fn set_vring_err(&self, queue_index: usize, event: &Event) -> Result<()> {
        self.borrow_mut().set_vring_err(queue_index, event)
    }

    fn sleep(&self) -> Result<()> {
        self.borrow_mut().sleep()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    struct MockBackend {}

    impl VhostBackendMut for MockBackend {
        fn get_features(&mut self) -> Result<u64> {
            Ok(0x1)
        }

        fn set_features(&mut self, features: u64) -> Result<()> {
            assert_eq!(features, 0x1);
            Ok(())
        }

        fn set_owner(&mut self) -> Result<()> {
            Ok(())
        }

        fn reset_owner(&mut self) -> Result<()> {
            Ok(())
        }

        fn set_mem_table(&mut self, _regions: &[VhostUserMemoryRegionInfo]) -> Result<()> {
            Ok(())
        }

        fn set_log_base(&mut self, base: u64, fd: Option<RawDescriptor>) -> Result<()> {
            assert_eq!(base, 0x100);
            #[allow(clippy::unnecessary_cast)]
            let rd = 100 as RawDescriptor;
            assert_eq!(fd, Some(rd));
            Ok(())
        }

        fn set_log_fd(&mut self, fd: RawDescriptor) -> Result<()> {
            #[allow(clippy::unnecessary_cast)]
            let rd = 100 as RawDescriptor;
            assert_eq!(fd, rd);
            Ok(())
        }

        fn set_vring_num(&mut self, queue_index: usize, num: u16) -> Result<()> {
            assert_eq!(queue_index, 1);
            assert_eq!(num, 256);
            Ok(())
        }

        fn set_vring_addr(
            &mut self,
            queue_index: usize,
            _config_data: &VringConfigData,
        ) -> Result<()> {
            assert_eq!(queue_index, 1);
            Ok(())
        }

        fn set_vring_base(&mut self, queue_index: usize, base: u16) -> Result<()> {
            assert_eq!(queue_index, 1);
            assert_eq!(base, 2);
            Ok(())
        }

        fn get_vring_base(&mut self, queue_index: usize) -> Result<u32> {
            assert_eq!(queue_index, 1);
            Ok(2)
        }

        fn set_vring_call(&mut self, queue_index: usize, _event: &Event) -> Result<()> {
            assert_eq!(queue_index, 1);
            Ok(())
        }

        fn set_vring_kick(&mut self, queue_index: usize, _event: &Event) -> Result<()> {
            assert_eq!(queue_index, 1);
            Ok(())
        }

        fn set_vring_err(&mut self, queue_index: usize, _event: &Event) -> Result<()> {
            assert_eq!(queue_index, 1);
            Ok(())
        }

        fn sleep(&mut self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_vring_backend_mut() {
        let b = RwLock::new(MockBackend {});

        assert_eq!(b.get_features().unwrap(), 0x1);
        b.set_features(0x1).unwrap();
        b.set_owner().unwrap();
        b.reset_owner().unwrap();
        b.set_mem_table(&[]).unwrap();

        #[allow(clippy::unnecessary_cast)]
        let rd = 100 as RawDescriptor;
        b.set_log_base(0x100, Some(rd)).unwrap();
        b.set_log_fd(rd).unwrap();
        b.set_vring_num(1, 256).unwrap();

        let config = VringConfigData {
            queue_max_size: 0x1000,
            queue_size: 0x2000,
            flags: 0x0,
            desc_table_addr: 0x4000,
            used_ring_addr: 0x5000,
            avail_ring_addr: 0x6000,
            log_addr: None,
        };
        b.set_vring_addr(1, &config).unwrap();

        b.set_vring_base(1, 2).unwrap();
        assert_eq!(b.get_vring_base(1).unwrap(), 2);

        let event = Event::new().unwrap();
        b.set_vring_call(1, &event).unwrap();
        b.set_vring_kick(1, &event).unwrap();
        b.set_vring_err(1, &event).unwrap();
    }

    #[test]
    fn test_vring_config_data() {
        let mut config = VringConfigData {
            queue_max_size: 0x1000,
            queue_size: 0x2000,
            flags: 0x0,
            desc_table_addr: 0x4000,
            used_ring_addr: 0x5000,
            avail_ring_addr: 0x6000,
            log_addr: None,
        };

        assert!(config.is_log_addr_valid());
        assert_eq!(config.get_log_addr(), 0);

        config.flags = 0x1;
        assert!(!config.is_log_addr_valid());
        assert_eq!(config.get_log_addr(), 0);

        config.log_addr = Some(0x7000);
        assert!(config.is_log_addr_valid());
        assert_eq!(config.get_log_addr(), 0x7000);

        config.flags = 0x0;
        assert!(config.is_log_addr_valid());
        assert_eq!(config.get_log_addr(), 0);
    }
}

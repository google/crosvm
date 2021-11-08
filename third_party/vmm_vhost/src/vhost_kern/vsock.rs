// Copyright (C) 2019 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
//
// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-Google file.

//! Kernel-based vhost-vsock backend.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};

use sys_util::ioctl_with_ref;
use vm_memory::GuestAddressSpace;

use super::vhost_binding::{VHOST_VSOCK_SET_GUEST_CID, VHOST_VSOCK_SET_RUNNING};
use super::{ioctl_result, Error, Result, VhostKernBackend};
use crate::vsock::VhostVsock;

const VHOST_PATH: &str = "/dev/vhost-vsock";

/// Handle for running VHOST_VSOCK ioctls.
pub struct Vsock<AS: GuestAddressSpace> {
    fd: File,
    mem: AS,
}

impl<AS: GuestAddressSpace> Vsock<AS> {
    /// Open a handle to a new VHOST-VSOCK instance.
    pub fn new(mem: AS) -> Result<Self> {
        Ok(Vsock {
            fd: OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
                .open(VHOST_PATH)
                .map_err(Error::VhostOpen)?,
            mem,
        })
    }

    fn set_running(&self, running: bool) -> Result<()> {
        let on: ::std::os::raw::c_int = if running { 1 } else { 0 };
        let ret = unsafe { ioctl_with_ref(&self.fd, VHOST_VSOCK_SET_RUNNING(), &on) };
        ioctl_result(ret, ())
    }
}

impl<AS: GuestAddressSpace> VhostVsock for Vsock<AS> {
    fn set_guest_cid(&self, cid: u64) -> Result<()> {
        let ret = unsafe { ioctl_with_ref(&self.fd, VHOST_VSOCK_SET_GUEST_CID(), &cid) };
        ioctl_result(ret, ())
    }

    fn start(&self) -> Result<()> {
        self.set_running(true)
    }

    fn stop(&self) -> Result<()> {
        self.set_running(false)
    }
}

impl<AS: GuestAddressSpace> VhostKernBackend for Vsock<AS> {
    type AS = AS;

    fn mem(&self) -> &Self::AS {
        &self.mem
    }
}

impl<AS: GuestAddressSpace> AsRawFd for Vsock<AS> {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use sys_util::EventFd;
    use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap};

    use super::*;
    use crate::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};

    // Ignore all tests because /dev/vhost-vsock is unavailable in Chrome OS chroot.
    #[test]
    #[ignore]
    fn test_vsock_new_device() {
        let m = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10_0000)]).unwrap();
        let vsock = Vsock::new(&m).unwrap();

        assert!(vsock.as_raw_fd() >= 0);
        assert!(vsock.mem().find_region(GuestAddress(0x100)).is_some());
        assert!(vsock.mem().find_region(GuestAddress(0x10_0000)).is_none());
    }

    #[test]
    #[ignore]
    fn test_vsock_is_valid() {
        let m = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10_0000)]).unwrap();
        let vsock = Vsock::new(&m).unwrap();

        let mut config = VringConfigData {
            queue_max_size: 32,
            queue_size: 32,
            flags: 0,
            desc_table_addr: 0x1000,
            used_ring_addr: 0x2000,
            avail_ring_addr: 0x3000,
            log_addr: None,
        };
        assert!(vsock.is_valid(&config));

        config.queue_size = 0;
        assert!(!vsock.is_valid(&config));
        config.queue_size = 31;
        assert!(!vsock.is_valid(&config));
        config.queue_size = 33;
        assert!(!vsock.is_valid(&config));
    }

    #[test]
    #[ignore]
    fn test_vsock_ioctls() {
        let m = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10_0000)]).unwrap();
        let vsock = Vsock::new(&m).unwrap();

        let features = vsock.get_features().unwrap();
        vsock.set_features(features).unwrap();

        vsock.set_owner().unwrap();

        vsock.set_mem_table(&[]).unwrap_err();

        /*
        let region = VhostUserMemoryRegionInfo {
            guest_phys_addr: 0x0,
            memory_size: 0x10_0000,
            userspace_addr: 0,
            mmap_offset: 0,
            mmap_handle: -1,
        };
        vsock.set_mem_table(&[region]).unwrap_err();
         */

        let region = VhostUserMemoryRegionInfo {
            guest_phys_addr: 0x0,
            memory_size: 0x10_0000,
            userspace_addr: m.get_host_address(GuestAddress(0x0)).unwrap() as u64,
            mmap_offset: 0,
            mmap_handle: -1,
        };
        vsock.set_mem_table(&[region]).unwrap();

        vsock.set_log_base(0x4000, Some(1)).unwrap_err();
        vsock.set_log_base(0x4000, None).unwrap();

        let eventfd = EventFd::new().unwrap();
        vsock.set_log_fd(eventfd.as_raw_fd()).unwrap();

        vsock.set_vring_num(0, 32).unwrap();

        let config = VringConfigData {
            queue_max_size: 32,
            queue_size: 32,
            flags: 0,
            desc_table_addr: 0x1000,
            used_ring_addr: 0x2000,
            avail_ring_addr: 0x3000,
            log_addr: None,
        };
        vsock.set_vring_addr(0, &config).unwrap();
        vsock.set_vring_base(0, 1).unwrap();
        vsock.set_vring_call(0, &eventfd).unwrap();
        vsock.set_vring_kick(0, &eventfd).unwrap();
        vsock.set_vring_err(0, &eventfd).unwrap();
        assert_eq!(vsock.get_vring_base(0).unwrap(), 1);
        vsock.set_guest_cid(0xdead).unwrap();
        //vsock.start().unwrap();
        //vsock.stop().unwrap();
    }
}

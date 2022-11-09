// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(dead_code)]

use std::fs::File;
use std::fs::OpenOptions;
use std::io::Error as IoError;
use std::os::raw::c_uint;
use std::path::Path;

use base::ioctl_iow_nr;
use base::ioctl_with_ptr;
use base::pagesize;
use base::FromRawDescriptor;
use base::MappedRegion;
use base::SafeDescriptor;
use data_model::flexible_array_impl;
use data_model::FlexibleArrayWrapper;

use crate::udmabuf::UdmabufDriverTrait;
use crate::udmabuf::UdmabufError;
use crate::udmabuf::UdmabufResult;
use crate::udmabuf_bindings::*;
use crate::GuestAddress;
use crate::GuestMemory;
use crate::GuestMemoryError;

const UDMABUF_IOCTL_BASE: c_uint = 0x75;

ioctl_iow_nr!(UDMABUF_CREATE, UDMABUF_IOCTL_BASE, 0x42, udmabuf_create);
ioctl_iow_nr!(
    UDMABUF_CREATE_LIST,
    UDMABUF_IOCTL_BASE,
    0x43,
    udmabuf_create_list
);

flexible_array_impl!(udmabuf_create_list, udmabuf_create_item, count, list);
type UdmabufCreateList = FlexibleArrayWrapper<udmabuf_create_list, udmabuf_create_item>;

// Returns absolute offset within the memory corresponding to a particular guest address.
// This offset is not relative to a particular mapping.

// # Examples
//
// # fn test_memory_offsets() {
// #    let start_addr1 = GuestAddress(0x100)
// #    let start_addr2 = GuestAddress(0x1100);
// #    let mem = GuestMemory::new(&vec![(start_addr1, 0x1000),(start_addr2, 0x1000)])?;
// #    assert_eq!(memory_offset(&mem, GuestAddress(0x1100), 0x1000).unwrap(),0x1000);
// #}
fn memory_offset(mem: &GuestMemory, guest_addr: GuestAddress, len: u64) -> UdmabufResult<u64> {
    let (mapping, map_offset, memfd_offset) = mem
        .find_region(guest_addr)
        .map_err(UdmabufError::InvalidOffset)?;
    let map_offset = map_offset as u64;
    if map_offset
        .checked_add(len)
        .map_or(true, |a| a > mapping.size() as u64)
    {
        return Err(UdmabufError::InvalidOffset(
            GuestMemoryError::InvalidGuestAddress(guest_addr),
        ));
    }

    Ok(memfd_offset + map_offset)
}

/// A convenience wrapper for the Linux kernel's udmabuf driver.
///
/// udmabuf is a kernel driver that turns memfd pages into dmabufs. It can be used for
/// zero-copy buffer sharing between the guest and host when guest memory is backed by
/// memfd pages.
pub struct UnixUdmabufDriver {
    driver_fd: File,
}

impl UdmabufDriverTrait for UnixUdmabufDriver {
    fn new() -> UdmabufResult<UnixUdmabufDriver> {
        const UDMABUF_PATH: &str = "/dev/udmabuf";
        let path = Path::new(UDMABUF_PATH);
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(UdmabufError::DriverOpenFailed)?;

        Ok(UnixUdmabufDriver { driver_fd: fd })
    }

    fn create_udmabuf(
        &self,
        mem: &GuestMemory,
        iovecs: &[(GuestAddress, usize)],
    ) -> UdmabufResult<SafeDescriptor> {
        let pgsize = pagesize();

        let mut list = UdmabufCreateList::new(iovecs.len() as usize);
        let mut items = list.mut_entries_slice();
        for (i, &(addr, len)) in iovecs.iter().enumerate() {
            let offset = memory_offset(mem, addr, len as u64)?;

            if offset as usize % pgsize != 0 || len % pgsize != 0 {
                return Err(UdmabufError::NotPageAligned);
            }

            // `unwrap` can't panic if `memory_offset obove succeeds.
            items[i].memfd = mem.shm_region(addr).unwrap().as_raw_descriptor() as u32;
            items[i].__pad = 0;
            items[i].offset = offset;
            items[i].size = len as u64;
        }

        // Safe because we always allocate enough space for `udmabuf_create_list`.
        let fd = unsafe {
            let create_list = list.as_mut_ptr();
            (*create_list).flags = UDMABUF_FLAGS_CLOEXEC;
            ioctl_with_ptr(&self.driver_fd, UDMABUF_CREATE_LIST(), create_list)
        };

        if fd < 0 {
            return Err(UdmabufError::DmabufCreationFail(IoError::last_os_error()));
        }

        // Safe because we validated the file exists.
        Ok(unsafe { SafeDescriptor::from_raw_descriptor(fd) })
    }
}

#[cfg(test)]
mod tests {
    use base::kernel_has_memfd;

    use super::*;
    use crate::GuestAddress;

    #[test]
    fn test_memory_offsets() {
        if !kernel_has_memfd() {
            return;
        }

        let start_addr1 = GuestAddress(0x100);
        let start_addr2 = GuestAddress(0x1100);
        let start_addr3 = GuestAddress(0x2100);

        let mem = GuestMemory::new(&[
            (start_addr1, 0x1000),
            (start_addr2, 0x1000),
            (start_addr3, 0x1000),
        ])
        .unwrap();

        assert_eq!(memory_offset(&mem, GuestAddress(0x300), 1).unwrap(), 0x200);
        assert_eq!(
            memory_offset(&mem, GuestAddress(0x1200), 1).unwrap(),
            0x1100
        );
        assert_eq!(
            memory_offset(&mem, GuestAddress(0x1100), 0x1000).unwrap(),
            0x1000
        );
        assert!(memory_offset(&mem, GuestAddress(0x1100), 0x1001).is_err());
    }

    #[test]
    fn test_udmabuf_create() {
        if !kernel_has_memfd() {
            return;
        }

        let driver_result = UnixUdmabufDriver::new();

        // Most kernels will not have udmabuf support.
        if driver_result.is_err() {
            return;
        }

        let driver = driver_result.unwrap();

        let start_addr1 = GuestAddress(0x100);
        let start_addr2 = GuestAddress(0x1100);
        let start_addr3 = GuestAddress(0x2100);

        let sg_list = vec![
            (start_addr1, 0x1000),
            (start_addr2, 0x1000),
            (start_addr3, 0x1000),
        ];

        let mem = GuestMemory::new(&sg_list[..]).unwrap();

        let mut udmabuf_create_list = vec![
            (start_addr3, 0x1000),
            (start_addr2, 0x1000),
            (start_addr1, 0x1000),
            (GuestAddress(0x4000), 0x1000),
        ];

        let result = driver.create_udmabuf(&mem, &udmabuf_create_list[..]);
        assert_eq!(result.is_err(), true);

        udmabuf_create_list.pop();

        let _ = driver
            .create_udmabuf(&mem, &udmabuf_create_list[..])
            .unwrap();

        udmabuf_create_list.pop();

        // Multiple udmabufs with same memory backing is allowed.
        let _ = driver
            .create_udmabuf(&mem, &udmabuf_create_list[..])
            .unwrap();
    }
}

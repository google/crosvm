// Copyright 2021 The Chromium OS Authors. All rights reservsize.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(dead_code)]

use std::fs::{File, OpenOptions};
use std::os::raw::c_uint;

use std::path::Path;
use std::{fmt, io};

use base::{
    ioctl_iow_nr, ioctl_with_ptr, pagesize, AsRawDescriptor, FromRawDescriptor, MappedRegion,
    SafeDescriptor,
};

use data_model::{FlexibleArray, FlexibleArrayWrapper};

use rutabaga_gfx::{RutabagaHandle, RUTABAGA_MEM_HANDLE_TYPE_DMABUF};

use super::udmabuf_bindings::*;

use vm_memory::{GuestAddress, GuestMemory, GuestMemoryError};

const UDMABUF_IOCTL_BASE: c_uint = 0x75;

ioctl_iow_nr!(UDMABUF_CREATE, UDMABUF_IOCTL_BASE, 0x42, udmabuf_create);
ioctl_iow_nr!(
    UDMABUF_CREATE_LIST,
    UDMABUF_IOCTL_BASE,
    0x43,
    udmabuf_create_list
);

// It's possible to make the flexible array trait implementation a macro one day...
impl FlexibleArray<udmabuf_create_item> for udmabuf_create_list {
    fn set_len(&mut self, len: usize) {
        self.count = len as u32;
    }

    fn get_len(&self) -> usize {
        self.count as usize
    }

    fn get_slice(&self, len: usize) -> &[udmabuf_create_item] {
        unsafe { self.list.as_slice(len) }
    }

    fn get_mut_slice(&mut self, len: usize) -> &mut [udmabuf_create_item] {
        unsafe { self.list.as_mut_slice(len) }
    }
}

type UdmabufCreateList = FlexibleArrayWrapper<udmabuf_create_list, udmabuf_create_item>;

#[derive(Debug)]
pub enum UdmabufError {
    DriverOpenFailed(io::Error),
    NotPageAligned,
    InvalidOffset(GuestMemoryError),
    DmabufCreationFail(io::Error),
}

impl fmt::Display for UdmabufError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::UdmabufError::*;
        match self {
            DriverOpenFailed(e) => write!(f, "failed to open udmabuf driver: {:?}", e),
            NotPageAligned => write!(f, "All guest addresses must aligned to 4KiB"),
            InvalidOffset(e) => write!(f, "failed to get region offset: {:?}", e),
            DmabufCreationFail(e) => write!(f, "failed to create buffer: {:?}", e),
        }
    }
}

/// The result of an operation in this file.
pub type UdmabufResult<T> = std::result::Result<T, UdmabufError>;

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
    mem.do_in_region(guest_addr, move |mapping, map_offset, memfd_offset| {
        let map_offset = map_offset as u64;
        if map_offset
            .checked_add(len)
            .map_or(true, |a| a > mapping.size() as u64)
        {
            return Err(GuestMemoryError::InvalidGuestAddress(guest_addr));
        }

        return Ok(memfd_offset + map_offset);
    })
    .map_err(UdmabufError::InvalidOffset)
}

/// A convenience wrapper for the Linux kernel's udmabuf driver.
///
/// udmabuf is a kernel driver that turns memfd pages into dmabufs. It can be used for
/// zero-copy buffer sharing between the guest and host when guest memory is backed by
/// memfd pages.
pub struct UdmabufDriver {
    driver_fd: File,
}

impl UdmabufDriver {
    /// Opens the udmabuf device on success.
    pub fn new() -> UdmabufResult<UdmabufDriver> {
        const UDMABUF_PATH: &str = "/dev/udmabuf";
        let path = Path::new(UDMABUF_PATH);
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(UdmabufError::DriverOpenFailed)?;

        Ok(UdmabufDriver { driver_fd: fd })
    }

    /// Creates a dma-buf fd for the given scatter-gather list of guest memory pages (`iovecs`).
    pub fn create_udmabuf(
        &self,
        mem: &GuestMemory,
        iovecs: &[(GuestAddress, usize)],
    ) -> UdmabufResult<RutabagaHandle> {
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
            return Err(UdmabufError::DmabufCreationFail(io::Error::last_os_error()));
        }

        // Safe because we validated the file exists.
        let os_handle = unsafe { SafeDescriptor::from_raw_descriptor(fd) };
        Ok(RutabagaHandle {
            os_handle,
            handle_type: RUTABAGA_MEM_HANDLE_TYPE_DMABUF,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base::kernel_has_memfd;
    use vm_memory::GuestAddress;

    #[test]
    fn test_memory_offsets() {
        if !kernel_has_memfd() {
            return;
        }

        let start_addr1 = GuestAddress(0x100);
        let start_addr2 = GuestAddress(0x1100);
        let start_addr3 = GuestAddress(0x2100);

        let mem = GuestMemory::new(&vec![
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

        let driver_result = UdmabufDriver::new();

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
            (start_addr3, 0x1000 as usize),
            (start_addr2, 0x1000 as usize),
            (start_addr1, 0x1000 as usize),
            (GuestAddress(0x4000), 0x1000 as usize),
        ];

        let result = driver.create_udmabuf(&mem, &udmabuf_create_list[..]);
        assert_eq!(result.is_err(), true);

        udmabuf_create_list.pop();

        let rutabaga_handle1 = driver
            .create_udmabuf(&mem, &udmabuf_create_list[..])
            .unwrap();
        assert_eq!(
            rutabaga_handle1.handle_type,
            RUTABAGA_MEM_HANDLE_TYPE_DMABUF
        );

        udmabuf_create_list.pop();

        // Multiple udmabufs with same memory backing is allowed.
        let rutabaga_handle2 = driver
            .create_udmabuf(&mem, &udmabuf_create_list[..])
            .unwrap();
        assert_eq!(
            rutabaga_handle2.handle_type,
            RUTABAGA_MEM_HANDLE_TYPE_DMABUF
        );
    }
}

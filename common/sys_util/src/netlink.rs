// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{alloc::Layout, mem::MaybeUninit, os::unix::io::AsRawFd};

use data_model::DataInit;
use libc::EINVAL;

use sys_util_core::LayoutAllocation;

use super::{errno_result, Error, FromRawDescriptor, Result, SafeDescriptor};

// Custom nlmsghdr struct that can be declared DataInit.
#[repr(C)]
#[derive(Copy, Clone)]
struct NlMsgHdr {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}
unsafe impl DataInit for NlMsgHdr {}

/// Netlink attribute struct, can be used by netlink consumer
#[repr(C)]
#[derive(Copy, Clone)]
pub struct NlAttr {
    pub len: u16,
    pub _type: u16,
}
unsafe impl DataInit for NlAttr {}

/// Generic netlink header struct, can be used by netlink consumer
#[repr(C)]
#[derive(Copy, Clone)]
pub struct GenlMsgHdr {
    pub cmd: u8,
    pub version: u8,
    pub reserved: u16,
}
unsafe impl DataInit for GenlMsgHdr {}

/// A single netlink message, including its header and data.
pub struct NetlinkMessage<'a> {
    pub _type: u16,
    pub flags: u16,
    pub seq: u32,
    pub pid: u32,
    pub data: &'a [u8],
}

/// Iterator over `struct nlmsghdr` as received from a netlink socket.
pub struct NetlinkMessageIter<'a> {
    // `data` must be properly aligned for nlmsghdr.
    data: &'a [u8],
}

impl<'a> Iterator for NetlinkMessageIter<'a> {
    type Item = NetlinkMessage<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        const HDR_SIZE: usize = std::mem::size_of::<NlMsgHdr>();
        if self.data.len() < HDR_SIZE {
            return None;
        }
        let hdr = NlMsgHdr::from_slice(&self.data[..HDR_SIZE])?;

        // NLMSG_OK
        let msg_len = hdr.nlmsg_len as usize;
        if msg_len < HDR_SIZE || msg_len > self.data.len() {
            return None;
        }

        // NLMSG_DATA
        let data_start = HDR_SIZE;
        let data = &self.data[data_start..msg_len];

        // NLMSG_NEXT
        let align_to = std::mem::align_of::<NlMsgHdr>();
        let next_hdr = (msg_len + align_to - 1) & !(align_to - 1);
        if next_hdr >= self.data.len() {
            self.data = &[];
        } else {
            self.data = &self.data[next_hdr..];
        }

        Some(NetlinkMessage {
            _type: hdr.nlmsg_type,
            flags: hdr.nlmsg_flags,
            seq: hdr.nlmsg_seq,
            pid: hdr.nlmsg_pid,
            data,
        })
    }
}

/// Safe wrapper for `NETLINK_GENERIC` netlink sockets.
pub struct NetlinkGenericSocket {
    sock: SafeDescriptor,
}

impl NetlinkGenericSocket {
    /// Create and bind a new `NETLINK_GENERIC` socket.
    pub fn new(nl_groups: u32) -> Result<Self> {
        // Safe because we check the return value and convert the raw fd into a SafeDescriptor.
        let sock = unsafe {
            let fd = libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_GENERIC,
            );
            if fd < 0 {
                return errno_result();
            }

            SafeDescriptor::from_raw_descriptor(fd)
        };

        // This MaybeUninit dance is needed because sockaddr_nl has a private padding field and
        // doesn't implement Default. Safe because all 0s is valid data for sockaddr_nl.
        let mut sa = unsafe { MaybeUninit::<libc::sockaddr_nl>::zeroed().assume_init() };
        sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        sa.nl_groups = nl_groups;

        // Safe because we pass a descriptor that we own and valid pointer/size for sockaddr.
        unsafe {
            let res = libc::bind(
                sock.as_raw_fd(),
                &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of_val(&sa) as libc::socklen_t,
            );
            if res < 0 {
                return errno_result();
            }
        }

        Ok(NetlinkGenericSocket { sock })
    }

    /// Receive messages from the netlink socket.
    pub fn recv(&self) -> Result<NetlinkGenericRead> {
        let buf_size = 8192; // TODO(dverkamp): make this configurable?

        // Create a buffer with sufficient alignment for nlmsghdr.
        let layout = Layout::from_size_align(buf_size, std::mem::align_of::<NlMsgHdr>())
            .map_err(|_| Error::new(EINVAL))?;
        let allocation = LayoutAllocation::uninitialized(layout);

        // Safe because we pass a valid, owned socket fd and a valid pointer/size for the buffer.
        let bytes_read = unsafe {
            let res = libc::recv(
                self.sock.as_raw_fd(),
                allocation.as_ptr() as *mut libc::c_void,
                buf_size,
                0,
            );
            if res < 0 {
                return errno_result();
            }
            res as usize
        };

        Ok(NetlinkGenericRead {
            allocation,
            len: bytes_read,
        })
    }
}

pub struct NetlinkGenericRead {
    allocation: LayoutAllocation,
    len: usize,
}

impl NetlinkGenericRead {
    pub fn iter(&self) -> NetlinkMessageIter {
        // Safe because the data in allocation was initialized up to `self.len` by `recv()` and is
        // sufficiently aligned.
        let data = unsafe { &self.allocation.as_slice(self.len) };
        NetlinkMessageIter { data }
    }
}

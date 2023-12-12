// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Linux USB device filesystem ioctl bindings.

// Translated from include/uapi/linux/usbdevice_fs.h

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_uchar;
use std::os::raw::c_uint;
use std::os::raw::c_void;

use base::ioctl_io_nr;
use base::ioctl_ior_nr;
use base::ioctl_iow_nr;
use base::ioctl_iowr_nr;

#[repr(C)]
#[derive(Default)]
pub struct __IncompleteArrayField<T>(::std::marker::PhantomData<T>);
impl<T> __IncompleteArrayField<T> {
    #[inline]
    pub fn new() -> Self {
        __IncompleteArrayField(::std::marker::PhantomData)
    }
    /// # Safety
    ///
    /// Caller must ensure that Self's size and alignment requirements matches
    /// those of `T`s.
    #[inline]
    pub unsafe fn as_ptr(&self) -> *const T {
        ::std::mem::transmute(self)
    }
    /// # Safety
    ///
    /// Caller must ensure that Self's size and alignment requirements matches
    /// those of `T`s.
    #[inline]
    pub unsafe fn as_mut_ptr(&mut self) -> *mut T {
        ::std::mem::transmute(self)
    }
    /// # Safety
    ///
    /// Caller must ensure that Self's size and alignment requirements matches
    /// those of `T`s.
    #[inline]
    pub unsafe fn as_slice(&self, len: usize) -> &[T] {
        ::std::slice::from_raw_parts(self.as_ptr(), len)
    }
    /// # Safety
    ///
    /// Caller must ensure that Self's size and alignment requirements matches
    /// those of `T`s.
    #[inline]
    pub unsafe fn as_mut_slice(&mut self, len: usize) -> &mut [T] {
        ::std::slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }
}
impl<T> ::std::clone::Clone for __IncompleteArrayField<T> {
    #[inline]
    fn clone(&self) -> Self {
        Self::new()
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct usbdevfs_ctrltransfer {
    pub bRequestType: u8,
    pub bRequest: u8,
    pub wValue: u16,
    pub wIndex: u16,
    pub wLength: u16,
    pub timeout: u32,
    pub data: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct usbdevfs_bulktransfer {
    pub ep: c_uint,
    pub len: c_uint,
    pub timeout: c_uint,
    pub data: *mut c_void,
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct usbdevfs_setinterface {
    pub interface: c_uint,
    pub altsetting: c_uint,
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
struct usbdevfs_disconnectsignal {
    pub signr: c_uint,
    pub context: usize,
}

pub const USBDEVFS_MAXDRIVERNAME: usize = 255;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct usbdevfs_getdriver {
    pub interface: c_uint,
    pub driver: [u8; USBDEVFS_MAXDRIVERNAME + 1],
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct usbdevfs_connectinfo {
    pub devnum: c_uint,
    pub slow: c_char,
}

pub const USBDEVFS_URB_SHORT_NOT_OK: c_uint = 0x01;
pub const USBDEVFS_URB_ISO_ASAP: c_uint = 0x02;
pub const USBDEVFS_URB_BULK_CONTINUATION: c_uint = 0x04;
pub const USBDEVFS_URB_NO_FSBR: c_uint = 0x20;
pub const USBDEVFS_URB_ZERO_PACKET: c_uint = 0x40;
pub const USBDEVFS_URB_NO_INTERRUPT: c_uint = 0x80;

pub const USBDEVFS_URB_TYPE_ISO: c_uchar = 0;
pub const USBDEVFS_URB_TYPE_INTERRUPT: c_uchar = 1;
pub const USBDEVFS_URB_TYPE_CONTROL: c_uchar = 2;
pub const USBDEVFS_URB_TYPE_BULK: c_uchar = 3;

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct usbdevfs_iso_packet_desc {
    pub length: c_uint,
    pub actual_length: c_uint,
    pub status: c_uint,
}

#[repr(C)]
#[derive(Clone)]
pub struct usbdevfs_urb {
    pub urb_type: c_uchar,
    pub endpoint: c_uchar,
    pub status: c_int,
    pub flags: c_uint,
    pub buffer: *mut c_void,
    pub buffer_length: c_int,
    pub actual_length: c_int,
    pub start_frame: c_int,
    pub number_of_packets_or_stream_id: c_uint,
    pub error_count: c_int,
    pub signr: c_uint,
    pub usercontext: usize,
    pub iso_frame_desc: __IncompleteArrayField<usbdevfs_iso_packet_desc>,
}

impl Default for usbdevfs_urb {
    fn default() -> Self {
        // SAFETY: trivially safe
        unsafe { ::std::mem::zeroed() }
    }
}

// SAFETY:
// The structure that embeds this should ensure that this is safe.
unsafe impl Send for usbdevfs_urb {}
// SAFETY:
// The structure that embeds this should ensure that this is safe.
unsafe impl Sync for usbdevfs_urb {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct usbdevfs_ioctl {
    pub ifno: c_int,
    pub ioctl_code: c_int,
    pub data: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct usbdevfs_hub_portinfo {
    pub nports: c_char,
    pub port: [u8; 127],
}

pub const USBDEVFS_CAP_ZERO_PACKET: u32 = 0x01;
pub const USBDEVFS_CAP_BULK_CONTINUATION: u32 = 0x02;
pub const USBDEVFS_CAP_NO_PACKET_SIZE_LIM: u32 = 0x04;
pub const USBDEVFS_CAP_BULK_SCATTER_GATHER: u32 = 0x08;
pub const USBDEVFS_CAP_REAP_AFTER_DISCONNECT: u32 = 0x10;
pub const USBDEVFS_CAP_MMAP: u32 = 0x20;
pub const USBDEVFS_CAP_DROP_PRIVILEGES: u32 = 0x40;

pub const USBDEVFS_DISCONNECT_CLAIM_IF_DRIVER: c_uint = 0x01;
pub const USBDEVFS_DISCONNECT_CLAIM_EXCEPT_DRIVER: c_uint = 0x02;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct usbdevfs_disconnect_claim {
    pub interface: c_uint,
    pub flags: c_uint,
    pub driver: [u8; USBDEVFS_MAXDRIVERNAME + 1],
}

#[repr(C)]
pub struct usbdevfs_streams {
    pub num_streams: c_uint,
    pub num_eps: c_uint,
    pub eps: __IncompleteArrayField<c_uchar>,
}

impl Default for usbdevfs_streams {
    fn default() -> Self {
        // SAFETY: trivially safe
        unsafe { ::std::mem::zeroed() }
    }
}

const U: u32 = 'U' as u32;

ioctl_iowr_nr!(USBDEVFS_CONTROL, U, 0, usbdevfs_ctrltransfer);
ioctl_iowr_nr!(USBDEVFS_BULK, U, 2, usbdevfs_bulktransfer);
ioctl_ior_nr!(USBDEVFS_RESETEP, U, 3, c_uint);
ioctl_ior_nr!(USBDEVFS_SETINTERFACE, U, 4, usbdevfs_setinterface);
ioctl_ior_nr!(USBDEVFS_SETCONFIGURATION, U, 5, c_uint);
ioctl_ior_nr!(USBDEVFS_GETDRIVER, U, 8, usbdevfs_getdriver);
ioctl_ior_nr!(USBDEVFS_SUBMITURB, U, 10, usbdevfs_urb);
ioctl_io_nr!(USBDEVFS_DISCARDURB, U, 11);
ioctl_iow_nr!(USBDEVFS_REAPURB, U, 12, *mut *mut usbdevfs_urb);
ioctl_iow_nr!(USBDEVFS_REAPURBNDELAY, U, 13, *mut *mut usbdevfs_urb);
ioctl_ior_nr!(USBDEVFS_DISCSIGNAL, U, 14, usbdevfs_disconnectsignal);
ioctl_ior_nr!(USBDEVFS_CLAIMINTERFACE, U, 15, c_uint);
ioctl_ior_nr!(USBDEVFS_RELEASEINTERFACE, U, 16, c_uint);
ioctl_iow_nr!(USBDEVFS_CONNECTINFO, U, 17, usbdevfs_connectinfo);
ioctl_iowr_nr!(USBDEVFS_IOCTL, U, 18, usbdevfs_ioctl);
ioctl_ior_nr!(USBDEVFS_HUB_PORTINFO, U, 19, usbdevfs_hub_portinfo);
ioctl_io_nr!(USBDEVFS_RESET, U, 20);
ioctl_ior_nr!(USBDEVFS_CLEAR_HALT, U, 21, c_uint);
ioctl_io_nr!(USBDEVFS_DISCONNECT, U, 22);
ioctl_io_nr!(USBDEVFS_CONNECT, U, 23);
ioctl_ior_nr!(USBDEVFS_CLAIM_PORT, U, 24, c_uint);
ioctl_ior_nr!(USBDEVFS_RELEASE_PORT, U, 25, c_uint);
ioctl_ior_nr!(USBDEVFS_GET_CAPABILITIES, U, 26, u32);
ioctl_ior_nr!(USBDEVFS_DISCONNECT_CLAIM, U, 27, usbdevfs_disconnect_claim);
ioctl_ior_nr!(USBDEVFS_ALLOC_STREAMS, U, 28, usbdevfs_streams);
ioctl_ior_nr!(USBDEVFS_FREE_STREAMS, U, 29, usbdevfs_streams);
ioctl_iow_nr!(USBDEVFS_DROP_PRIVILEGES, U, 30, u32);
ioctl_io_nr!(USBDEVFS_GET_SPEED, U, 31);

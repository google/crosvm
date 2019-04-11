// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use sys_util::{ioctl_io_nr, ioctl_ior_nr, ioctl_iow_nr, ioctl_iowr_nr};

// generated with bindgen /usr/include/linux/vhost.h --no-unstable-rust --constified-enum '*' --with-derive-default
pub mod vhost;
// generated with bindgen /usr/include/linux/virtio_net.h --no-unstable-rust --constified-enum '*' --with-derive-default
pub mod virtio_net;
// generated with bindgen /usr/include/linux/virtio_ring.h --no-unstable-rust --constified-enum '*' --with-derive-default
pub mod virtio_ring;
pub use crate::vhost::*;
pub use crate::virtio_net::*;
pub use crate::virtio_ring::*;

pub const VHOST: ::std::os::raw::c_uint = 0xaf;

ioctl_ior_nr!(VHOST_GET_FEATURES, VHOST, 0x00, ::std::os::raw::c_ulonglong);
ioctl_iow_nr!(VHOST_SET_FEATURES, VHOST, 0x00, ::std::os::raw::c_ulonglong);
ioctl_io_nr!(VHOST_SET_OWNER, VHOST, 0x01);
ioctl_io_nr!(VHOST_RESET_OWNER, VHOST, 0x02);
ioctl_iow_nr!(VHOST_SET_MEM_TABLE, VHOST, 0x03, vhost_memory);
ioctl_iow_nr!(VHOST_SET_LOG_BASE, VHOST, 0x04, ::std::os::raw::c_ulonglong);
ioctl_iow_nr!(VHOST_SET_LOG_FD, VHOST, 0x07, ::std::os::raw::c_int);
ioctl_iow_nr!(VHOST_SET_VRING_NUM, VHOST, 0x10, vhost_vring_state);
ioctl_iow_nr!(VHOST_SET_VRING_ADDR, VHOST, 0x11, vhost_vring_addr);
ioctl_iow_nr!(VHOST_SET_VRING_BASE, VHOST, 0x12, vhost_vring_state);
ioctl_iowr_nr!(VHOST_GET_VRING_BASE, VHOST, 0x12, vhost_vring_state);
ioctl_iow_nr!(VHOST_SET_VRING_KICK, VHOST, 0x20, vhost_vring_file);
ioctl_iow_nr!(VHOST_SET_VRING_CALL, VHOST, 0x21, vhost_vring_file);
ioctl_iow_nr!(VHOST_SET_VRING_ERR, VHOST, 0x22, vhost_vring_file);
ioctl_iow_nr!(VHOST_NET_SET_BACKEND, VHOST, 0x30, vhost_vring_file);
ioctl_iow_nr!(VHOST_SCSI_SET_ENDPOINT, VHOST, 0x40, vhost_scsi_target);
ioctl_iow_nr!(VHOST_SCSI_CLEAR_ENDPOINT, VHOST, 0x41, vhost_scsi_target);
ioctl_iow_nr!(
    VHOST_SCSI_GET_ABI_VERSION,
    VHOST,
    0x42,
    ::std::os::raw::c_int
);
ioctl_iow_nr!(
    VHOST_SCSI_SET_EVENTS_MISSED,
    VHOST,
    0x43,
    ::std::os::raw::c_uint
);
ioctl_iow_nr!(
    VHOST_SCSI_GET_EVENTS_MISSED,
    VHOST,
    0x44,
    ::std::os::raw::c_uint
);
ioctl_iow_nr!(
    VHOST_VSOCK_SET_GUEST_CID,
    VHOST,
    0x60,
    ::std::os::raw::c_ulonglong
);
ioctl_iow_nr!(VHOST_VSOCK_SET_RUNNING, VHOST, 0x61, ::std::os::raw::c_int);

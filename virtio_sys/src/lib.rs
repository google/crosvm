// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Linux virtio bindings.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use base::ioctl_io_nr;
use base::ioctl_ior_nr;
use base::ioctl_iow_nr;
use base::ioctl_iowr_nr;

pub mod vhost;
pub mod virtio_config;
pub mod virtio_fs;
pub mod virtio_ids;
pub mod virtio_mmio;
pub mod virtio_net;
pub mod virtio_ring;
pub mod virtio_scsi;
pub mod virtio_vsock;
pub use crate::virtio_mmio::*;

pub const VHOST: ::std::os::raw::c_uint = 0xaf;

ioctl_ior_nr!(VHOST_GET_FEATURES, VHOST, 0x00, ::std::os::raw::c_ulonglong);
ioctl_iow_nr!(VHOST_SET_FEATURES, VHOST, 0x00, ::std::os::raw::c_ulonglong);
ioctl_io_nr!(VHOST_SET_OWNER, VHOST, 0x01);
ioctl_io_nr!(VHOST_RESET_OWNER, VHOST, 0x02);
ioctl_iow_nr!(VHOST_SET_MEM_TABLE, VHOST, 0x03, vhost::vhost_memory);
ioctl_iow_nr!(VHOST_SET_LOG_BASE, VHOST, 0x04, ::std::os::raw::c_ulonglong);
ioctl_iow_nr!(VHOST_SET_LOG_FD, VHOST, 0x07, ::std::os::raw::c_int);
ioctl_iow_nr!(VHOST_SET_VRING_NUM, VHOST, 0x10, vhost::vhost_vring_state);
ioctl_iow_nr!(VHOST_SET_VRING_ADDR, VHOST, 0x11, vhost::vhost_vring_addr);
ioctl_iow_nr!(VHOST_SET_VRING_BASE, VHOST, 0x12, vhost::vhost_vring_state);
ioctl_iowr_nr!(VHOST_GET_VRING_BASE, VHOST, 0x12, vhost::vhost_vring_state);
ioctl_iow_nr!(VHOST_SET_VRING_KICK, VHOST, 0x20, vhost::vhost_vring_file);
ioctl_iow_nr!(VHOST_SET_VRING_CALL, VHOST, 0x21, vhost::vhost_vring_file);
ioctl_iow_nr!(VHOST_SET_VRING_ERR, VHOST, 0x22, vhost::vhost_vring_file);
ioctl_iow_nr!(VHOST_NET_SET_BACKEND, VHOST, 0x30, vhost::vhost_vring_file);
ioctl_iow_nr!(
    VHOST_SCSI_SET_ENDPOINT,
    VHOST,
    0x40,
    vhost::vhost_scsi_target
);
ioctl_iow_nr!(
    VHOST_SCSI_CLEAR_ENDPOINT,
    VHOST,
    0x41,
    vhost::vhost_scsi_target
);
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

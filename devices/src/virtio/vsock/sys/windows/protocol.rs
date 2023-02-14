// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use data_model::Le16;
use data_model::Le32;
use data_model::Le64;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

pub const TYPE_STREAM_SOCKET: u16 = 1;

/// virtio_vsock_config is the vsock device configuration space defined by the virtio spec.
#[derive(Copy, Clone, Debug, Default, AsBytes, FromBytes)]
#[repr(C)]
pub struct virtio_vsock_config {
    pub guest_cid: Le64,
}

/// The message header for data packets sent on the tx/rx queues
#[derive(Copy, Clone, Debug, Default, AsBytes, FromBytes)]
#[repr(packed)]
#[allow(non_camel_case_types)]
pub struct virtio_vsock_hdr {
    pub src_cid: Le64,
    pub dst_cid: Le64,
    pub src_port: Le32,
    pub dst_port: Le32,
    pub len: Le32,
    pub r#type: Le16,
    pub op: Le16,
    pub flags: Le32,
    pub buf_alloc: Le32,
    pub fwd_cnt: Le32,
}

/// An event sent to the event queue
#[derive(Copy, Clone, Debug, Default, AsBytes, FromBytes)]
#[repr(C)]
pub struct virtio_vsock_event {
    // ID from the virtio_vsock_event_id struct in the virtio spec
    pub id: Le32,
}

pub mod vsock_op {
    pub const VIRTIO_VSOCK_OP_INVALID: u16 = 0;

    /* Connect operations */
    pub const VIRTIO_VSOCK_OP_REQUEST: u16 = 1;
    pub const VIRTIO_VSOCK_OP_RESPONSE: u16 = 2;
    pub const VIRTIO_VSOCK_OP_RST: u16 = 3;
    pub const VIRTIO_VSOCK_OP_SHUTDOWN: u16 = 4;

    /* To send payload */
    pub const VIRTIO_VSOCK_OP_RW: u16 = 5;

    /* Tell the peer our credit info */
    pub const VIRTIO_VSOCK_OP_CREDIT_UPDATE: u16 = 6;
    /* Request the peer to send the credit info to us */
    pub const VIRTIO_VSOCK_OP_CREDIT_REQUEST: u16 = 7;
}

// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//

//! Contains the Rust implementation of the libslirp consumer main loop, high
//! level interfaces to libslirp that are used to implement that loop, and
//! diagnostic tools.

#[path = "../../third_party/libslirp-rs/src/context.rs"]
pub mod context;

#[cfg(feature = "slirp-ring-capture")]
pub mod packet_ring_buffer;

pub mod sys;
pub use sys::Slirp;

/// Length includes space for an ethernet frame & the vnet header. See the virtio spec for details:
/// <http://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-2050006>
pub const ETHERNET_FRAME_SIZE: usize = 1526;

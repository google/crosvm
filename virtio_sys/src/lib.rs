// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! virtio bindings.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[cfg(any(target_os = "android", target_os = "linux"))]
pub mod vhost;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub mod vhost_ioctl;
pub mod virtio_config;
pub mod virtio_fs;
pub mod virtio_ids;
pub mod virtio_mmio;
pub mod virtio_net;
pub mod virtio_ring;
pub mod virtio_scsi;
pub mod virtio_vsock;

#[cfg(any(target_os = "android", target_os = "linux"))]
pub use crate::vhost_ioctl::*;
pub use crate::virtio_mmio::*;

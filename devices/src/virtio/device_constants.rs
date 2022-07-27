// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Contains constants and struct definitions used for implementing vhost-user
//! frontend devices without compile-time dependencies on their corresponding
//! backend devices.

use data_model::DataInit;
use data_model::Le32;

pub mod gpu {
    use super::*;

    // First queue is for virtio gpu commands. Second queue is for cursor commands, which we expect
    // there to be fewer of.
    pub const QUEUE_SIZES: &[u16] = &[256, 16];

    pub const VIRTIO_GPU_F_VIRGL: u32 = 0;
    pub const VIRTIO_GPU_F_EDID: u32 = 1;
    pub const VIRTIO_GPU_F_RESOURCE_UUID: u32 = 2;
    pub const VIRTIO_GPU_F_RESOURCE_BLOB: u32 = 3;
    pub const VIRTIO_GPU_F_CONTEXT_INIT: u32 = 4;
    /* The following capabilities are not upstreamed. */
    pub const VIRTIO_GPU_F_RESOURCE_SYNC: u32 = 5;
    pub const VIRTIO_GPU_F_CREATE_GUEST_HANDLE: u32 = 6;

    pub const VIRTIO_GPU_SHM_ID_HOST_VISIBLE: u8 = 0x0001;

    #[derive(Copy, Clone, Debug, Default)]
    #[repr(C)]
    pub struct virtio_gpu_config {
        pub events_read: Le32,
        pub events_clear: Le32,
        pub num_scanouts: Le32,
        pub num_capsets: Le32,
    }

    unsafe impl DataInit for virtio_gpu_config {}
}

pub mod snd {
    use super::*;

    #[derive(Copy, Clone, Default)]
    #[repr(C, packed)]
    pub struct virtio_snd_config {
        pub jacks: Le32,
        pub streams: Le32,
        pub chmaps: Le32,
    }
    // Safe because it only has data and has no implicit padding.
    unsafe impl DataInit for virtio_snd_config {}
}

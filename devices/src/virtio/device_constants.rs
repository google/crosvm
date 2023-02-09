// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Contains constants and struct definitions used for implementing vhost-user
//! frontend devices without compile-time dependencies on their corresponding
//! backend devices.

use data_model::DataInit;
use data_model::Le16;
use data_model::Le32;
use data_model::Le64;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

pub mod block {
    use super::*;

    pub const VIRTIO_BLK_T_IN: u32 = 0;
    pub const VIRTIO_BLK_T_OUT: u32 = 1;
    pub const VIRTIO_BLK_T_FLUSH: u32 = 4;
    pub const VIRTIO_BLK_T_GET_ID: u32 = 8;
    pub const VIRTIO_BLK_T_DISCARD: u32 = 11;
    pub const VIRTIO_BLK_T_WRITE_ZEROES: u32 = 13;

    pub const VIRTIO_BLK_S_OK: u8 = 0;
    pub const VIRTIO_BLK_S_IOERR: u8 = 1;
    pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

    pub const VIRTIO_BLK_F_SEG_MAX: u32 = 2;
    pub const VIRTIO_BLK_F_RO: u32 = 5;
    pub const VIRTIO_BLK_F_BLK_SIZE: u32 = 6;
    pub const VIRTIO_BLK_F_FLUSH: u32 = 9;
    pub const VIRTIO_BLK_F_MQ: u32 = 12;
    pub const VIRTIO_BLK_F_DISCARD: u32 = 13;
    pub const VIRTIO_BLK_F_WRITE_ZEROES: u32 = 14;

    #[derive(Copy, Clone, Debug, Default)]
    #[repr(C)]
    pub struct virtio_blk_geometry {
        cylinders: Le16,
        heads: u8,
        sectors: u8,
    }

    // Safe because it only has data and has no implicit padding.
    unsafe impl DataInit for virtio_blk_geometry {}

    #[derive(Copy, Clone, Debug, Default)]
    #[repr(C)]
    pub struct virtio_blk_topology {
        physical_block_exp: u8,
        alignment_offset: u8,
        min_io_size: Le16,
        opt_io_size: Le32,
    }

    // Safe because it only has data and has no implicit padding.
    unsafe impl DataInit for virtio_blk_topology {}

    #[derive(Copy, Clone, Debug, Default)]
    #[repr(C, packed)]
    pub struct virtio_blk_config {
        pub capacity: Le64,
        pub size_max: Le32,
        pub seg_max: Le32,
        pub geometry: virtio_blk_geometry,
        pub blk_size: Le32,
        pub topology: virtio_blk_topology,
        pub writeback: u8,
        pub unused0: u8,
        pub num_queues: Le16,
        pub max_discard_sectors: Le32,
        pub max_discard_seg: Le32,
        pub discard_sector_alignment: Le32,
        pub max_write_zeroes_sectors: Le32,
        pub max_write_zeroes_seg: Le32,
        pub write_zeroes_may_unmap: u8,
        pub unused1: [u8; 3],
    }

    // Safe because it only has data and has no implicit padding.
    unsafe impl DataInit for virtio_blk_config {}

    #[derive(Copy, Clone, Debug, Default, FromBytes)]
    #[repr(C)]
    pub(crate) struct virtio_blk_req_header {
        pub req_type: Le32,
        pub reserved: Le32,
        pub sector: Le64,
    }

    // Safe because it only has data and has no implicit padding.
    unsafe impl DataInit for virtio_blk_req_header {}

    #[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes)]
    #[repr(C)]
    pub(crate) struct virtio_blk_discard_write_zeroes {
        pub sector: Le64,
        pub num_sectors: Le32,
        pub flags: Le32,
    }

    pub(crate) const VIRTIO_BLK_DISCARD_WRITE_ZEROES_FLAG_UNMAP: u32 = 1 << 0;

    // Safe because it only has data and has no implicit padding.
    unsafe impl DataInit for virtio_blk_discard_write_zeroes {}
}

pub mod fs {
    /// The maximum allowable length of the tag used to identify a specific virtio-fs device.
    pub const FS_MAX_TAG_LEN: usize = 36;

    // The fs device does not have a fixed number of queues.
    pub const QUEUE_SIZE: u16 = 1024;
}

pub mod gpu {
    use super::*;

    // First queue is for virtio gpu commands. Second queue is for cursor commands, which we expect
    // there to be fewer of.
    pub const QUEUE_SIZES: &[u16] = &[512, 16];

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

pub mod video {
    use data_model::DataInit;
    use data_model::Le32;
    use serde::Deserialize;
    use serde::Serialize;
    use serde_keyvalue::FromKeyValues;

    // CMD_QUEUE_SIZE = max number of command descriptors for input and output queues
    // Experimentally, it appears a stream allocates 16 input and 26 output buffers = 42 total
    // For 8 simultaneous streams, 2 descs per buffer * 42 buffers * 8 streams = 672 descs
    // Allocate 1024 to give some headroom in case of extra streams/buffers
    //
    // TODO(b/204055006): Make cmd queue size dependent of
    // (max buf cnt for input + max buf cnt for output) * max descs per buffer * max nb of streams
    const CMD_QUEUE_SIZE: u16 = 1024;
    pub const CMD_QUEUE_INDEX: usize = 0;
    // EVENT_QUEUE_SIZE = max number of event descriptors for stream events like resolution changes
    const EVENT_QUEUE_SIZE: u16 = 256;
    pub const EVENT_QUEUE_INDEX: usize = 1;
    pub const QUEUE_SIZES: &[u16] = &[CMD_QUEUE_SIZE, EVENT_QUEUE_SIZE];

    pub const VIRTIO_VIDEO_F_RESOURCE_GUEST_PAGES: u32 = 0;
    pub const VIRTIO_VIDEO_F_RESOURCE_NON_CONTIG: u32 = 1;
    pub const VIRTIO_VIDEO_F_RESOURCE_VIRTIO_OBJECT: u32 = 2;

    #[derive(Debug, Clone, Copy)]
    pub enum VideoDeviceType {
        Decoder,
        Encoder,
    }

    #[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum VideoBackendType {
        #[cfg(feature = "libvda")]
        Libvda,
        #[cfg(feature = "libvda")]
        LibvdaVd,
        #[cfg(feature = "ffmpeg")]
        Ffmpeg,
        #[cfg(feature = "vaapi")]
        Vaapi,
    }

    #[derive(Debug, Serialize, Deserialize, FromKeyValues)]
    pub struct VideoDeviceConfig {
        pub backend: VideoBackendType,
    }

    /// The same set of virtio features is supported by the ffmpeg decoder and encoder.
    pub fn ffmpeg_supported_virtio_features() -> u64 {
        1u64 << VIRTIO_VIDEO_F_RESOURCE_GUEST_PAGES
            | 1u64 << VIRTIO_VIDEO_F_RESOURCE_NON_CONTIG
            | 1u64 << VIRTIO_VIDEO_F_RESOURCE_VIRTIO_OBJECT
    }

    /// The same set of virtio features is supported by the vaapi decoder and encoder.
    pub fn vaapi_supported_virtio_features() -> u64 {
        1u64 << VIRTIO_VIDEO_F_RESOURCE_GUEST_PAGES
            | 1u64 << VIRTIO_VIDEO_F_RESOURCE_NON_CONTIG
            | 1u64 << VIRTIO_VIDEO_F_RESOURCE_VIRTIO_OBJECT
    }

    /// The same set of virtio features is supported by the vda decoder and encoder.
    pub fn vda_supported_virtio_features() -> u64 {
        1u64 << VIRTIO_VIDEO_F_RESOURCE_NON_CONTIG | 1u64 << VIRTIO_VIDEO_F_RESOURCE_VIRTIO_OBJECT
    }

    /// Union of the supported features of all decoder and encoder backends.
    pub fn all_backend_virtio_features() -> u64 {
        ffmpeg_supported_virtio_features()
            | vaapi_supported_virtio_features()
            | vda_supported_virtio_features()
    }

    pub fn backend_supported_virtio_features(backend: VideoBackendType) -> u64 {
        match backend {
            #[cfg(feature = "libvda")]
            VideoBackendType::Libvda | VideoBackendType::LibvdaVd => {
                vda_supported_virtio_features()
            }
            #[cfg(feature = "ffmpeg")]
            VideoBackendType::Ffmpeg => ffmpeg_supported_virtio_features(),
            #[cfg(feature = "vaapi")]
            VideoBackendType::Vaapi => vaapi_supported_virtio_features(),
        }
    }

    #[repr(C)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct virtio_video_config {
        pub version: Le32,
        pub max_caps_length: Le32,
        pub max_resp_length: Le32,
        pub device_name: [u8; 32],
    }
    // Safe because auto-generated structs have no implicit padding.
    unsafe impl DataInit for virtio_video_config {}
}

pub mod vsock {
    pub const QUEUE_SIZE: u16 = 256;
    pub const NUM_QUEUES: usize = 3;
    pub const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];
}

pub mod wl {
    pub const QUEUE_SIZE: u16 = 256;
    pub const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE, QUEUE_SIZE];

    pub const VIRTIO_WL_F_TRANS_FLAGS: u32 = 0x01;
    pub const VIRTIO_WL_F_SEND_FENCES: u32 = 0x02;
    pub const VIRTIO_WL_F_USE_SHMEM: u32 = 0x03;
}

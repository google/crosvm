// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use data_model::{DataInit, Le16, Le32, Le64};

pub const SECTOR_SHIFT: u8 = 9;
pub const SECTOR_SIZE: u64 = 0x01 << SECTOR_SHIFT;
pub const MAX_DISCARD_SECTORS: u32 = u32::MAX;
pub const MAX_WRITE_ZEROES_SECTORS: u32 = u32::MAX;
// Arbitrary limits for number of discard/write zeroes segments.
pub const MAX_DISCARD_SEG: u32 = 32;
pub const MAX_WRITE_ZEROES_SEG: u32 = 32;
// Hard-coded to 64 KiB (in 512-byte sectors) for now,
// but this should probably be based on cluster size for qcow.
pub const DISCARD_SECTOR_ALIGNMENT: u32 = 128;

pub const ID_LEN: usize = 20;

/// Virtio block device identifier.
/// This is an ASCII string terminated by a \0, unless all 20 bytes are used,
/// in which case the \0 terminator is omitted.
pub type BlockId = [u8; ID_LEN];

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

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub(crate) struct virtio_blk_req_header {
    pub req_type: Le32,
    pub reserved: Le32,
    pub sector: Le64,
}

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_blk_req_header {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub(crate) struct virtio_blk_discard_write_zeroes {
    pub sector: Le64,
    pub num_sectors: Le32,
    pub flags: Le32,
}

pub(crate) const VIRTIO_BLK_DISCARD_WRITE_ZEROES_FLAG_UNMAP: u32 = 1 << 0;

// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_blk_discard_write_zeroes {}

/// Builds and returns the config structure used to specify block features.
pub fn build_config_space(
    disk_size: u64,
    seg_max: u32,
    block_size: u32,
    num_queues: u16,
) -> virtio_blk_config {
    virtio_blk_config {
        // If the image is not a multiple of the sector size, the tail bits are not exposed.
        capacity: Le64::from(disk_size >> SECTOR_SHIFT),
        seg_max: Le32::from(seg_max),
        blk_size: Le32::from(block_size),
        num_queues: Le16::from(num_queues),
        max_discard_sectors: Le32::from(MAX_DISCARD_SECTORS),
        discard_sector_alignment: Le32::from(DISCARD_SECTOR_ALIGNMENT),
        max_write_zeroes_sectors: Le32::from(MAX_WRITE_ZEROES_SECTORS),
        write_zeroes_may_unmap: 1,
        max_discard_seg: Le32::from(MAX_DISCARD_SEG),
        max_write_zeroes_seg: Le32::from(MAX_WRITE_ZEROES_SEG),
        ..Default::default()
    }
}

/// Returns the feature flags given the specified attributes.
pub fn build_avail_features(
    base_features: u64,
    read_only: bool,
    sparse: bool,
    multi_queue: bool,
) -> u64 {
    let mut avail_features = base_features;
    avail_features |= 1 << VIRTIO_BLK_F_FLUSH;
    if read_only {
        avail_features |= 1 << VIRTIO_BLK_F_RO;
    } else {
        if sparse {
            avail_features |= 1 << VIRTIO_BLK_F_DISCARD;
        }
        avail_features |= 1 << VIRTIO_BLK_F_WRITE_ZEROES;
    }
    avail_features |= 1 << VIRTIO_BLK_F_SEG_MAX;
    avail_features |= 1 << VIRTIO_BLK_F_BLK_SIZE;
    if multi_queue {
        avail_features |= 1 << VIRTIO_BLK_F_MQ;
    }
    avail_features
}

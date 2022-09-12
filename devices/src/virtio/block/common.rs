// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use data_model::DataInit;
use data_model::Le16;
use data_model::Le32;
use data_model::Le64;

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

// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use data_model::{DataInit, Le32, Le64};

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_snd_hdr {
    pub code: Le32,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_snd_hdr {}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct virtio_snd_query_info {
    pub hdr: virtio_snd_hdr,
    pub start_id: Le32,
    pub count: Le32,
    pub size: Le32,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_snd_query_info {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_snd_info {
    pub hda_fn_nid: Le32,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_snd_info {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct virtio_snd_pcm_info {
    pub hdr: virtio_snd_info,
    pub features: Le32,
    pub formats: Le64,
    pub rates: Le64,
    pub direction: u8,
    pub channels_min: u8,
    pub channels_max: u8,

    pub padding: [u8; 5],
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_snd_pcm_info {}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct virtio_snd_pcm_hdr {
    pub hdr: virtio_snd_hdr,
    pub stream_id: Le32,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_snd_pcm_hdr {}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct virtio_snd_pcm_set_params {
    pub hdr: virtio_snd_pcm_hdr,
    pub buffer_bytes: Le32,
    pub period_bytes: Le32,
    pub features: Le32,
    pub channels: u8,
    pub format: u8,
    pub rate: u8,
    pub padding: u8,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_snd_pcm_set_params {}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct virtio_snd_pcm_xfer {
    pub stream_id: Le32,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_snd_pcm_xfer {}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct virtio_snd_pcm_status {
    pub status: Le32,
    pub latency_bytes: Le32,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for virtio_snd_pcm_status {}

// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use data_model::Le32;
use data_model::Le64;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

use crate::virtio::snd::constants::VIRTIO_SND_CHMAP_MAX_SIZE;

#[derive(Copy, Clone, Default, AsBytes, FromBytes)]
#[repr(C)]
pub struct virtio_snd_hdr {
    pub code: Le32,
}

#[derive(Copy, Clone, Default, AsBytes, FromBytes)]
#[repr(C)]
pub struct virtio_snd_jack_hdr {
    pub hdr: virtio_snd_hdr,
    pub jack_id: Le32,
}

#[derive(Copy, Clone, Default, AsBytes, FromBytes)]
#[repr(C)]
pub struct virtio_snd_event {
    pub hdr: virtio_snd_hdr,
    pub data: Le32,
}

#[derive(Copy, Clone, Default, AsBytes, FromBytes)]
#[repr(C)]
pub struct virtio_snd_query_info {
    pub hdr: virtio_snd_hdr,
    pub start_id: Le32,
    pub count: Le32,
    pub size: Le32,
}

#[derive(Copy, Clone, Default, AsBytes, FromBytes)]
#[repr(C)]
pub struct virtio_snd_info {
    pub hda_fn_nid: Le32,
}

#[derive(Copy, Clone, Default, AsBytes, FromBytes)]
#[repr(C)]
pub struct virtio_snd_pcm_info {
    pub hdr: virtio_snd_info,
    pub features: Le32, /* 1 << VIRTIO_SND_PCM_F_XXX */
    pub formats: Le64,  /* 1 << VIRTIO_SND_PCM_FMT_XXX */
    pub rates: Le64,    /* 1 << VIRTIO_SND_PCM_RATE_XXX */
    pub direction: u8,
    pub channels_min: u8,
    pub channels_max: u8,

    pub padding: [u8; 5],
}

#[derive(Copy, Clone, Default, AsBytes, FromBytes)]
#[repr(C)]
pub struct virtio_snd_pcm_hdr {
    pub hdr: virtio_snd_hdr,
    pub stream_id: Le32,
}

#[derive(Copy, Clone, Default, AsBytes, FromBytes)]
#[repr(C)]
pub struct virtio_snd_pcm_set_params {
    pub hdr: virtio_snd_pcm_hdr,
    pub buffer_bytes: Le32,
    pub period_bytes: Le32,
    pub features: Le32, /* 1 << VIRTIO_SND_PCM_F_XXX */
    pub channels: u8,
    pub format: u8,
    pub rate: u8,
    pub padding: u8,
}

#[derive(Copy, Clone, AsBytes, FromBytes)]
#[repr(C)]
pub struct virtio_snd_pcm_xfer {
    pub stream_id: Le32,
}

#[derive(Copy, Clone, Default, AsBytes, FromBytes)]
#[repr(C)]
pub struct virtio_snd_pcm_status {
    pub status: Le32,
    pub latency_bytes: Le32,
}

#[derive(Copy, Clone, Default, AsBytes, FromBytes)]
#[repr(C)]
pub struct virtio_snd_jack_info {
    pub hdr: virtio_snd_info,
    pub features: Le32, /* 1 << VIRTIO_SND_JACK_F_XXX */
    pub hda_reg_defconf: Le32,
    pub hda_reg_caps: Le32,
    pub connected: u8,
    pub padding: [u8; 7],
}

#[derive(Copy, Clone, Default, AsBytes, FromBytes)]
#[repr(C)]
pub struct virtio_snd_jack_remap {
    pub hdr: virtio_snd_jack_hdr, /* .code = VIRTIO_SND_R_JACK_REMAP */
    pub association: Le32,
    pub sequence: Le32,
}

#[derive(Copy, Clone, Default, AsBytes, FromBytes)]
#[repr(C)]
pub struct virtio_snd_chmap_info {
    pub hdr: virtio_snd_info,
    pub direction: u8,
    pub channels: u8,
    pub positions: [u8; VIRTIO_SND_CHMAP_MAX_SIZE],
}

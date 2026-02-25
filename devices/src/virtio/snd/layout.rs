// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use data_model::Le32;
use data_model::Le64;
use serde::Deserialize;
use serde::Serialize;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

use crate::virtio::snd::constants::StatusCode;
use crate::virtio::snd::constants::VIRTIO_SND_CHMAP_MAX_SIZE;

#[derive(
    Copy, Clone, Default, FromBytes, Immutable, IntoBytes, KnownLayout, Serialize, Deserialize,
)]
#[repr(C)]
pub struct virtio_snd_hdr {
    pub code: Le32,
}

#[derive(Copy, Clone, Default, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
pub struct virtio_snd_jack_hdr {
    pub hdr: virtio_snd_hdr,
    pub jack_id: Le32,
}

#[derive(Copy, Clone, Default, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
pub struct virtio_snd_event {
    pub hdr: virtio_snd_hdr,
    pub data: Le32,
}

#[derive(Copy, Clone, Default, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
pub struct virtio_snd_query_info {
    pub hdr: virtio_snd_hdr,
    pub start_id: Le32,
    pub count: Le32,
    pub size: Le32,
}

#[derive(
    Copy,
    Clone,
    Default,
    FromBytes,
    Immutable,
    IntoBytes,
    KnownLayout,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Debug,
)]
#[repr(C)]
pub struct virtio_snd_info {
    pub hda_fn_nid: Le32,
}

#[derive(
    Copy,
    Clone,
    Default,
    FromBytes,
    Immutable,
    IntoBytes,
    KnownLayout,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Debug,
)]
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

#[derive(
    Copy, Clone, Default, FromBytes, Immutable, IntoBytes, KnownLayout, Serialize, Deserialize,
)]
#[repr(C)]
pub struct virtio_snd_pcm_hdr {
    pub hdr: virtio_snd_hdr,
    pub stream_id: Le32,
}

#[derive(
    Copy, Clone, Default, FromBytes, Immutable, IntoBytes, KnownLayout, Serialize, Deserialize,
)]
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

#[derive(Copy, Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
pub struct virtio_snd_pcm_xfer {
    pub stream_id: Le32,
}

#[derive(Copy, Clone, Default, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
pub struct virtio_snd_pcm_status {
    pub status: Le32,
    pub latency_bytes: Le32,
}

impl virtio_snd_pcm_status {
    pub fn new(status: StatusCode, latency_bytes: u32) -> Self {
        Self {
            status: Le32::from(status as u32),
            latency_bytes: Le32::from(latency_bytes),
        }
    }
}

#[derive(
    Copy,
    Clone,
    Default,
    FromBytes,
    Immutable,
    IntoBytes,
    KnownLayout,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Debug,
)]
#[repr(C)]
pub struct virtio_snd_jack_info {
    pub hdr: virtio_snd_info,
    pub features: Le32, /* 1 << VIRTIO_SND_JACK_F_XXX */
    pub hda_reg_defconf: Le32,
    pub hda_reg_caps: Le32,
    pub connected: u8,
    pub padding: [u8; 7],
}

#[derive(Copy, Clone, Default, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
pub struct virtio_snd_jack_remap {
    pub hdr: virtio_snd_jack_hdr, /* .code = VIRTIO_SND_R_JACK_REMAP */
    pub association: Le32,
    pub sequence: Le32,
}

#[derive(
    Copy,
    Clone,
    Default,
    FromBytes,
    Immutable,
    IntoBytes,
    KnownLayout,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Debug,
)]
#[repr(C)]
pub struct virtio_snd_chmap_info {
    pub hdr: virtio_snd_info,
    pub direction: u8,
    pub channels: u8,
    pub positions: [u8; VIRTIO_SND_CHMAP_MAX_SIZE],
}

#[derive(Copy, Clone, Default, Immutable, IntoBytes, FromBytes, KnownLayout)]
#[repr(C)]
pub struct virtio_snd_ctl_hdr {
    pub hdr: virtio_snd_hdr,
    pub control_id: Le32,
}

#[derive(Copy, Clone, Immutable, FromBytes, IntoBytes, KnownLayout)]
#[repr(C)]
pub struct virtio_snd_ctl_info_value_integer64 {
    pub min: Le64,
    pub max: Le64,
    pub step: Le64,
}

#[derive(Copy, Clone, Immutable, FromBytes, IntoBytes, KnownLayout)]
#[repr(C)]
pub struct virtio_snd_ctl_info_value_integer32 {
    pub min: Le32,
    pub max: Le32,
    pub step: Le32,
    _padding: [u8; 12],
}

#[derive(Copy, Clone, Immutable, FromBytes, IntoBytes, KnownLayout)]
#[repr(C)]
pub struct virtio_snd_ctl_info_value_enumerated {
    pub items: Le32,
    _padding: [u8; 20],
}

#[derive(Copy, Clone, Immutable, FromBytes, IntoBytes, KnownLayout)]
#[repr(C)]
pub union virtio_snd_ctl_info_value_union {
    integer64: virtio_snd_ctl_info_value_integer64,
    integer: virtio_snd_ctl_info_value_integer32,
    enumerated: virtio_snd_ctl_info_value_enumerated,
}

pub mod union_serde {
    use serde::Deserialize;
    use serde::Deserializer;
    use serde::Serializer;

    use super::*;

    pub fn serialize<S>(val: &virtio_snd_ctl_info_value_union, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = val.as_bytes();
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<virtio_snd_ctl_info_value_union, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(d)?;
        virtio_snd_ctl_info_value_union::read_from_bytes(&bytes)
            .map_err(|e| serde::de::Error::custom(format!("Failed to read from bytes: {e}")))
    }
}

#[derive(Copy, Clone, Immutable, KnownLayout, IntoBytes, FromBytes, Serialize, Deserialize)]
#[repr(C)]
pub struct virtio_snd_ctl_info {
    pub hdr: virtio_snd_info,
    pub role: Le32,
    pub type_: Le32,
    pub access: Le32, /* 1 << VIRTIO_SND_CTL_ACCESS_XXX */
    pub count: Le32,
    pub index: Le32,
    #[serde(with = "serde_bytes")]
    pub name: [u8; 44],
    _padding: [u8; 4],
    #[serde(with = "union_serde")]
    pub value: virtio_snd_ctl_info_value_union,
}

impl Default for virtio_snd_ctl_info {
    fn default() -> Self {
        Self {
            hdr: Default::default(),
            role: Default::default(),
            type_: Default::default(),
            access: Default::default(),
            count: Default::default(),
            index: Default::default(),
            name: [0; 44],
            _padding: [0; 4],
            value: virtio_snd_ctl_info_value_union {
                integer64: virtio_snd_ctl_info_value_integer64 {
                    min: Le64::from(0),
                    max: Le64::from(0),
                    step: Le64::from(0),
                },
            },
        }
    }
}

#[derive(Copy, Clone, Immutable, IntoBytes, FromBytes, KnownLayout)]
#[repr(C)]
pub union virtio_snd_ctl_value_union {
    pub integer: [Le32; 128],
    pub integer64: [Le64; 64],
    pub enumerated: [Le32; 128],
    pub bytes: [u8; 512],
    // TODO: virtio_snd_ctl_iec958
}

// Manually implement Default for the union
impl Default for virtio_snd_ctl_value_union {
    fn default() -> Self {
        Self {
            integer64: [Le64::default(); 64],
        }
    }
}

#[derive(Copy, Clone, Immutable, Default, IntoBytes, FromBytes, KnownLayout)]
#[repr(C)]
pub struct virtio_snd_ctl_value {
    pub value: virtio_snd_ctl_value_union,
}

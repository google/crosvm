// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(unexpected_cfgs)]

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

#[derive(Copy, Clone, Immutable, FromBytes, KnownLayout)]
#[repr(C)]
pub struct virtio_snd_ctl_info_value_integer64 {
    pub min: Le64,
    pub max: Le64,
    pub step: Le64,
}

#[derive(Copy, Clone, Immutable, FromBytes, KnownLayout)]
#[repr(C)]
pub struct virtio_snd_ctl_info_value_integer32 {
    pub min: Le32,
    pub max: Le32,
    pub step: Le32,
}

#[derive(Copy, Clone, Immutable, FromBytes, KnownLayout)]
#[repr(C)]
pub struct virtio_snd_ctl_info_value_enumerated {
    pub items: Le32,
}

#[derive(Copy, Clone, Immutable, FromBytes, KnownLayout)]
#[repr(C)]
pub union virtio_snd_ctl_info_value_union {
    integer64: virtio_snd_ctl_info_value_integer64,
    integer: virtio_snd_ctl_info_value_integer32,
    enumerated: virtio_snd_ctl_info_value_enumerated,
}

impl Default for virtio_snd_ctl_info_value_union {
    fn default() -> Self {
        // Initialize the largest variant to guarantee the entire
        // union memory space is physically zeroed out.
        // This is important because this memory will be exposed to the guest.
        Self {
            integer64: virtio_snd_ctl_info_value_integer64 {
                min: Le64::from(0),
                max: Le64::from(0),
                step: Le64::from(0),
            },
        }
    }
}

impl virtio_snd_ctl_info_value_union {
    pub fn new_integer64(val: virtio_snd_ctl_info_value_integer64) -> Self {
        let mut u = Self::default();
        u.integer64 = val;
        u
    }
    pub fn new_integer(val: virtio_snd_ctl_info_value_integer32) -> Self {
        let mut u = Self::default();
        u.integer = val;
        u
    }
    pub fn new_enumerated(val: virtio_snd_ctl_info_value_enumerated) -> Self {
        let mut u = Self::default();
        u.enumerated = val;
        u
    }
}

pub mod union_serde {
    use std::mem;

    use serde::Deserialize;
    use serde::Deserializer;
    use serde::Serializer;

    use super::*;

    const SIZE: usize = mem::size_of::<virtio_snd_ctl_info_value_union>();

    pub fn serialize<S>(val: &virtio_snd_ctl_info_value_union, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // SAFETY:
        // `virtio_snd_ctl_info_value_union` is a `#[repr(C)]` union, meaning its layout
        // is fixed and defined safely by C conventions.
        let bytes = unsafe { std::slice::from_raw_parts(val as *const _ as *const u8, SIZE) };
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<virtio_snd_ctl_info_value_union, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(d)?;

        if bytes.len() != SIZE {
            return Err(serde::de::Error::custom("Byte length mismatch"));
        }

        // SAFETY:
        // Since we explicitly verified that `bytes.len() == SIZE`, copying exactly `SIZE`
        // bytes of the received bit-pattern into the uninitialized value is safe and prevents
        // buffer overflows. Because `virtio_snd_ctl_info_value_union` is a `#[repr(C)]` union,
        // it acts as a generic byte buffer, meaning any bit pattern of `SIZE` length is valid.
        unsafe {
            let mut val = mem::MaybeUninit::<virtio_snd_ctl_info_value_union>::uninit();
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), val.as_mut_ptr() as *mut u8, SIZE);
            Ok(val.assume_init())
        }
    }
}

#[derive(Copy, Clone, Immutable, KnownLayout, Serialize, Deserialize)]
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
            value: Default::default(),
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

// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
pub const JACK_INFO: u32 = 1;
pub const JACK_REMAP: u32 = 2;

pub const STREAM_INFO: u32 = 0x0100;
pub const STREAM_SET_PARAMS: u32 = 0x0100 + 1;
pub const STREAM_PREPARE: u32 = 0x0100 + 2;
pub const STREAM_RELEASE: u32 = 0x0100 + 3;
pub const STREAM_START: u32 = 0x0100 + 4;
pub const STREAM_STOP: u32 = 0x0100 + 5;

pub const CHANNEL_MAP_INFO: u32 = 0x0200;

pub const VIRTIO_SND_S_OK: u32 = 0x8000;
pub const VIRTIO_SND_S_BAD_MSG: u32 = 0x8001;
pub const VIRTIO_SND_S_NOT_SUPP: u32 = 0x8002;
pub const VIRTIO_SND_S_IO_ERR: u32 = 0x8003;

pub const VIRTIO_SND_D_OUTPUT: u8 = 0;
pub const VIRTIO_SND_D_INPUT: u8 = 1;

pub const VIRTIO_SND_PCM_FMT_IMA_ADPCM: u8 = 0;
pub const VIRTIO_SND_PCM_FMT_MU_LAW: u8 = 1;
pub const VIRTIO_SND_PCM_FMT_A_LAW: u8 = 2;
pub const VIRTIO_SND_PCM_FMT_S8: u8 = 3;
pub const VIRTIO_SND_PCM_FMT_U8: u8 = 4;
pub const VIRTIO_SND_PCM_FMT_S16: u8 = 5;
pub const VIRTIO_SND_PCM_FMT_U16: u8 = 6;
pub const VIRTIO_SND_PCM_FMT_S18_3: u8 = 7;
pub const VIRTIO_SND_PCM_FMT_U18_3: u8 = 8;
pub const VIRTIO_SND_PCM_FMT_S20_3: u8 = 9;
pub const VIRTIO_SND_PCM_FMT_U20_3: u8 = 10;
pub const VIRTIO_SND_PCM_FMT_S24_3: u8 = 11;
pub const VIRTIO_SND_PCM_FMT_U24_3: u8 = 12;
pub const VIRTIO_SND_PCM_FMT_S20: u8 = 13;
pub const VIRTIO_SND_PCM_FMT_U20: u8 = 14;
pub const VIRTIO_SND_PCM_FMT_S24: u8 = 15;
pub const VIRTIO_SND_PCM_FMT_U24: u8 = 16;
pub const VIRTIO_SND_PCM_FMT_S32: u8 = 17;
pub const VIRTIO_SND_PCM_FMT_U32: u8 = 18;
pub const VIRTIO_SND_PCM_FMT_FLOAT: u8 = 19;
pub const VIRTIO_SND_PCM_FMT_FLOAT64: u8 = 20;
pub const VIRTIO_SND_PCM_FMT_DSD_U8: u8 = 21;
pub const VIRTIO_SND_PCM_FMT_DSD_U16: u8 = 22;
pub const VIRTIO_SND_PCM_FMT_DSD_U32: u8 = 23;
pub const VIRTIO_SND_PCM_FMT_IEC958_SUBFRAME: u8 = 24;

pub const VIRTIO_SND_PCM_RATE_5512: u8 = 0;
pub const VIRTIO_SND_PCM_RATE_8000: u8 = 1;
pub const VIRTIO_SND_PCM_RATE_11025: u8 = 2;
pub const VIRTIO_SND_PCM_RATE_16000: u8 = 3;
pub const VIRTIO_SND_PCM_RATE_22050: u8 = 4;
pub const VIRTIO_SND_PCM_RATE_32000: u8 = 5;
pub const VIRTIO_SND_PCM_RATE_44100: u8 = 6;
pub const VIRTIO_SND_PCM_RATE_48000: u8 = 7;
pub const VIRTIO_SND_PCM_RATE_64000: u8 = 8;
pub const VIRTIO_SND_PCM_RATE_88200: u8 = 9;
pub const VIRTIO_SND_PCM_RATE_96000: u8 = 10;
pub const VIRTIO_SND_PCM_RATE_176400: u8 = 11;
pub const VIRTIO_SND_PCM_RATE_192000: u8 = 12;
pub const VIRTIO_SND_PCM_RATE_384000: u8 = 13;

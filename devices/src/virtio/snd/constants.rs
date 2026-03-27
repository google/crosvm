// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub const VIRTIO_SND_R_JACK_INFO: u32 = 1;
pub const VIRTIO_SND_R_JACK_REMAP: u32 = 2;

/* PCM control request types */
pub const VIRTIO_SND_R_PCM_INFO: u32 = 0x0100;
pub const VIRTIO_SND_R_PCM_SET_PARAMS: u32 = 0x0101;
pub const VIRTIO_SND_R_PCM_PREPARE: u32 = 0x0102;
pub const VIRTIO_SND_R_PCM_RELEASE: u32 = 0x0103;
pub const VIRTIO_SND_R_PCM_START: u32 = 0x0104;
pub const VIRTIO_SND_R_PCM_STOP: u32 = 0x0105;

/* channel map control request types */
pub const VIRTIO_SND_R_CHMAP_INFO: u32 = 0x0200;

/* jack event types */
pub const VIRTIO_SND_EVT_JACK_CONNECTED: u32 = 0x1000;
pub const VIRTIO_SND_EVT_JACK_DISCONNECTED: u32 = 0x1001;

/* PCM event types */
pub const VIRTIO_SND_EVT_PCM_PERIOD_ELAPSED: u32 = 0x1100;
pub const VIRTIO_SND_EVT_PCM_XRUN: u32 = 0x1101;

/* common status codes */
pub const VIRTIO_SND_S_OK: u32 = 0x8000;
pub const VIRTIO_SND_S_BAD_MSG: u32 = 0x8001;
pub const VIRTIO_SND_S_NOT_SUPP: u32 = 0x8002;
pub const VIRTIO_SND_S_IO_ERR: u32 = 0x8003;

pub enum StatusCode {
    OK = VIRTIO_SND_S_OK as isize,
    IoErr = VIRTIO_SND_S_IO_ERR as isize,
}

/* stream direction */
pub const VIRTIO_SND_D_OUTPUT: u8 = 0;
pub const VIRTIO_SND_D_INPUT: u8 = 1;

/* supported jack features */
pub const VIRTIO_SND_JACK_F_REMAP: u32 = 0;

/* supported PCM stream features */
pub const VIRTIO_SND_PCM_F_SHMEM_HOST: u8 = 0;
pub const VIRTIO_SND_PCM_F_SHMEM_GUEST: u8 = 1;
pub const VIRTIO_SND_PCM_F_MSG_POLLING: u8 = 2;
pub const VIRTIO_SND_PCM_F_EVT_SHMEM_PERIODS: u8 = 3;
pub const VIRTIO_SND_PCM_F_EVT_XRUNS: u8 = 4;

/* supported PCM sample formats */
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
/* digital formats (width / physical width) */
pub const VIRTIO_SND_PCM_FMT_DSD_U8: u8 = 21;
pub const VIRTIO_SND_PCM_FMT_DSD_U16: u8 = 22;
pub const VIRTIO_SND_PCM_FMT_DSD_U32: u8 = 23;
pub const VIRTIO_SND_PCM_FMT_IEC958_SUBFRAME: u8 = 24;

/* supported PCM frame rates */
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

/* standard channel position definition */
pub const VIRTIO_SND_CHMAP_NONE: u8 = 0; /* undefined */
pub const VIRTIO_SND_CHMAP_NA: u8 = 1; /* silent */
pub const VIRTIO_SND_CHMAP_MONO: u8 = 2; /* mono stream */
pub const VIRTIO_SND_CHMAP_FL: u8 = 3; /* front left */
pub const VIRTIO_SND_CHMAP_FR: u8 = 4; /* front right */
pub const VIRTIO_SND_CHMAP_RL: u8 = 5; /* rear left */
pub const VIRTIO_SND_CHMAP_RR: u8 = 6; /* rear right */
pub const VIRTIO_SND_CHMAP_FC: u8 = 7; /* front center */
pub const VIRTIO_SND_CHMAP_LFE: u8 = 8; /* low frequency (LFE) */
pub const VIRTIO_SND_CHMAP_SL: u8 = 9; /* side left */
pub const VIRTIO_SND_CHMAP_SR: u8 = 10; /* side right */
pub const VIRTIO_SND_CHMAP_RC: u8 = 11; /* rear center */
pub const VIRTIO_SND_CHMAP_FLC: u8 = 12; /* front left center */
pub const VIRTIO_SND_CHMAP_FRC: u8 = 13; /* front right center */
pub const VIRTIO_SND_CHMAP_RLC: u8 = 14; /* rear left center */
pub const VIRTIO_SND_CHMAP_RRC: u8 = 15; /* rear right center */
pub const VIRTIO_SND_CHMAP_FLW: u8 = 16; /* front left wide */
pub const VIRTIO_SND_CHMAP_FRW: u8 = 17; /* front right wide */
pub const VIRTIO_SND_CHMAP_FLH: u8 = 18; /* front left high */
pub const VIRTIO_SND_CHMAP_FCH: u8 = 19; /* front center high */
pub const VIRTIO_SND_CHMAP_FRH: u8 = 20; /* front right high */
pub const VIRTIO_SND_CHMAP_TC: u8 = 21; /* top center */
pub const VIRTIO_SND_CHMAP_TFL: u8 = 22; /* top front left */
pub const VIRTIO_SND_CHMAP_TFR: u8 = 23; /* top front right */
pub const VIRTIO_SND_CHMAP_TFC: u8 = 24; /* top front center */
pub const VIRTIO_SND_CHMAP_TRL: u8 = 25; /* top rear left */
pub const VIRTIO_SND_CHMAP_TRR: u8 = 26; /* top rear right */
pub const VIRTIO_SND_CHMAP_TRC: u8 = 27; /* top rear center */
pub const VIRTIO_SND_CHMAP_TFLC: u8 = 28; /* top front left center */
pub const VIRTIO_SND_CHMAP_TFRC: u8 = 29; /* top front right center */
pub const VIRTIO_SND_CHMAP_TSL: u8 = 34; /* top side left */
pub const VIRTIO_SND_CHMAP_TSR: u8 = 35; /* top side right */
pub const VIRTIO_SND_CHMAP_LLFE: u8 = 36; /* left LFE */
pub const VIRTIO_SND_CHMAP_RLFE: u8 = 37; /* right LFE */
pub const VIRTIO_SND_CHMAP_BC: u8 = 38; /* bottom center */
pub const VIRTIO_SND_CHMAP_BLC: u8 = 39; /* bottom left center */
pub const VIRTIO_SND_CHMAP_BRC: u8 = 40; /* bottom right center */

pub const VIRTIO_SND_CHMAP_MAX_SIZE: usize = 18;

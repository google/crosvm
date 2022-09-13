// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use audio_streams::SampleFormat;
use remain::sorted;
use thiserror::Error as ThisError;

use crate::virtio::snd::constants::*;

#[sorted]
#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Unsupported frame rate: {0}")]
    UnsupportedFrameRate(u32),
    #[error("Unsupported virtio frame rate: {0}")]
    UnsupportedVirtioFrameRate(u8),
    #[error("Unsupported virtio pcm format: {0}")]
    UnsupportedVirtioPcmFormat(u8),
}

type Result<T> = std::result::Result<T, Error>;

/// Converts VIRTIO_SND_PCM_RATE_* enum to frame rate
pub fn from_virtio_frame_rate(virtio_frame_rate: u8) -> Result<u32> {
    Ok(match virtio_frame_rate {
        VIRTIO_SND_PCM_RATE_5512 => 5512u32,
        VIRTIO_SND_PCM_RATE_8000 => 8000u32,
        VIRTIO_SND_PCM_RATE_11025 => 11025u32,
        VIRTIO_SND_PCM_RATE_16000 => 16000u32,
        VIRTIO_SND_PCM_RATE_22050 => 22050u32,
        VIRTIO_SND_PCM_RATE_32000 => 32000u32,
        VIRTIO_SND_PCM_RATE_44100 => 44100u32,
        VIRTIO_SND_PCM_RATE_48000 => 48000u32,
        VIRTIO_SND_PCM_RATE_64000 => 64000u32,
        VIRTIO_SND_PCM_RATE_88200 => 88200u32,
        VIRTIO_SND_PCM_RATE_96000 => 96000u32,
        VIRTIO_SND_PCM_RATE_176400 => 176400u32,
        VIRTIO_SND_PCM_RATE_192000 => 192000u32,
        VIRTIO_SND_PCM_RATE_384000 => 384000u32,
        _ => {
            return Err(Error::UnsupportedVirtioFrameRate(virtio_frame_rate));
        }
    })
}

/// Converts VIRTIO_SND_PCM_FMT_* enum to SampleFormat
pub fn from_virtio_sample_format(virtio_pcm_format: u8) -> Result<SampleFormat> {
    Ok(match virtio_pcm_format {
        VIRTIO_SND_PCM_FMT_U8 => SampleFormat::U8,
        VIRTIO_SND_PCM_FMT_S16 => SampleFormat::S16LE,
        VIRTIO_SND_PCM_FMT_S24 => SampleFormat::S24LE,
        VIRTIO_SND_PCM_FMT_S32 => SampleFormat::S32LE,
        _ => {
            return Err(Error::UnsupportedVirtioPcmFormat(virtio_pcm_format));
        }
    })
}

/// Converts SampleFormat to VIRTIO_SND_PCM_FMT_*
pub fn from_sample_format(format: SampleFormat) -> u8 {
    match format {
        SampleFormat::U8 => VIRTIO_SND_PCM_FMT_U8,
        SampleFormat::S16LE => VIRTIO_SND_PCM_FMT_S16,
        SampleFormat::S24LE => VIRTIO_SND_PCM_FMT_S24,
        SampleFormat::S32LE => VIRTIO_SND_PCM_FMT_S32,
    }
}

/// Converts frame rate to VIRTIO_SND_PCM_RATE_* enum
pub fn virtio_frame_rate(frame_rate: u32) -> Result<u8> {
    Ok(match frame_rate {
        5512u32 => VIRTIO_SND_PCM_RATE_5512,
        8000u32 => VIRTIO_SND_PCM_RATE_8000,
        11025u32 => VIRTIO_SND_PCM_RATE_11025,
        16000u32 => VIRTIO_SND_PCM_RATE_16000,
        22050u32 => VIRTIO_SND_PCM_RATE_22050,
        32000u32 => VIRTIO_SND_PCM_RATE_32000,
        44100u32 => VIRTIO_SND_PCM_RATE_44100,
        48000u32 => VIRTIO_SND_PCM_RATE_48000,
        64000u32 => VIRTIO_SND_PCM_RATE_64000,
        88200u32 => VIRTIO_SND_PCM_RATE_88200,
        96000u32 => VIRTIO_SND_PCM_RATE_96000,
        176400u32 => VIRTIO_SND_PCM_RATE_176400,
        192000u32 => VIRTIO_SND_PCM_RATE_192000,
        384000u32 => VIRTIO_SND_PCM_RATE_384000,
        _ => {
            return Err(Error::UnsupportedFrameRate(frame_rate));
        }
    })
}

/// Get the name of VIRTIO_SND_R_PCM_* enums
pub fn get_virtio_snd_r_pcm_cmd_name(cmd_code: u32) -> &'static str {
    match cmd_code {
        0 => "Uninitialized",
        VIRTIO_SND_R_PCM_SET_PARAMS => "VIRTIO_SND_R_PCM_SET_PARAMS",
        VIRTIO_SND_R_PCM_PREPARE => "VIRTIO_SND_R_PCM_PREPARE",
        VIRTIO_SND_R_PCM_START => "VIRTIO_SND_R_PCM_START",
        VIRTIO_SND_R_PCM_STOP => "VIRTIO_SND_R_PCM_STOP",
        VIRTIO_SND_R_PCM_RELEASE => "VIRTIO_SND_R_PCM_RELEASE",
        _ => unreachable!(),
    }
}

pub fn get_virtio_direction_name(dir: u8) -> &'static str {
    match dir {
        VIRTIO_SND_D_OUTPUT => "VIRTIO_SND_D_OUTPUT",
        VIRTIO_SND_D_INPUT => "VIRTIO_SND_D_INPUT",
        _ => unreachable!(),
    }
}

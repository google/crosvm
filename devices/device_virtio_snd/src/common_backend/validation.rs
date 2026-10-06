// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Pure validation of guest-provided control requests. Everything in this module is free of I/O so
//! that it can be exhaustively checked with Kani.

use std::ops::Range;

use thiserror::Error as ThisError;

use crate::common::*;
use crate::common_backend::stream_info::SetParams;
use crate::constants::*;
use crate::layout::*;

/// Error returned when `VIRTIO_SND_R_PCM_SET_PARAMS` contains invalid or unsupported parameters.
#[derive(ThisError, Debug, PartialEq, Eq)]
pub(crate) enum SetParamsError {
    #[error("Number of channels ({channels}) must be between {min} and {max}")]
    InvalidChannels { channels: u8, min: u8, max: u8 },
    #[error("PCM format {format} is not supported")]
    UnsupportedFormat { format: u8 },
    #[error("PCM frame rate {rate} is not supported")]
    UnsupportedRate { rate: u8 },
    #[error("No feature is supported (requested features: {features:#x})")]
    UnsupportedFeatures { features: u32 },
    #[error("period_bytes must not be zero")]
    ZeroPeriodBytes,
    #[error("buffer_bytes must not be zero")]
    ZeroBufferBytes,
    #[error("buffer_bytes ({buffer_bytes}) must be at least period_bytes ({period_bytes})")]
    BufferSmallerThanPeriod {
        buffer_bytes: usize,
        period_bytes: usize,
    },
    #[error("buffer_bytes ({buffer_bytes}) must be divisible by period_bytes ({period_bytes})")]
    BufferNotPeriodMultiple {
        buffer_bytes: usize,
        period_bytes: usize,
    },
}

impl SetParamsError {
    /// Maps the error to the corresponding Virtio Sound specification status code.
    pub fn status_code(&self) -> u32 {
        match self {
            Self::InvalidChannels { .. }
            | Self::UnsupportedFormat { .. }
            | Self::UnsupportedRate { .. }
            | Self::UnsupportedFeatures { .. } => VIRTIO_SND_S_NOT_SUPP,
            Self::ZeroPeriodBytes
            | Self::ZeroBufferBytes
            | Self::BufferSmallerThanPeriod { .. }
            | Self::BufferNotPeriodMultiple { .. } => VIRTIO_SND_S_BAD_MSG,
        }
    }
}

/// Validates a `virtio_snd_query_info` request against the number of available items.
///
/// Returns the index range of items to read, or `VIRTIO_SND_S_BAD_MSG` if `start_id + count`
/// exceeds `len` or overflows `usize`.
pub(crate) fn validate_query_info(
    query_info: &virtio_snd_query_info,
    len: usize,
) -> Result<Range<usize>, u32> {
    let start_id: usize = u32::from(query_info.start_id) as usize;
    let count: usize = u32::from(query_info.count) as usize;
    let end = match start_id.checked_add(count) {
        Some(end) if end <= len => end,
        _ => return Err(VIRTIO_SND_S_BAD_MSG),
    };
    Ok(start_id..end)
}

/// Validates parameters in `VIRTIO_SND_R_PCM_SET_PARAMS` against the stream's `pcm_info`.
///
/// Returns a validated [`SetParams`] struct, or a [`SetParamsError`] detailing the validation
/// failure.
pub(crate) fn validate_set_params(
    set_params: &virtio_snd_pcm_set_params,
    pcm_info: &virtio_snd_pcm_info,
) -> Result<SetParams, SetParamsError> {
    if set_params.channels < pcm_info.channels_min || set_params.channels > pcm_info.channels_max {
        return Err(SetParamsError::InvalidChannels {
            channels: set_params.channels,
            min: pcm_info.channels_min,
            max: pcm_info.channels_max,
        });
    }

    // A u8 shift operand of 64 or greater overflows a 64-bit mask.
    if set_params.format >= 64 || (u64::from(pcm_info.formats) & (1u64 << set_params.format)) == 0 {
        return Err(SetParamsError::UnsupportedFormat {
            format: set_params.format,
        });
    }

    if set_params.rate >= 64 || (u64::from(pcm_info.rates) & (1u64 << set_params.rate)) == 0 {
        return Err(SetParamsError::UnsupportedRate {
            rate: set_params.rate,
        });
    }

    if set_params.features != 0 {
        return Err(SetParamsError::UnsupportedFeatures {
            features: set_params.features.into(),
        });
    }

    let period_bytes: usize = (u32::from(set_params.period_bytes)) as usize;
    if period_bytes == 0 {
        return Err(SetParamsError::ZeroPeriodBytes);
    }

    let buffer_bytes: usize = (u32::from(set_params.buffer_bytes)) as usize;
    if buffer_bytes == 0 {
        return Err(SetParamsError::ZeroBufferBytes);
    }
    if buffer_bytes < period_bytes {
        return Err(SetParamsError::BufferSmallerThanPeriod {
            buffer_bytes,
            period_bytes,
        });
    }
    if buffer_bytes % period_bytes != 0 {
        return Err(SetParamsError::BufferNotPeriodMultiple {
            buffer_bytes,
            period_bytes,
        });
    }

    // format and rate are guaranteed by the bitwise checks above to be supported by the device,
    // which in crosvm is a subset of valid virtio sample formats and frame rates.
    let format = from_virtio_sample_format(set_params.format).map_err(|_| {
        SetParamsError::UnsupportedFormat {
            format: set_params.format,
        }
    })?;
    let frame_rate =
        from_virtio_frame_rate(set_params.rate).map_err(|_| SetParamsError::UnsupportedRate {
            rate: set_params.rate,
        })?;

    Ok(SetParams {
        channels: set_params.channels,
        format,
        frame_rate,
        buffer_bytes,
        period_bytes,
        dir: pcm_info.direction,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn dummy_pcm_info() -> virtio_snd_pcm_info {
        virtio_snd_pcm_info {
            channels_min: 1,
            channels_max: 2,
            formats: ((1 << VIRTIO_SND_PCM_FMT_S16) | (1 << VIRTIO_SND_PCM_FMT_U8)).into(),
            rates: ((1 << VIRTIO_SND_PCM_RATE_44100) | (1 << VIRTIO_SND_PCM_RATE_48000)).into(),
            direction: VIRTIO_SND_D_OUTPUT,
            ..Default::default()
        }
    }

    #[test]
    fn test_validate_query_info_success() {
        let q = virtio_snd_query_info {
            hdr: virtio_snd_hdr {
                code: VIRTIO_SND_R_JACK_INFO.into(),
            },
            start_id: 1.into(),
            count: 3.into(),
            size: 0.into(),
        };
        assert_eq!(validate_query_info(&q, 10), Ok(1..4));
    }

    #[test]
    fn test_validate_query_info_out_of_bounds() {
        let q = virtio_snd_query_info {
            hdr: virtio_snd_hdr {
                code: VIRTIO_SND_R_JACK_INFO.into(),
            },
            start_id: 8.into(),
            count: 3.into(),
            size: 0.into(),
        };
        assert_eq!(validate_query_info(&q, 10), Err(VIRTIO_SND_S_BAD_MSG));
    }

    #[test]
    fn test_validate_query_info_overflow() {
        let q = virtio_snd_query_info {
            hdr: virtio_snd_hdr {
                code: VIRTIO_SND_R_JACK_INFO.into(),
            },
            start_id: u32::MAX.into(),
            count: 1.into(),
            size: 0.into(),
        };
        assert_eq!(validate_query_info(&q, 10), Err(VIRTIO_SND_S_BAD_MSG));
    }

    #[test]
    fn test_validate_set_params_success() {
        let pcm_info = dummy_pcm_info();
        let set_params = virtio_snd_pcm_set_params {
            channels: 2,
            format: VIRTIO_SND_PCM_FMT_S16,
            rate: VIRTIO_SND_PCM_RATE_48000,
            buffer_bytes: 4096.into(),
            period_bytes: 1024.into(),
            features: 0.into(),
            ..Default::default()
        };
        let res = validate_set_params(&set_params, &pcm_info);
        assert!(res.is_ok());
        let params = res.unwrap();
        assert_eq!(params.channels, 2);
        assert_eq!(params.buffer_bytes, 4096);
        assert_eq!(params.period_bytes, 1024);
        assert_eq!(params.dir, VIRTIO_SND_D_OUTPUT);
    }

    #[test]
    fn test_validate_set_params_zero_period() {
        let pcm_info = dummy_pcm_info();
        let set_params = virtio_snd_pcm_set_params {
            channels: 2,
            format: VIRTIO_SND_PCM_FMT_S16,
            rate: VIRTIO_SND_PCM_RATE_44100,
            buffer_bytes: 4096.into(),
            period_bytes: 0.into(),
            features: 0.into(),
            ..Default::default()
        };
        assert_eq!(
            validate_set_params(&set_params, &pcm_info),
            Err(SetParamsError::ZeroPeriodBytes)
        );
    }

    #[test]
    fn test_validate_set_params_buffer_smaller_than_period() {
        let pcm_info = dummy_pcm_info();
        let set_params = virtio_snd_pcm_set_params {
            channels: 2,
            format: VIRTIO_SND_PCM_FMT_S16,
            rate: VIRTIO_SND_PCM_RATE_44100,
            buffer_bytes: 512.into(),
            period_bytes: 1024.into(),
            features: 0.into(),
            ..Default::default()
        };
        assert_eq!(
            validate_set_params(&set_params, &pcm_info),
            Err(SetParamsError::BufferSmallerThanPeriod {
                buffer_bytes: 512,
                period_bytes: 1024,
            })
        );
    }

    #[test]
    fn test_validate_set_params_format_overflow() {
        let pcm_info = dummy_pcm_info();
        let set_params = virtio_snd_pcm_set_params {
            channels: 2,
            format: 100,
            rate: VIRTIO_SND_PCM_RATE_44100,
            buffer_bytes: 4096.into(),
            period_bytes: 1024.into(),
            features: 0.into(),
            ..Default::default()
        };
        assert_eq!(
            validate_set_params(&set_params, &pcm_info),
            Err(SetParamsError::UnsupportedFormat { format: 100 })
        );
    }

    #[test]
    fn test_validate_set_params_rate_overflow() {
        let pcm_info = dummy_pcm_info();
        let set_params = virtio_snd_pcm_set_params {
            channels: 2,
            format: VIRTIO_SND_PCM_FMT_S16,
            rate: 200,
            buffer_bytes: 4096.into(),
            period_bytes: 1024.into(),
            features: 0.into(),
            ..Default::default()
        };
        assert_eq!(
            validate_set_params(&set_params, &pcm_info),
            Err(SetParamsError::UnsupportedRate { rate: 200 })
        );
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn proof_validate_query_info() {
        let start_id: u32 = kani::any();
        let count: u32 = kani::any();
        let len: usize = kani::any();

        let query = virtio_snd_query_info {
            hdr: virtio_snd_hdr { code: 0.into() },
            start_id: start_id.into(),
            count: count.into(),
            size: 0.into(),
        };

        if let Ok(range) = validate_query_info(&query, len) {
            assert!(range.start <= range.end);
            assert!(range.end <= len);
            assert_eq!(range.end - range.start, count as usize);
        }
    }

    #[kani::proof]
    fn proof_validate_set_params() {
        let channels: u8 = kani::any();
        let format: u8 = kani::any();
        let rate: u8 = kani::any();
        let buffer_bytes: u32 = kani::any();
        let period_bytes: u32 = kani::any();
        let features: u32 = kani::any();

        let set_params = virtio_snd_pcm_set_params {
            hdr: virtio_snd_pcm_hdr {
                hdr: virtio_snd_hdr { code: 0.into() },
                stream_id: 0.into(),
            },
            buffer_bytes: buffer_bytes.into(),
            period_bytes: period_bytes.into(),
            features: features.into(),
            channels,
            format,
            rate,
            padding: 0,
        };

        let pcm_info = virtio_snd_pcm_info {
            hdr: virtio_snd_info {
                hda_fn_nid: 0.into(),
            },
            features: 0.into(),
            formats: crate::common_backend::SUPPORTED_FORMATS.into(),
            rates: crate::common_backend::SUPPORTED_FRAME_RATES.into(),
            direction: VIRTIO_SND_D_OUTPUT,
            channels_min: 1,
            channels_max: 2,
            padding: [0; 5],
        };

        if let Ok(p) = validate_set_params(&set_params, &pcm_info) {
            assert!(p.channels >= 1 && p.channels <= 2);
            assert!(p.period_bytes > 0);
            assert!(p.buffer_bytes >= p.period_bytes);
            assert_eq!(p.dir, VIRTIO_SND_D_OUTPUT);
        }
    }

    #[kani::proof]
    fn proof_hardcoded_capabilities_are_convertible() {
        let bit: u8 = kani::any();
        kani::assume(bit < 64);
        if (crate::common_backend::SUPPORTED_FORMATS & (1u64 << bit)) != 0 {
            assert!(from_virtio_sample_format(bit).is_ok());
        }
        if (crate::common_backend::SUPPORTED_FRAME_RATES & (1u64 << bit)) != 0 {
            assert!(from_virtio_frame_rate(bit).is_ok());
        }
    }

    #[kani::proof]
    fn proof_format_and_rate_roundtrip() {
        let fmt_idx: u8 = kani::any();
        kani::assume(fmt_idx < 64);
        if let Ok(sample_fmt) = from_virtio_sample_format(fmt_idx) {
            let back = from_sample_format(sample_fmt);
            assert_eq!(back, fmt_idx);
        }

        let rate_idx: u8 = kani::any();
        kani::assume(rate_idx < 64);
        if let Ok(frame_rate) = from_virtio_frame_rate(rate_idx) {
            let back = virtio_frame_rate(frame_rate);
            assert_eq!(back.unwrap(), rate_idx);
        }
    }
}

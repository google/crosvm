// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Validation of guest-provided control requests.

use std::ops::Range;

use crate::common::*;
use crate::common_backend::stream_info::SetParams;
use crate::constants::*;
use crate::layout::*;

/// Validates a `virtio_snd_query_info` request against the number of available items.
pub(crate) fn validate_query_info(
    query_info: &virtio_snd_query_info,
    len: usize,
) -> Result<Range<usize>, u32> {
    let start_id: usize = u32::from(query_info.start_id) as usize;
    let count: usize = u32::from(query_info.count) as usize;
    if start_id + count > len {
        return Err(VIRTIO_SND_S_BAD_MSG);
    }
    Ok(start_id..(start_id + count))
}

/// Validates parameters in `VIRTIO_SND_R_PCM_SET_PARAMS` against the stream's `pcm_info`.
pub(crate) fn validate_set_params(
    set_params: &virtio_snd_pcm_set_params,
    pcm_info: &virtio_snd_pcm_info,
) -> Result<SetParams, u32> {
    if set_params.channels < pcm_info.channels_min || set_params.channels > pcm_info.channels_max {
        return Err(VIRTIO_SND_S_NOT_SUPP);
    }
    if (u64::from(pcm_info.formats) & (1 << set_params.format)) == 0 {
        return Err(VIRTIO_SND_S_NOT_SUPP);
    }
    if (u64::from(pcm_info.rates) & (1 << set_params.rate)) == 0 {
        return Err(VIRTIO_SND_S_NOT_SUPP);
    }
    if set_params.features != 0 {
        return Err(VIRTIO_SND_S_NOT_SUPP);
    }
    let buffer_bytes: u32 = set_params.buffer_bytes.into();
    let period_bytes: u32 = set_params.period_bytes.into();
    if buffer_bytes % period_bytes != 0 {
        return Err(VIRTIO_SND_S_BAD_MSG);
    }

    let format = from_virtio_sample_format(set_params.format).unwrap();
    let frame_rate = from_virtio_frame_rate(set_params.rate).unwrap();

    Ok(SetParams {
        channels: set_params.channels,
        format,
        frame_rate,
        buffer_bytes: buffer_bytes as usize,
        period_bytes: period_bytes as usize,
        dir: pcm_info.direction,
    })
}

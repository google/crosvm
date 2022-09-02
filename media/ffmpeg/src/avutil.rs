// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::avcodec::AvError;
use crate::avcodec::AvPixelFormat;
use crate::ffi;

pub const AV_NOPTS_VALUE: u64 = 0x8000000000000000;
const MAX_FFMPEG_PLANES: usize = 4;

/// Get the maximum data alignment that may be required by FFmpeg.
/// This could change depending on FFmpeg's build configuration (AVX etc.).
pub fn max_buffer_alignment() -> usize {
    // Safe because this function has no side effects and just returns an integer.
    unsafe { ffi::av_cpu_max_align() as usize }
}

// See AvPixelFormat::line_size.
pub(crate) fn av_image_line_size(
    format: AvPixelFormat,
    width: u32,
    plane: usize,
) -> Result<usize, AvError> {
    // Safe because format is a valid format and this function is pure computation.
    match unsafe { ffi::av_image_get_linesize(format.pix_fmt(), width as _, plane as _) } {
        i if i >= 0 => Ok(i as _),
        err => Err(AvError(err)),
    }
}

// See AvPixelFormat::plane_sizes.
pub(crate) fn av_image_plane_sizes<I: IntoIterator<Item = u32>>(
    format: AvPixelFormat,
    linesizes: I,
    height: u32,
) -> Result<Vec<usize>, AvError> {
    let mut linesizes_buf = [0; MAX_FFMPEG_PLANES];
    let mut planes = 0;
    for (i, linesize) in linesizes.into_iter().take(MAX_FFMPEG_PLANES).enumerate() {
        linesizes_buf[i] = linesize as _;
        planes += 1;
    }
    let mut plane_sizes_buf = [0; MAX_FFMPEG_PLANES];
    // Safe because plane_sizes_buf and linesizes_buf have the size specified by the API, format is
    // valid, and this function doesn't have any side effects other than writing to plane_sizes_buf.
    AvError::result(unsafe {
        ffi::av_image_fill_plane_sizes(
            plane_sizes_buf.as_mut_ptr(),
            format.pix_fmt(),
            height as _,
            linesizes_buf.as_ptr(),
        )
    })?;
    Ok(plane_sizes_buf
        .into_iter()
        .map(|x| x as _)
        .take(planes)
        .collect())
}

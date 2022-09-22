// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use ffmpeg::avcodec::AvPixelFormat;

use crate::virtio::video::format::Format;

/// The error returned by `AvPixelFormat::try_from` when there's no applicable format.
// The empty field prevents constructing this and allows extending it in the future.
#[derive(Debug)]
pub struct TryFromFormatError(());

impl TryFrom<Format> for AvPixelFormat {
    type Error = TryFromFormatError;

    fn try_from(value: Format) -> Result<Self, Self::Error> {
        use ffmpeg::*;
        AvPixelFormat::try_from(match value {
            Format::NV12 => AVPixelFormat_AV_PIX_FMT_NV12,
            Format::YUV420 => AVPixelFormat_AV_PIX_FMT_YUV420P,
            _ => return Err(TryFromFormatError(())),
        })
        .map_err(|_|
            // The error case should never happen as long as we use valid constant values, but
            // don't panic in case something goes wrong. 
            TryFromFormatError(()))
    }
}

// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Data structures representing coded/raw formats.

use enumn::N;
use std::os::unix::io::RawFd;

use super::bindings;
use super::error::*;

/// Represents a FD for bitstream/frame buffer.
/// Files described by BufferFd must be accessed from outside of this crate.
pub type BufferFd = RawFd;

/// Represents a video frame plane.
pub struct FramePlane {
    pub offset: i32,
    pub stride: i32,
}

impl FramePlane {
    pub fn to_raw_frame_plane(&self) -> bindings::video_frame_plane_t {
        bindings::video_frame_plane_t {
            offset: self.offset,
            stride: self.stride,
        }
    }
}

// The callers must guarantee that `ptr` is valid for |`num`| elements when both `ptr` and `num`
// are valid.
pub(crate) unsafe fn validate_formats<T, U, F>(ptr: *const T, num: usize, f: F) -> Result<Vec<U>>
where
    F: FnMut(&T) -> Result<U>,
{
    if num == 0 {
        return Err(Error::InvalidCapabilities("num must not be 0".to_string()));
    }
    if ptr.is_null() {
        return Err(Error::InvalidCapabilities(
            "pointer must not be NULL".to_string(),
        ));
    }

    std::slice::from_raw_parts(ptr, num)
        .iter()
        .map(f)
        .collect::<Result<Vec<_>>>()
}

/// Represents a video codec.
#[derive(Debug, Clone, Copy, N)]
#[repr(i32)]
pub enum Profile {
    H264ProfileBaseline = bindings::video_codec_profile_H264PROFILE_BASELINE,
    H264ProfileMain = bindings::video_codec_profile_H264PROFILE_MAIN,
    H264ProfileExtended = bindings::video_codec_profile_H264PROFILE_EXTENDED,
    H264ProfileHigh = bindings::video_codec_profile_H264PROFILE_HIGH,
    H264ProfileHigh10Profile = bindings::video_codec_profile_H264PROFILE_HIGH10PROFILE,
    H264ProfileHigh422Profile = bindings::video_codec_profile_H264PROFILE_HIGH422PROFILE,
    H264ProfileHigh444PredictiveProfile =
        bindings::video_codec_profile_H264PROFILE_HIGH444PREDICTIVEPROFILE,
    H264ProfileScalableBaseline = bindings::video_codec_profile_H264PROFILE_SCALABLEBASELINE,
    H264ProfileScalableHigh = bindings::video_codec_profile_H264PROFILE_SCALABLEHIGH,
    H264ProfileStereoHigh = bindings::video_codec_profile_H264PROFILE_STEREOHIGH,
    H264ProfileMultiviewHigh = bindings::video_codec_profile_H264PROFILE_MULTIVIEWHIGH,
    VP8 = bindings::video_codec_profile_VP8PROFILE_MIN,
    VP9Profile0 = bindings::video_codec_profile_VP9PROFILE_PROFILE0,
    VP9Profile1 = bindings::video_codec_profile_VP9PROFILE_PROFILE1,
    VP9Profile2 = bindings::video_codec_profile_VP9PROFILE_PROFILE2,
    VP9Profile3 = bindings::video_codec_profile_VP9PROFILE_PROFILE3,
    HevcProfileMain = bindings::video_codec_profile_HEVCPROFILE_MAIN,
    HevcProfileMain10 = bindings::video_codec_profile_HEVCPROFILE_MAIN10,
    HevcProfileMainStillPicture = bindings::video_codec_profile_HEVCPROFILE_MAIN_STILL_PICTURE,
    DolbyVisionProfile0 = bindings::video_codec_profile_DOLBYVISION_PROFILE0,
    DolbyVisionProfile4 = bindings::video_codec_profile_DOLBYVISION_PROFILE4,
    DolbyVisionProfile5 = bindings::video_codec_profile_DOLBYVISION_PROFILE5,
    DolbyVisionProfile7 = bindings::video_codec_profile_DOLBYVISION_PROFILE7,
    Theora = bindings::video_codec_profile_THEORAPROFILE_ANY,
    Av1ProfileMain = bindings::video_codec_profile_AV1PROFILE_PROFILE_MAIN,
    Av1ProfileHigh = bindings::video_codec_profile_AV1PROFILE_PROFILE_HIGH,
    Av1ProfilePro = bindings::video_codec_profile_AV1PROFILE_PROFILE_PRO,
}

impl Profile {
    pub(crate) fn new(p: bindings::video_codec_profile_t) -> Result<Self> {
        Self::n(p).ok_or(Error::UnknownProfile(p))
    }

    pub(crate) fn to_raw_profile(self) -> bindings::video_codec_profile_t {
        self as bindings::video_codec_profile_t
    }
}

/// Represents a raw pixel format.
#[derive(Debug, Clone, Copy, N)]
#[repr(u32)]
pub enum PixelFormat {
    YV12 = bindings::video_pixel_format_YV12,
    NV12 = bindings::video_pixel_format_NV12,
}

impl PixelFormat {
    pub(crate) fn new(f: bindings::video_pixel_format_t) -> Result<PixelFormat> {
        PixelFormat::n(f).ok_or(Error::UnknownPixelFormat(f))
    }

    pub(crate) fn to_raw_pixel_format(&self) -> bindings::video_pixel_format_t {
        match *self {
            PixelFormat::YV12 => bindings::video_pixel_format_YV12,
            PixelFormat::NV12 => bindings::video_pixel_format_NV12,
        }
    }

    pub(crate) unsafe fn from_raw_parts(
        data: *const bindings::video_pixel_format_t,
        len: usize,
    ) -> Result<Vec<Self>> {
        validate_formats(data, len, |f| Self::new(*f))
    }
}

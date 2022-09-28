// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod avcodec;
mod avutil;
pub use avutil::*;
mod error;
pub use error::*;
mod ffmpeg;
use crate::ffmpeg as ffi;
pub mod swscale;

pub use ffi::AVPixelFormat_AV_PIX_FMT_NV12;
pub use ffi::AVPixelFormat_AV_PIX_FMT_YUV420P;
pub use ffi::AV_CODEC_CAP_DR1;
pub use ffi::FF_PROFILE_H264_BASELINE;
pub use ffi::FF_PROFILE_H264_EXTENDED;
pub use ffi::FF_PROFILE_H264_HIGH;
pub use ffi::FF_PROFILE_H264_HIGH_10;
pub use ffi::FF_PROFILE_H264_HIGH_422;
pub use ffi::FF_PROFILE_H264_HIGH_444_PREDICTIVE;
pub use ffi::FF_PROFILE_H264_MAIN;
pub use ffi::FF_PROFILE_H264_MULTIVIEW_HIGH;
pub use ffi::FF_PROFILE_H264_STEREO_HIGH;
pub use ffi::FF_PROFILE_HEVC_MAIN;
pub use ffi::FF_PROFILE_HEVC_MAIN_10;
pub use ffi::FF_PROFILE_HEVC_MAIN_STILL_PICTURE;
pub use ffi::FF_PROFILE_VP9_0;
pub use ffi::FF_PROFILE_VP9_1;
pub use ffi::FF_PROFILE_VP9_2;
pub use ffi::FF_PROFILE_VP9_3;

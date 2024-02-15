// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Data structures that represent video format information in virtio video devices.

use std::convert::From;
use std::convert::Into;
use std::convert::TryFrom;
use std::fmt;
use std::fmt::Display;
use std::io;

use base::error;
use data_model::Le32;
use enumn::N;

use crate::virtio::video::command::ReadCmdError;
use crate::virtio::video::protocol::*;
use crate::virtio::video::response::Response;
use crate::virtio::Writer;

#[derive(PartialEq, Eq, PartialOrd, Ord, N, Clone, Copy, Debug)]
#[repr(u32)]
pub enum Profile {
    H264Baseline = VIRTIO_VIDEO_PROFILE_H264_BASELINE,
    H264Main = VIRTIO_VIDEO_PROFILE_H264_MAIN,
    H264Extended = VIRTIO_VIDEO_PROFILE_H264_EXTENDED,
    H264High = VIRTIO_VIDEO_PROFILE_H264_HIGH,
    H264High10 = VIRTIO_VIDEO_PROFILE_H264_HIGH10PROFILE,
    H264High422 = VIRTIO_VIDEO_PROFILE_H264_HIGH422PROFILE,
    H264High444PredictiveProfile = VIRTIO_VIDEO_PROFILE_H264_HIGH444PREDICTIVEPROFILE,
    H264ScalableBaseline = VIRTIO_VIDEO_PROFILE_H264_SCALABLEBASELINE,
    H264ScalableHigh = VIRTIO_VIDEO_PROFILE_H264_SCALABLEHIGH,
    H264StereoHigh = VIRTIO_VIDEO_PROFILE_H264_STEREOHIGH,
    H264MultiviewHigh = VIRTIO_VIDEO_PROFILE_H264_MULTIVIEWHIGH,
    HevcMain = VIRTIO_VIDEO_PROFILE_HEVC_MAIN,
    HevcMain10 = VIRTIO_VIDEO_PROFILE_HEVC_MAIN10,
    HevcMainStillPicture = VIRTIO_VIDEO_PROFILE_HEVC_MAIN_STILL_PICTURE,
    VP8Profile0 = VIRTIO_VIDEO_PROFILE_VP8_PROFILE0,
    VP8Profile1 = VIRTIO_VIDEO_PROFILE_VP8_PROFILE1,
    VP8Profile2 = VIRTIO_VIDEO_PROFILE_VP8_PROFILE2,
    VP8Profile3 = VIRTIO_VIDEO_PROFILE_VP8_PROFILE3,
    VP9Profile0 = VIRTIO_VIDEO_PROFILE_VP9_PROFILE0,
    VP9Profile1 = VIRTIO_VIDEO_PROFILE_VP9_PROFILE1,
    VP9Profile2 = VIRTIO_VIDEO_PROFILE_VP9_PROFILE2,
    VP9Profile3 = VIRTIO_VIDEO_PROFILE_VP9_PROFILE3,
}
impl_try_from_le32_for_enumn!(Profile, "profile");

impl Profile {
    #[cfg(any(feature = "video-encoder", feature = "libvda", feature = "vaapi"))]
    pub fn to_format(self) -> Format {
        use Profile::*;
        match self {
            H264Baseline
            | H264Main
            | H264Extended
            | H264High
            | H264High10
            | H264High422
            | H264High444PredictiveProfile
            | H264ScalableBaseline
            | H264ScalableHigh
            | H264StereoHigh
            | H264MultiviewHigh => Format::H264,
            HevcMain | HevcMain10 | HevcMainStillPicture => Format::Hevc,
            VP8Profile0 | VP8Profile1 | VP8Profile2 | VP8Profile3 => Format::VP8,
            VP9Profile0 | VP9Profile1 | VP9Profile2 | VP9Profile3 => Format::VP9,
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, N, Clone, Copy, Debug)]
#[repr(u32)]
pub enum Level {
    H264_1_0 = VIRTIO_VIDEO_LEVEL_H264_1_0,
    H264_1_1 = VIRTIO_VIDEO_LEVEL_H264_1_1,
    H264_1_2 = VIRTIO_VIDEO_LEVEL_H264_1_2,
    H264_1_3 = VIRTIO_VIDEO_LEVEL_H264_1_3,
    H264_2_0 = VIRTIO_VIDEO_LEVEL_H264_2_0,
    H264_2_1 = VIRTIO_VIDEO_LEVEL_H264_2_1,
    H264_2_2 = VIRTIO_VIDEO_LEVEL_H264_2_2,
    H264_3_0 = VIRTIO_VIDEO_LEVEL_H264_3_0,
    H264_3_1 = VIRTIO_VIDEO_LEVEL_H264_3_1,
    H264_3_2 = VIRTIO_VIDEO_LEVEL_H264_3_2,
    H264_4_0 = VIRTIO_VIDEO_LEVEL_H264_4_0,
    H264_4_1 = VIRTIO_VIDEO_LEVEL_H264_4_1,
    H264_4_2 = VIRTIO_VIDEO_LEVEL_H264_4_2,
    H264_5_0 = VIRTIO_VIDEO_LEVEL_H264_5_0,
    H264_5_1 = VIRTIO_VIDEO_LEVEL_H264_5_1,
}
impl_try_from_le32_for_enumn!(Level, "level");

#[derive(PartialEq, Eq, PartialOrd, Ord, N, Clone, Copy, Debug)]
#[repr(u32)]
pub enum Format {
    // Raw formats
    NV12 = VIRTIO_VIDEO_FORMAT_NV12,
    YUV420 = VIRTIO_VIDEO_FORMAT_YUV420,

    // Bitstream formats
    H264 = VIRTIO_VIDEO_FORMAT_H264,
    Hevc = VIRTIO_VIDEO_FORMAT_HEVC,
    VP8 = VIRTIO_VIDEO_FORMAT_VP8,
    VP9 = VIRTIO_VIDEO_FORMAT_VP9,
}
impl_try_from_le32_for_enumn!(Format, "format");

impl Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Format::*;
        match self {
            NV12 => write!(f, "NV12"),
            YUV420 => write!(f, "YUV420"),
            H264 => write!(f, "H264"),
            Hevc => write!(f, "HEVC"),
            VP8 => write!(f, "VP8"),
            VP9 => write!(f, "VP9"),
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, N, Clone, Copy, Debug)]
#[repr(u32)]
pub enum BitrateMode {
    Vbr = VIRTIO_VIDEO_BITRATE_MODE_VBR,
    Cbr = VIRTIO_VIDEO_BITRATE_MODE_CBR,
}
impl_try_from_le32_for_enumn!(BitrateMode, "bitrate_mode");

#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
pub enum Bitrate {
    /// Constant bitrate.
    Cbr { target: u32 },
    /// Variable bitrate.
    Vbr { target: u32, peak: u32 },
}

#[cfg(feature = "video-encoder")]
impl Bitrate {
    pub fn mode(&self) -> BitrateMode {
        match self {
            Bitrate::Cbr { .. } => BitrateMode::Cbr,
            Bitrate::Vbr { .. } => BitrateMode::Vbr,
        }
    }

    pub fn target(&self) -> u32 {
        match self {
            Bitrate::Cbr { target } => *target,
            Bitrate::Vbr { target, .. } => *target,
        }
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct Crop {
    pub left: u32,
    pub top: u32,
    pub width: u32,
    pub height: u32,
}
impl_from_for_interconvertible_structs!(virtio_video_crop, Crop, left, top, width, height);

#[derive(PartialEq, Eq, Debug, Default, Clone, Copy)]
pub struct PlaneFormat {
    pub plane_size: u32,
    pub stride: u32,
}
impl_from_for_interconvertible_structs!(virtio_video_plane_format, PlaneFormat, plane_size, stride);

impl PlaneFormat {
    pub fn get_plane_layout(format: Format, width: u32, height: u32) -> Option<Vec<PlaneFormat>> {
        // Halved size for UV sampling, but rounded up to cover all samples in case of odd input
        // resolution.
        let half_width = (width + 1) / 2;
        let half_height = (height + 1) / 2;
        match format {
            Format::NV12 => Some(vec![
                // Y plane, 1 sample per pixel.
                PlaneFormat {
                    plane_size: width * height,
                    stride: width,
                },
                // UV plane, 1 sample per group of 4 pixels for U and V.
                PlaneFormat {
                    // Add one vertical line so odd resolutions result in an extra UV line to cover
                    // all the Y samples.
                    plane_size: width * half_height,
                    stride: width,
                },
            ]),
            Format::YUV420 => Some(vec![
                // Y plane, 1 sample per pixel.
                PlaneFormat {
                    plane_size: width * height,
                    stride: width,
                },
                // U plane, 1 sample per group of 4 pixels.
                PlaneFormat {
                    plane_size: half_width * half_height,
                    stride: half_width,
                },
                // V plane, same layout as U plane.
                PlaneFormat {
                    plane_size: half_width * half_height,
                    stride: half_width,
                },
            ]),
            _ => None,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct FormatRange {
    pub min: u32,
    pub max: u32,
    pub step: u32,
}
impl_from_for_interconvertible_structs!(virtio_video_format_range, FormatRange, min, max, step);

#[derive(Debug, Default, Clone)]
pub struct FrameFormat {
    pub width: FormatRange,
    pub height: FormatRange,
    pub bitrates: Vec<FormatRange>,
}

impl Response for FrameFormat {
    fn write(&self, w: &mut Writer) -> Result<(), io::Error> {
        w.write_obj(virtio_video_format_frame {
            width: self.width.into(),
            height: self.height.into(),
            num_rates: Le32::from(self.bitrates.len() as u32),
            ..Default::default()
        })?;
        w.write_iter(
            self.bitrates
                .iter()
                .map(|r| Into::<virtio_video_format_range>::into(*r)),
        )
    }
}

#[derive(Debug, Clone)]
pub struct FormatDesc {
    pub mask: u64,
    pub format: Format,
    pub frame_formats: Vec<FrameFormat>,
    pub plane_align: u32,
}

impl Response for FormatDesc {
    fn write(&self, w: &mut Writer) -> Result<(), io::Error> {
        w.write_obj(virtio_video_format_desc {
            mask: self.mask.into(),
            format: Le32::from(self.format as u32),
            // ChromeOS only supports single-buffer mode.
            planes_layout: Le32::from(VIRTIO_VIDEO_PLANES_LAYOUT_SINGLE_BUFFER),
            // No alignment is required on boards that we currently support.
            plane_align: Le32::from(self.plane_align),
            num_frames: Le32::from(self.frame_formats.len() as u32),
        })?;
        self.frame_formats.iter().try_for_each(|ff| ff.write(w))
    }
}

#[cfg(feature = "video-encoder")]
fn clamp_size(size: u32, min: u32, step: u32) -> u32 {
    match step {
        0 | 1 => size,
        _ => {
            let step_mod = (size - min) % step;
            if step_mod == 0 {
                size
            } else {
                size - step_mod + step
            }
        }
    }
}

/// Parses a slice of valid frame formats and the desired resolution
/// and returns the closest available resolution.
#[cfg(feature = "video-encoder")]
pub fn find_closest_resolution(
    frame_formats: &[FrameFormat],
    desired_width: u32,
    desired_height: u32,
) -> (u32, u32) {
    for FrameFormat { width, height, .. } in frame_formats.iter() {
        if desired_width < width.min || desired_width > width.max {
            continue;
        }
        if desired_height < height.min || desired_height > height.max {
            continue;
        }
        let allowed_width = clamp_size(desired_width, width.min, width.step);
        let allowed_height = clamp_size(desired_height, height.min, height.step);
        return (allowed_width, allowed_height);
    }

    // Return the resolution with maximum surface if nothing better is found.
    match frame_formats
        .iter()
        .max_by_key(|format| format.width.max * format.height.max)
    {
        None => (0, 0),
        Some(format) => (format.width.max, format.height.max),
    }
}

/// A rectangle used to describe portions of a frame.
#[derive(Debug, Eq, PartialEq)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

/// Description of the layout for a single plane.
#[derive(Debug, Clone)]
pub struct FramePlane {
    pub offset: usize,
    pub stride: usize,
    pub size: usize,
}

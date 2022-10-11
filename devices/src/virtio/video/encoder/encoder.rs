// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;

use base::error;

use crate::virtio::video::error::VideoError;
use crate::virtio::video::error::VideoResult;
use crate::virtio::video::format::find_closest_resolution;
use crate::virtio::video::format::Bitrate;
use crate::virtio::video::format::Format;
use crate::virtio::video::format::FormatDesc;
use crate::virtio::video::format::Level;
use crate::virtio::video::format::PlaneFormat;
use crate::virtio::video::format::Profile;
use crate::virtio::video::params::Params;

pub type InputBufferId = u32;
pub type OutputBufferId = u32;

#[derive(Debug)]
pub enum EncoderEvent {
    RequireInputBuffers {
        input_count: u32,
        input_frame_width: u32,
        input_frame_height: u32,
        output_buffer_size: u32,
    },
    ProcessedInputBuffer {
        id: InputBufferId,
    },
    ProcessedOutputBuffer {
        id: OutputBufferId,
        bytesused: u32,
        keyframe: bool,
        timestamp: u64,
    },
    FlushResponse {
        flush_done: bool,
    },
    #[allow(dead_code)]
    NotifyError {
        error: VideoError,
    },
}

#[derive(Debug)]
pub struct SessionConfig {
    pub src_params: Params,
    pub dst_params: Params,
    pub dst_profile: Profile,
    pub dst_bitrate: Bitrate,
    pub dst_h264_level: Option<Level>,
    pub frame_rate: u32,
}

#[derive(Clone)]
pub struct EncoderCapabilities {
    pub input_format_descs: Vec<FormatDesc>,
    pub output_format_descs: Vec<FormatDesc>,
    pub coded_format_profiles: BTreeMap<Format, Vec<Profile>>,
}

impl EncoderCapabilities {
    pub fn populate_src_params(
        &self,
        src_params: &mut Params,
        desired_format: Format,
        desired_width: u32,
        desired_height: u32,
        mut stride: u32,
    ) -> VideoResult<()> {
        let format_desc = self
            .input_format_descs
            .iter()
            .find(|&format_desc| format_desc.format == desired_format)
            .unwrap_or(
                self.input_format_descs
                    .get(0)
                    .ok_or(VideoError::InvalidFormat)?,
            );

        let (allowed_width, allowed_height) =
            find_closest_resolution(&format_desc.frame_formats, desired_width, desired_height);

        if stride == 0 {
            stride = allowed_width;
        }

        let plane_formats =
            PlaneFormat::get_plane_layout(format_desc.format, stride, allowed_height)
                .ok_or(VideoError::InvalidFormat)?;

        src_params.frame_width = allowed_width;
        src_params.frame_height = allowed_height;
        src_params.format = Some(format_desc.format);
        src_params.plane_formats = plane_formats;
        Ok(())
    }

    pub fn populate_dst_params(
        &self,
        dst_params: &mut Params,
        desired_format: Format,
        buffer_size: u32,
    ) -> VideoResult<()> {
        // TODO(alexlau): Should the first be the default?
        let format_desc = self
            .output_format_descs
            .iter()
            .find(move |&format_desc| format_desc.format == desired_format)
            .unwrap_or(
                self.output_format_descs
                    .get(0)
                    .ok_or(VideoError::InvalidFormat)?,
            );
        dst_params.format = Some(format_desc.format);

        // The requested output buffer size might be adjusted by the encoder to match hardware
        // requirements in RequireInputBuffers.
        dst_params.plane_formats = vec![PlaneFormat {
            plane_size: buffer_size,
            stride: 0,
        }];
        Ok(())
    }

    pub fn get_profiles(&self, coded_format: &Format) -> Option<&Vec<Profile>> {
        self.coded_format_profiles.get(coded_format)
    }

    pub fn get_default_profile(&self, coded_format: &Format) -> Option<Profile> {
        let profiles = self.get_profiles(coded_format)?;
        match profiles.get(0) {
            None => {
                error!("Format {} exists but no available profiles.", coded_format);
                None
            }
            Some(profile) => Some(*profile),
        }
    }
}

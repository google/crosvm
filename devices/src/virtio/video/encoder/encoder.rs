// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::fs::File;

use base::error;

use crate::virtio::video::params::Params;
use crate::virtio::video::{
    error::{VideoError, VideoResult},
    format::{find_closest_resolution, Format, FormatDesc, Level, PlaneFormat, Profile},
};

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
    NotifyError {
        error: VideoError,
    },
}

#[derive(Debug)]
pub struct SessionConfig {
    pub src_params: Params,
    pub dst_params: Params,
    pub dst_profile: Profile,
    pub dst_bitrate: u32,
    pub dst_h264_level: Option<Level>,
    pub frame_rate: u32,
}

#[derive(Debug)]
pub struct VideoFramePlane {
    pub offset: usize,
    pub stride: usize,
}

pub trait EncoderSession {
    /// Encodes the frame provided by `resource`, with planes specified by `plane`.
    /// `force_keyframe` forces the frame to be encoded as a keyframe.
    /// When the buffer has been successfully processed, a `ProcessedInputBuffer` event will
    /// be readable from the event pipe, with the same `InputBufferId` as returned by this
    /// function.
    /// When the corresponding encoded data is ready, `ProcessedOutputBuffer` events will be
    /// readable from the event pipe, with the same timestamp as provided `timestamp`.
    fn encode(
        &mut self,
        resource: File,
        planes: &[VideoFramePlane],
        timestamp: u64,
        force_keyframe: bool,
    ) -> VideoResult<InputBufferId>;

    /// Provides an output buffer `file` to store encoded output, where `offset` and `size`
    /// define the region of memory to use.
    /// When the buffer has been filled with encoded output, a `ProcessedOutputBuffer` event
    /// will be readable from the event pipe, with the same `OutputBufferId` as returned by this
    /// function.
    fn use_output_buffer(
        &mut self,
        file: File,
        offset: u32,
        size: u32,
    ) -> VideoResult<OutputBufferId>;

    /// Requests the encoder to flush. When completed, an `EncoderEvent::FlushResponse` event will
    /// be readable from the event pipe.
    fn flush(&mut self) -> VideoResult<()>;

    /// Requests the encoder to use new encoding parameters provided by `bitrate` and `framerate`.
    fn request_encoding_params_change(&mut self, bitrate: u32, framerate: u32) -> VideoResult<()>;

    /// Returns the event pipe as a pollable file descriptor. When the file descriptor is
    /// readable, an event can be read by `read_event`.
    fn event_pipe(&self) -> &File;

    /// Performs a blocking read for an encoder event. This function should only be called when
    /// the file descriptor returned by `event_pipe` is readable.
    fn read_event(&mut self) -> VideoResult<EncoderEvent>;
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

        let plane_formats = match format_desc.format {
            Format::NV12 => {
                let y_plane = PlaneFormat {
                    plane_size: stride * allowed_height,
                    stride,
                };
                let crcb_plane = PlaneFormat {
                    plane_size: y_plane.plane_size / 2,
                    stride,
                };
                vec![y_plane, crcb_plane]
            }
            _ => {
                return Err(VideoError::InvalidFormat);
            }
        };

        src_params.frame_width = allowed_width;
        src_params.frame_height = allowed_height;
        src_params.format = Some(format_desc.format.clone());
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
        dst_params.format = Some(format_desc.format.clone());

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

pub trait Encoder {
    type Session: EncoderSession;

    fn query_capabilities(&self) -> VideoResult<EncoderCapabilities>;
    fn start_session(&mut self, config: SessionConfig) -> VideoResult<Self::Session>;
    fn stop_session(&mut self, session: Self::Session) -> VideoResult<()>;
}

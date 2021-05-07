// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::{error, warn, RawDescriptor};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use thiserror::Error as ThisError;

use libvda::decode::Event as LibvdaEvent;

use crate::virtio::video::{
    decoder::{backend::*, Capability, Decoder},
    error::{VideoError, VideoResult},
    format::*,
};

#[derive(Debug, ThisError)]
#[error("VDA Failure: {0}")]
struct VdaFailure(libvda::decode::Response);

impl TryFrom<Format> for libvda::Profile {
    type Error = VideoError;

    fn try_from(format: Format) -> Result<Self, Self::Error> {
        Ok(match format {
            Format::VP8 => libvda::Profile::VP8,
            Format::VP9 => libvda::Profile::VP9Profile0,
            Format::H264 => libvda::Profile::H264ProfileBaseline,
            _ => {
                error!("specified format {} is not supported by VDA", format);
                return Err(VideoError::InvalidParameter);
            }
        })
    }
}

impl TryFrom<Format> for libvda::PixelFormat {
    type Error = VideoError;

    fn try_from(format: Format) -> Result<Self, Self::Error> {
        Ok(match format {
            Format::NV12 => libvda::PixelFormat::NV12,
            _ => {
                error!("specified format {} is not supported by VDA", format);
                return Err(VideoError::InvalidParameter);
            }
        })
    }
}

impl From<&FramePlane> for libvda::FramePlane {
    fn from(plane: &FramePlane) -> Self {
        libvda::FramePlane {
            offset: plane.offset,
            stride: plane.stride,
        }
    }
}

impl From<libvda::decode::Event> for DecoderEvent {
    fn from(event: libvda::decode::Event) -> Self {
        // We cannot use the From trait here since neither libvda::decode::Response
        // no std::result::Result are defined in the current crate.
        fn vda_response_to_result(resp: libvda::decode::Response) -> VideoResult<()> {
            match resp {
                libvda::decode::Response::Success => Ok(()),
                resp => Err(VideoError::BackendFailure(Box::new(VdaFailure(resp)))),
            }
        }

        match event {
            LibvdaEvent::ProvidePictureBuffers {
                min_num_buffers,
                width,
                height,
                visible_rect_left,
                visible_rect_top,
                visible_rect_right,
                visible_rect_bottom,
            } => DecoderEvent::ProvidePictureBuffers {
                min_num_buffers,
                width,
                height,
                visible_rect: Rect {
                    left: visible_rect_left,
                    top: visible_rect_top,
                    right: visible_rect_right,
                    bottom: visible_rect_bottom,
                },
            },
            LibvdaEvent::PictureReady {
                buffer_id,
                bitstream_id,
                left,
                top,
                right,
                bottom,
            } => DecoderEvent::PictureReady {
                picture_buffer_id: buffer_id,
                bitstream_id,
                visible_rect: Rect {
                    left,
                    top,
                    right,
                    bottom,
                },
            },
            LibvdaEvent::NotifyEndOfBitstreamBuffer { bitstream_id } => {
                DecoderEvent::NotifyEndOfBitstreamBuffer(bitstream_id)
            }
            LibvdaEvent::NotifyError(resp) => {
                DecoderEvent::NotifyError(VideoError::BackendFailure(Box::new(VdaFailure(resp))))
            }
            LibvdaEvent::ResetResponse(resp) => {
                DecoderEvent::ResetCompleted(vda_response_to_result(resp))
            }
            LibvdaEvent::FlushResponse(resp) => {
                DecoderEvent::FlushCompleted(vda_response_to_result(resp))
            }
        }
    }
}

// Used by DecoderSession::get_capabilities().
fn from_pixel_format(
    fmt: &libvda::PixelFormat,
    mask: u64,
    width_range: FormatRange,
    height_range: FormatRange,
) -> FormatDesc {
    let format = match fmt {
        libvda::PixelFormat::NV12 => Format::NV12,
        libvda::PixelFormat::YV12 => Format::YUV420,
    };

    let frame_formats = vec![FrameFormat {
        width: width_range,
        height: height_range,
        bitrates: Vec::new(),
    }];

    FormatDesc {
        mask,
        format,
        frame_formats,
    }
}

impl DecoderSession for libvda::decode::Session {
    fn set_output_buffer_count(&self, count: usize) -> VideoResult<()> {
        Ok(self.set_output_buffer_count(count)?)
    }

    fn decode(
        &self,
        bitstream_id: i32,
        descriptor: RawDescriptor,
        offset: u32,
        bytes_used: u32,
    ) -> VideoResult<()> {
        Ok(self.decode(bitstream_id, descriptor, offset, bytes_used)?)
    }

    fn flush(&self) -> VideoResult<()> {
        Ok(self.flush()?)
    }

    fn reset(&self) -> VideoResult<()> {
        Ok(self.reset()?)
    }

    fn event_pipe(&self) -> &std::fs::File {
        self.pipe()
    }

    fn use_output_buffer(
        &self,
        picture_buffer_id: i32,
        format: Format,
        output_buffer: RawDescriptor,
        planes: &[FramePlane],
        modifier: u64,
    ) -> VideoResult<()> {
        let vda_planes: Vec<libvda::FramePlane> = planes.iter().map(Into::into).collect();
        Ok(self.use_output_buffer(
            picture_buffer_id,
            libvda::PixelFormat::try_from(format)?,
            output_buffer,
            &vda_planes,
            modifier,
        )?)
    }

    fn reuse_output_buffer(&self, picture_buffer_id: i32) -> VideoResult<()> {
        Ok(self.reuse_output_buffer(picture_buffer_id)?)
    }

    fn read_event(&mut self) -> VideoResult<DecoderEvent> {
        self.read_event().map(Into::into).map_err(Into::into)
    }
}

impl DecoderBackend for libvda::decode::VdaInstance {
    type Session = libvda::decode::Session;

    fn new_session(&self, format: Format) -> VideoResult<Self::Session> {
        let profile = libvda::Profile::try_from(format)?;

        self.open_session(profile).map_err(|e| {
            error!("failed to open a session for {:?}: {}", format, e);
            VideoError::InvalidOperation
        })
    }

    fn get_capabilities(&self) -> Capability {
        let caps = libvda::decode::VdaInstance::get_capabilities(self);

        // Raise the first |# of supported raw formats|-th bits because we can assume that any
        // combination of (a coded format, a raw format) is valid in Chrome.
        let mask = !(u64::max_value() << caps.output_formats.len());

        let mut in_fmts = vec![];
        let mut profiles: BTreeMap<Format, Vec<Profile>> = Default::default();
        for fmt in caps.input_formats.iter() {
            match Profile::from_libvda_profile(fmt.profile) {
                Some(profile) => {
                    let format = profile.to_format();
                    in_fmts.push(FormatDesc {
                        mask,
                        format,
                        frame_formats: vec![Default::default()],
                    });
                    match profiles.entry(format) {
                        Entry::Occupied(mut e) => e.get_mut().push(profile),
                        Entry::Vacant(e) => {
                            e.insert(vec![profile]);
                        }
                    }
                }
                None => {
                    warn!(
                        "No virtio-video equivalent for libvda profile, skipping: {:?}",
                        fmt.profile
                    );
                }
            }
        }

        let levels: BTreeMap<Format, Vec<Level>> = if profiles.contains_key(&Format::H264) {
            // We only support Level 1.0 for H.264.
            vec![(Format::H264, vec![Level::H264_1_0])]
                .into_iter()
                .collect()
        } else {
            Default::default()
        };

        // Prepare {min, max} of {width, height}.
        // While these values are associated with each input format in libvda,
        // they are associated with each output format in virtio-video protocol.
        // Thus, we compute max of min values and min of max values here.
        let min_width = caps.input_formats.iter().map(|fmt| fmt.min_width).max();
        let max_width = caps.input_formats.iter().map(|fmt| fmt.max_width).min();
        let min_height = caps.input_formats.iter().map(|fmt| fmt.min_height).max();
        let max_height = caps.input_formats.iter().map(|fmt| fmt.max_height).min();
        let width_range = FormatRange {
            min: min_width.unwrap_or(0),
            max: max_width.unwrap_or(0),
            step: 1,
        };
        let height_range = FormatRange {
            min: min_height.unwrap_or(0),
            max: max_height.unwrap_or(0),
            step: 1,
        };

        // Raise the first |# of supported coded formats|-th bits because we can assume that any
        // combination of (a coded format, a raw format) is valid in Chrome.
        let mask = !(u64::max_value() << caps.input_formats.len());
        let out_fmts = caps
            .output_formats
            .iter()
            .map(|fmt| from_pixel_format(fmt, mask, width_range, height_range))
            .collect();

        Capability::new(in_fmts, out_fmts, profiles, levels)
    }
}

/// Create a new decoder instance using a Libvda decoder instance to perform
/// the decoding.
impl Decoder<libvda::decode::VdaInstance> {
    pub fn new() -> VideoResult<Self> {
        let vda = libvda::decode::VdaInstance::new(libvda::decode::VdaImplType::Gavda)?;
        Ok(Decoder::from_backend(vda))
    }
}

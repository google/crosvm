// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::error;
use std::convert::TryFrom;
use std::os::unix::io::RawFd;

use crate::virtio::video::{
    decoder::backend::*,
    error::{VideoError, VideoResult},
    format::Format,
};

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

pub struct LibvdaSession<'a> {
    session: libvda::decode::Session<'a>,
}

impl<'a> DecoderSession for LibvdaSession<'a> {
    fn set_output_buffer_count(&self, count: usize) -> VideoResult<()> {
        Ok(self.session.set_output_buffer_count(count)?)
    }

    fn decode(
        &self,
        bitstream_id: i32,
        fd: RawFd,
        offset: u32,
        bytes_used: u32,
    ) -> VideoResult<()> {
        Ok(self.session.decode(bitstream_id, fd, offset, bytes_used)?)
    }

    fn flush(&self) -> VideoResult<()> {
        Ok(self.session.flush()?)
    }

    fn reset(&self) -> VideoResult<()> {
        Ok(self.session.reset()?)
    }

    fn event_pipe(&self) -> &std::fs::File {
        self.session.pipe()
    }

    fn use_output_buffer(
        &self,
        picture_buffer_id: i32,
        format: Format,
        output_buffer: RawFd,
        planes: &[FramePlane],
    ) -> VideoResult<()> {
        let vda_planes: Vec<libvda::FramePlane> = planes.into_iter().map(Into::into).collect();
        Ok(self.session.use_output_buffer(
            picture_buffer_id,
            libvda::PixelFormat::try_from(format)?,
            output_buffer,
            &vda_planes,
        )?)
    }

    fn reuse_output_buffer(&self, picture_buffer_id: i32) -> VideoResult<()> {
        Ok(self.session.reuse_output_buffer(picture_buffer_id)?)
    }

    fn read_event(&mut self) -> VideoResult<libvda::decode::Event> {
        Ok(self.session.read_event()?)
    }
}

impl<'a> DecoderBackend for &'a libvda::decode::VdaInstance {
    type Session = LibvdaSession<'a>;

    fn new_session(&self, format: Format) -> VideoResult<Self::Session> {
        let profile = libvda::Profile::try_from(format)?;
        let session = self.open_session(profile).map_err(|e| {
            error!("failed to open a session for {:?}: {}", format, e);
            VideoError::InvalidOperation
        })?;

        Ok(LibvdaSession { session })
    }
}

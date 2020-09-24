// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::os::unix::io::RawFd;

use crate::virtio::video::decoder::backend::*;

pub struct LibvdaSession<'a> {
    session: libvda::decode::Session<'a>,
}

impl<'a> DecoderSession for LibvdaSession<'a> {
    fn set_output_buffer_count(&self, count: usize) -> libvda::Result<()> {
        self.session.set_output_buffer_count(count)
    }

    fn decode(
        &self,
        bitstream_id: i32,
        fd: RawFd,
        offset: u32,
        bytes_used: u32,
    ) -> libvda::Result<()> {
        self.session.decode(bitstream_id, fd, offset, bytes_used)
    }

    fn flush(&self) -> libvda::Result<()> {
        self.session.flush()
    }

    fn reset(&self) -> libvda::Result<()> {
        self.session.reset()
    }

    fn event_pipe(&self) -> &std::fs::File {
        self.session.pipe()
    }

    fn use_output_buffer(
        &self,
        picture_buffer_id: i32,
        format: libvda::PixelFormat,
        output_buffer: RawFd,
        planes: &[libvda::FramePlane],
    ) -> libvda::Result<()> {
        self.session
            .use_output_buffer(picture_buffer_id, format, output_buffer, planes)
    }

    fn reuse_output_buffer(&self, picture_buffer_id: i32) -> libvda::Result<()> {
        self.session.reuse_output_buffer(picture_buffer_id)
    }

    fn read_event(&mut self) -> libvda::Result<libvda::decode::Event> {
        self.session.read_event()
    }
}

impl<'a> DecoderBackend for &'a libvda::decode::VdaInstance {
    type Session = LibvdaSession<'a>;

    fn new_session(&self, profile: libvda::Profile) -> libvda::Result<Self::Session> {
        Ok(LibvdaSession {
            session: self.open_session(profile)?,
        })
    }
}

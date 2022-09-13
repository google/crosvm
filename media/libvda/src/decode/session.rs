// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::Read;
use std::mem;
use std::os::unix::io::FromRawFd;
use std::rc::Rc;

use super::bindings;
use super::event::*;
use super::VdaConnection;
use crate::error::*;
use crate::format::BufferFd;
use crate::format::FramePlane;
use crate::format::PixelFormat;
use crate::format::Profile;

/// Represents a decode session.
pub struct Session {
    // Ensures the VDA connection remains open for as long as there are active sessions.
    connection: Rc<VdaConnection>,
    // Pipe file to be notified decode session events.
    pipe: File,
    session_ptr: *mut bindings::vda_session_info_t,
}

impl Session {
    /// Creates a new `Session`.
    pub(super) fn new(connection: &Rc<VdaConnection>, profile: Profile) -> Option<Self> {
        // Safe because `conn_ptr()` is valid and won't be invalidated by `init_decode_session()`.
        let session_ptr: *mut bindings::vda_session_info_t = unsafe {
            bindings::init_decode_session(connection.conn_ptr(), profile.to_raw_profile())
        };

        if session_ptr.is_null() {
            return None;
        }

        // Dereferencing `session_ptr` is safe because it is a valid pointer to a FD provided by
        // libvda. We need to dup() the `event_pipe_fd` because File object close() the FD while
        // libvda also close() it when `close_decode_session` is called.
        let pipe = unsafe { File::from_raw_fd(libc::dup((*session_ptr).event_pipe_fd)) };

        Some(Session {
            connection: Rc::clone(connection),
            pipe,
            session_ptr,
        })
    }

    /// Gets a reference of pipe that notifies events from VDA session.
    pub fn pipe(&self) -> &File {
        &self.pipe
    }

    /// Reads an `Event` object from a pipe provided a decode session.
    pub fn read_event(&mut self) -> Result<Event> {
        const BUF_SIZE: usize = mem::size_of::<bindings::vda_event_t>();
        let mut buf = [0u8; BUF_SIZE];

        self.pipe
            .read_exact(&mut buf)
            .map_err(Error::ReadEventFailure)?;

        // Safe because libvda must have written vda_event_t to the pipe.
        let vda_event = unsafe { mem::transmute::<[u8; BUF_SIZE], bindings::vda_event_t>(buf) };

        // Safe because `vda_event` is a value read from `self.pipe`.
        unsafe { Event::new(vda_event) }
    }

    /// Sends a decode request for a bitstream buffer given as `fd`.
    ///
    /// `fd` will be closed by Chrome after decoding has occurred.
    pub fn decode(
        &self,
        bitstream_id: i32,
        fd: BufferFd,
        offset: u32,
        bytes_used: u32,
    ) -> Result<()> {
        // Safe because `session_ptr` is valid and a libvda's API is called properly.
        let r = unsafe {
            bindings::vda_decode(
                (*self.session_ptr).ctx,
                bitstream_id,
                fd,
                offset,
                bytes_used,
            )
        };
        Response::new(r).into()
    }

    /// Sets the number of expected output buffers.
    ///
    /// This function must be called after `Event::ProvidePictureBuffers` are notified.
    /// After calling this function, `user_output_buffer` must be called `num_output_buffers` times.
    pub fn set_output_buffer_count(&self, num_output_buffers: usize) -> Result<()> {
        // Safe because `session_ptr` is valid and a libvda's API is called properly.
        let r = unsafe {
            bindings::vda_set_output_buffer_count((*self.session_ptr).ctx, num_output_buffers)
        };
        Response::new(r).into()
    }

    /// Provides an output buffer that will be filled with decoded frames.
    ///
    /// Users calls this function after `set_output_buffer_count`. Then, libvda
    /// will fill next frames in the buffer and noitify `Event::PictureReady`.
    ///
    /// This function is also used to notify that they consumed decoded frames
    /// in the output buffer.
    ///
    /// This function takes ownership of `output_buffer`.
    pub fn use_output_buffer(
        &self,
        picture_buffer_id: i32,
        format: PixelFormat,
        output_buffer: BufferFd,
        planes: &[FramePlane],
        modifier: u64,
    ) -> Result<()> {
        let mut planes: Vec<_> = planes.iter().map(FramePlane::to_raw_frame_plane).collect();

        // Safe because `session_ptr` is valid and a libvda's API is called properly.
        let r = unsafe {
            bindings::vda_use_output_buffer(
                (*self.session_ptr).ctx,
                picture_buffer_id,
                format.to_raw_pixel_format(),
                output_buffer,
                planes.len(),
                planes.as_mut_ptr(),
                modifier,
            )
        };
        Response::new(r).into()
    }

    /// Returns an output buffer for reuse.
    ///
    /// `picture_buffer_id` must be a value for which `use_output_buffer` has been called already.
    pub fn reuse_output_buffer(&self, picture_buffer_id: i32) -> Result<()> {
        // Safe because `session_ptr` is valid and a libvda's API is called properly.
        let r = unsafe {
            bindings::vda_reuse_output_buffer((*self.session_ptr).ctx, picture_buffer_id)
        };
        Response::new(r).into()
    }

    /// Flushes the decode session.
    ///
    /// When this operation has completed, `Event::FlushResponse` will be notified.
    pub fn flush(&self) -> Result<()> {
        // Safe because `session_ptr` is valid and a libvda's API is called properly.
        let r = unsafe { bindings::vda_flush((*self.session_ptr).ctx) };
        Response::new(r).into()
    }

    /// Resets the decode session.
    ///
    /// When this operation has completed, Event::ResetResponse will be notified.
    pub fn reset(&self) -> Result<()> {
        // Safe because `session_ptr` is valid and a libvda's API is called properly.
        let r = unsafe { bindings::vda_reset((*self.session_ptr).ctx) };
        Response::new(r).into()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Safe because `session_ptr` is unchanged from the time `new` was called, and
        // `connection` also guarantees that the pointer returned by `conn_ptr()` is a valid
        // connection to a VDA instance.
        unsafe {
            bindings::close_decode_session(self.connection.conn_ptr(), self.session_ptr);
        }
    }
}

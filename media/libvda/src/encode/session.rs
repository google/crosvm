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
use super::format::Bitrate;
use super::vea_instance::Config;
use super::VeaConnection;
use crate::error::*;
use crate::format::BufferFd;
use crate::format::FramePlane;

pub type VeaInputBufferId = bindings::vea_input_buffer_id_t;
pub type VeaOutputBufferId = bindings::vea_output_buffer_id_t;

/// Represents an encode session.
pub struct Session {
    // Pipe file to be notified encode session events.
    pipe: File,
    // Ensures the VEA connection remains open for as long as there are active sessions.
    connection: Rc<VeaConnection>,
    session_ptr: *mut bindings::vea_session_info_t,
}

fn convert_error_code(code: i32) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(Error::EncodeSessionFailure(code))
    }
}

impl Session {
    /// Creates a new `Session`.
    pub(super) fn new(connection: &Rc<VeaConnection>, config: Config) -> Option<Self> {
        // Safe because `conn_ptr()` is valid and won't be invalidated by `init_encode_session()`.
        let session_ptr: *mut bindings::vea_session_info_t = unsafe {
            bindings::init_encode_session(connection.conn_ptr(), &mut config.to_raw_config())
        };

        if session_ptr.is_null() {
            return None;
        }

        // Dereferencing `session_ptr` is safe because it is a valid pointer to a FD provided by
        // libvda. We need to dup() the `event_pipe_fd` because File object close() the FD while
        // libvda also close() it when `close_encode_session` is called.
        // Calling `from_raw_fd` here is safe because the dup'ed FD is not going to be used by
        // anything else and `pipe` has full ownership of it.
        let pipe = unsafe { File::from_raw_fd(libc::dup((*session_ptr).event_pipe_fd)) };

        Some(Session {
            connection: Rc::clone(connection),
            pipe,
            session_ptr,
        })
    }

    /// Returns a reference for the pipe that notifies of encode events.
    pub fn pipe(&self) -> &File {
        &self.pipe
    }

    /// Reads an `Event` object from a pipe provided by an encode session.
    pub fn read_event(&mut self) -> Result<Event> {
        const BUF_SIZE: usize = mem::size_of::<bindings::vea_event_t>();
        let mut buf = [0u8; BUF_SIZE];

        self.pipe
            .read_exact(&mut buf)
            .map_err(Error::ReadEventFailure)?;

        // Safe because libvda must have written vea_event_t to the pipe.
        let vea_event = unsafe { mem::transmute::<[u8; BUF_SIZE], bindings::vea_event_t>(buf) };

        // Safe because `vea_event` is a value read from `self.pipe`.
        unsafe { Event::new(vea_event) }
    }

    /// Sends an encode request for an input buffer given as `fd` with planes described
    /// by `planes. The timestamp of the frame to encode is typically provided in
    /// milliseconds by `timestamp`. `force_keyframe` indicates to the encoder that
    /// the frame should be encoded as a keyframe.
    ///
    /// When the input buffer has been filled, an `EncoderEvent::ProcessedInputBuffer`
    /// event can be read from the event pipe.
    ///
    /// The caller is responsible for passing in a unique value for `input_buffer_id`
    /// which can be referenced when the event is received.
    ///
    /// `fd` will be closed after encoding has occurred.
    pub fn encode(
        &self,
        input_buffer_id: VeaInputBufferId,
        fd: BufferFd,
        planes: &[FramePlane],
        timestamp: i64,
        force_keyframe: bool,
    ) -> Result<()> {
        let mut planes: Vec<_> = planes.iter().map(FramePlane::to_raw_frame_plane).collect();

        // Safe because `session_ptr` is valid and libvda's encode API is called properly.
        let r = unsafe {
            bindings::vea_encode(
                (*self.session_ptr).ctx,
                input_buffer_id,
                fd,
                planes.len(),
                planes.as_mut_ptr(),
                timestamp,
                force_keyframe.into(),
            )
        };
        convert_error_code(r)
    }

    /// Provides a buffer for storing encoded output.
    ///
    /// When the output buffer has been filled, an `EncoderEvent::ProcessedOutputBuffer`
    /// event can be read from the event pipe.
    ///
    /// The caller is responsible for passing in a unique value for `output_buffer_id`
    /// which can be referenced when the event is received.
    ///
    /// This function takes ownership of `fd`.
    pub fn use_output_buffer(
        &self,
        output_buffer_id: VeaOutputBufferId,
        fd: BufferFd,
        offset: u32,
        size: u32,
    ) -> Result<()> {
        // Safe because `session_ptr` is valid and libvda's encode API is called properly.
        let r = unsafe {
            bindings::vea_use_output_buffer(
                (*self.session_ptr).ctx,
                output_buffer_id,
                fd,
                offset,
                size,
            )
        };
        convert_error_code(r)
    }

    /// Requests encoding parameter changes.
    ///
    /// The request is not guaranteed to be honored by libvda and could be ignored
    /// by the backing encoder implementation.
    pub fn request_encoding_params_change(&self, bitrate: Bitrate, framerate: u32) -> Result<()> {
        // Safe because `session_ptr` is valid and libvda's encode API is called properly.
        let r = unsafe {
            bindings::vea_request_encoding_params_change(
                (*self.session_ptr).ctx,
                bitrate.to_raw_bitrate(),
                framerate,
            )
        };
        convert_error_code(r)
    }

    /// Flushes the encode session.
    ///
    /// When this operation has completed, Event::FlushResponse can be read from
    /// the event pipe.
    pub fn flush(&self) -> Result<()> {
        // Safe because `session_ptr` is valid and libvda's encode API is called properly.
        let r = unsafe { bindings::vea_flush((*self.session_ptr).ctx) };
        convert_error_code(r)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Safe because `session_ptr` is unchanged from the time `new` was called, and
        // `connection` also guarantees that the pointer returned by `conn_ptr()` is a valid
        // connection to a VEA instance.
        unsafe {
            bindings::close_encode_session(self.connection.conn_ptr(), self.session_ptr);
        }
    }
}

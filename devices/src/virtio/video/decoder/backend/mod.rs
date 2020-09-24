// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module implements the interface that actual decoder devices need to
//! implement in order to provide video decoding capability to the guest.

use std::{fs::File, os::unix::io::RawFd};

pub mod vda;

/// Contains the device's state for one playback session, i.e. one stream.
pub trait DecoderSession {
    /// Tell how many output buffers will be used for this session. This method
    /// Must be called after a `ProvidePictureBuffers` event is emitted, and
    /// before the first call to `use_output_buffers()`.
    fn set_output_buffer_count(&self, count: usize) -> libvda::Result<()>;

    /// Decode the compressed stream contained in [`offset`..`offset`+`bytes_used`]
    /// of the shared memory in `fd`. `bitstream_id` is the identifier for that
    /// part of the stream (most likely, a timestamp).
    ///
    /// The device takes ownership of `fd` and is responsible for closing it
    /// once it is not used anymore.
    ///
    /// The device will emit a `NotifyEndOfBitstreamBuffer` event after the input
    /// buffer has been entirely processed.
    ///
    /// The device will emit a `PictureReady` event with the `bitstream_id` field
    /// set to the same value as the argument of the same name for each picture
    /// produced from that input buffer.
    fn decode(
        &self,
        bitstream_id: i32,
        fd: RawFd,
        offset: u32,
        bytes_used: u32,
    ) -> libvda::Result<()>;

    /// Flush the decoder device, i.e. finish processing of all queued decode
    /// requests.
    ///
    /// The device will emit a `FlushReponse` event once the flush is done.
    fn flush(&self) -> libvda::Result<()>;

    /// Reset the decoder device, i.e. cancel all pending decoding requests.
    ///
    /// The device will emit a `ResetResponse` event once the reset is done.
    fn reset(&self) -> libvda::Result<()>;

    /// Returns the event pipe on which the availability of an event will be
    /// signaled.
    fn event_pipe(&self) -> &File;

    /// Ask the device to use the memory buffer in `output_buffer` to store
    /// decoded frames in pixel format `format`. `planes` describes how the
    /// frame's planes should be laid out in the buffer, and `picture_buffer_id`
    /// is the ID of the picture, that will be reproduced in `PictureReady` events
    /// using this buffer.
    ///
    /// The device takes ownership of `output_buffer` and is responsible for
    /// closing it once the buffer is not used anymore (either when the session
    /// is closed, or a new set of buffers is provided for the session).
    ///
    /// The device will emit a `PictureReady` event with the `picture_buffer_id`
    /// field set to the same value as the argument of the same name when a
    /// frame has been decoded into that buffer.
    fn use_output_buffer(
        &self,
        picture_buffer_id: i32,
        format: libvda::PixelFormat,
        output_buffer: RawFd,
        planes: &[libvda::FramePlane],
    ) -> libvda::Result<()>;

    /// Ask the device to reuse an output buffer previously passed to
    /// `use_output_buffer` and that has previously been returned to the decoder
    /// in a `PictureReady` event.
    ///
    /// The device will emit a `PictureReady` event with the `picture_buffer_id`
    /// field set to the same value as the argument of the same name when a
    /// frame has been decoded into that buffer.
    fn reuse_output_buffer(&self, picture_buffer_id: i32) -> libvda::Result<()>;

    /// Blocking call to read a single event from the event pipe.
    fn read_event(&mut self) -> libvda::Result<libvda::decode::Event>;
}

pub trait DecoderBackend {
    type Session: DecoderSession;

    /// Create a new decoding session for the passed `profile`.
    fn new_session(&self, profile: libvda::Profile) -> libvda::Result<Self::Session>;
}

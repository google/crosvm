// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module implements the interface that actual decoder devices need to
//! implement in order to provide video decoding capability to the guest.

use std::fs::File;

use crate::virtio::video::{
    error::{VideoError, VideoResult},
    format::{Format, Rect},
};
use base::RawDescriptor;

pub mod vda;

pub struct FramePlane {
    pub offset: i32,
    pub stride: i32,
}

/// Contains the device's state for one playback session, i.e. one stream.
pub trait DecoderSession {
    /// Tell how many output buffers will be used for this session. This method
    /// Must be called after a `ProvidePictureBuffers` event is emitted, and
    /// before the first call to `use_output_buffers()`.
    fn set_output_buffer_count(&self, count: usize) -> VideoResult<()>;

    /// Decode the compressed stream contained in [`offset`..`offset`+`bytes_used`]
    /// of the shared memory in `descriptor`. `bitstream_id` is the identifier for that
    /// part of the stream (most likely, a timestamp).
    ///
    /// The device takes ownership of `descriptor` and is responsible for closing it
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
        descriptor: RawDescriptor,
        offset: u32,
        bytes_used: u32,
    ) -> VideoResult<()>;

    /// Flush the decoder device, i.e. finish processing of all queued decode
    /// requests.
    ///
    /// The device will emit a `FlushCompleted` event once the flush is done.
    fn flush(&self) -> VideoResult<()>;

    /// Reset the decoder device, i.e. cancel all pending decoding requests.
    ///
    /// The device will emit a `ResetCompleted` event once the reset is done.
    fn reset(&self) -> VideoResult<()>;

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
        format: Format,
        output_buffer: RawDescriptor,
        planes: &[FramePlane],
        modifier: u64,
    ) -> VideoResult<()>;

    /// Ask the device to reuse an output buffer previously passed to
    /// `use_output_buffer` and that has previously been returned to the decoder
    /// in a `PictureReady` event.
    ///
    /// The device will emit a `PictureReady` event with the `picture_buffer_id`
    /// field set to the same value as the argument of the same name when a
    /// frame has been decoded into that buffer.
    fn reuse_output_buffer(&self, picture_buffer_id: i32) -> VideoResult<()>;

    /// Blocking call to read a single event from the event pipe.
    fn read_event(&mut self) -> VideoResult<DecoderEvent>;
}

pub trait DecoderBackend {
    type Session: DecoderSession;

    /// Create a new decoding session for the passed `profile`.
    fn new_session(&self, format: Format) -> VideoResult<Self::Session>;
}

#[derive(Debug)]
pub enum DecoderEvent {
    /// Emitted when the device knows the buffer format it will need to decode
    /// frames, and how many buffers it will need. The decoder is supposed to
    /// provide buffers of the requested dimensions using `use_output_buffer`.
    ProvidePictureBuffers {
        min_num_buffers: u32,
        width: i32,
        height: i32,
        visible_rect: Rect,
    },
    /// Emitted when the decoder is done decoding a picture. `picture_buffer_id`
    /// corresponds to the argument of the same name passed to `use_output_buffer()`
    /// or `reuse_output_buffer()`. `bitstream_id` corresponds to the argument of
    /// the same name passed to `decode()` and can be used to match decoded frames
    /// to the input buffer they were produced from.
    PictureReady {
        picture_buffer_id: i32,
        bitstream_id: i32,
        visible_rect: Rect,
    },
    /// Emitted when an input buffer passed to `decode()` is not used by the
    /// device anymore and can be reused by the decoder. The parameter corresponds
    /// to the `bitstream_id` argument passed to `decode()`.
    NotifyEndOfBitstreamBuffer(i32),
    /// Emitted when a decoding error has occured.
    NotifyError(VideoError),
    /// Emitted after `flush()` has been called to signal that the flush is completed.
    FlushCompleted(VideoResult<()>),
    /// Emitted after `reset()` has been called to signal that the reset is completed.
    ResetCompleted(VideoResult<()>),
}

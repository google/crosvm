// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! This module implements the interface that actual decoder devices need to
//! implement in order to provide video decoding capability to the guest.

use base::AsRawDescriptor;

use crate::virtio::video::decoder::Capability;
use crate::virtio::video::error::VideoError;
use crate::virtio::video::error::VideoResult;
use crate::virtio::video::format::Format;
use crate::virtio::video::format::Rect;
use crate::virtio::video::resource::GuestResource;
use crate::virtio::video::resource::GuestResourceHandle;

#[cfg(feature = "ffmpeg")]
pub mod ffmpeg;

#[cfg(feature = "vaapi")]
pub mod vaapi;
#[cfg(feature = "libvda")]
pub mod vda;

/// Contains the device's state for one playback session, i.e. one stream.
pub trait DecoderSession {
    /// Tell how many output buffers will be used for this session and which format they will carry.
    /// This method must be called after a `ProvidePictureBuffers` event is emitted, and before the
    /// first call to `use_output_buffer()`.
    fn set_output_parameters(&mut self, buffer_count: usize, format: Format) -> VideoResult<()>;

    /// Decode the compressed stream contained in [`offset`..`offset`+`bytes_used`] of the shared
    /// memory in the input `resource`.
    ///
    /// `resource_id` is the ID of the input resource. It will be signaled using the
    /// `NotifyEndOfBitstreamBuffer` once the input resource is not used anymore.
    ///
    /// `timestamp` is a timestamp that will be copied into the frames decoded from that input
    /// stream. Units are effectively free and provided by the input stream.
    ///
    /// The device takes ownership of `resource` and is responsible for closing it once it is not
    /// used anymore.
    ///
    /// The device will emit a `NotifyEndOfBitstreamBuffer` event with the `resource_id` value after
    /// the input buffer has been entirely processed.
    ///
    /// The device will emit a `PictureReady` event with the `timestamp` value for each picture
    /// produced from that input buffer.
    fn decode(
        &mut self,
        resource_id: u32,
        timestamp: u64,
        resource: GuestResourceHandle,
        offset: u32,
        bytes_used: u32,
    ) -> VideoResult<()>;

    /// Flush the decoder device, i.e. finish processing all queued decode requests and emit frames
    /// for them.
    ///
    /// The device will emit a `FlushCompleted` event once the flush is done.
    fn flush(&mut self) -> VideoResult<()>;

    /// Reset the decoder device, i.e. cancel all pending decoding requests.
    ///
    /// The device will emit a `ResetCompleted` event once the reset is done.
    fn reset(&mut self) -> VideoResult<()>;

    /// Immediately release all buffers passed using `use_output_buffer()` and
    /// `reuse_output_buffer()`.
    fn clear_output_buffers(&mut self) -> VideoResult<()>;

    /// Returns the event pipe on which the availability of events will be signaled. Note that the
    /// returned value is borrowed and only valid as long as the session is alive.
    fn event_pipe(&self) -> &dyn AsRawDescriptor;

    /// Ask the device to use `resource` to store decoded frames according to its layout.
    /// `picture_buffer_id` is the ID of the picture that will be reproduced in `PictureReady`
    /// events using this buffer.
    ///
    /// The device takes ownership of `resource` and is responsible for closing it once the buffer
    /// is not used anymore (either when the session is closed, or a new set of buffers is provided
    /// for the session).
    ///
    /// The device will emit a `PictureReady` event with the `picture_buffer_id` field set to the
    /// same value as the argument of the same name when a frame has been decoded into that buffer.
    fn use_output_buffer(
        &mut self,
        picture_buffer_id: i32,
        resource: GuestResource,
    ) -> VideoResult<()>;

    /// Ask the device to reuse an output buffer previously passed to
    /// `use_output_buffer` and that has previously been returned to the decoder
    /// in a `PictureReady` event.
    ///
    /// The device will emit a `PictureReady` event with the `picture_buffer_id`
    /// field set to the same value as the argument of the same name when a
    /// frame has been decoded into that buffer.
    fn reuse_output_buffer(&mut self, picture_buffer_id: i32) -> VideoResult<()>;

    /// Blocking call to read a single event from the event pipe.
    fn read_event(&mut self) -> VideoResult<DecoderEvent>;
}

pub trait DecoderBackend {
    type Session: DecoderSession;

    /// Return the decoding capabilities for this backend instance.
    fn get_capabilities(&self) -> Capability;

    /// Create a new decoding session for the passed `format`.
    fn new_session(&mut self, format: Format) -> VideoResult<Self::Session>;
}

#[derive(Debug)]
pub enum DecoderEvent {
    /// Emitted when the device knows the buffer format it will need to decode frames, and how many
    /// buffers it will need. The decoder is supposed to call `set_output_parameters()` to confirm
    /// the pixel format and actual number of buffers used, and provide buffers of the requested
    /// dimensions using `use_output_buffer()`.
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
        timestamp: u64,
        visible_rect: Rect,
    },
    /// Emitted when an input buffer passed to `decode()` is not used by the
    /// device anymore and can be reused by the decoder. The parameter corresponds
    /// to the `timestamp` argument passed to `decode()`.
    NotifyEndOfBitstreamBuffer(u32),
    /// Emitted when a decoding error has occured.
    NotifyError(VideoError),
    /// Emitted after `flush()` has been called to signal that the flush is completed.
    FlushCompleted(VideoResult<()>),
    /// Emitted after `reset()` has been called to signal that the reset is completed.
    ResetCompleted(VideoResult<()>),
}

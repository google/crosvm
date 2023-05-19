// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(feature = "ffmpeg")]
pub mod ffmpeg;
#[cfg(feature = "libvda")]
pub mod vda;

use base::AsRawDescriptor;

use super::EncoderCapabilities;
use super::EncoderEvent;
use super::InputBufferId;
use super::OutputBufferId;
use super::SessionConfig;
use crate::virtio::video::error::VideoResult;
use crate::virtio::video::format::Bitrate;
use crate::virtio::video::resource::GuestResource;
use crate::virtio::video::resource::GuestResourceHandle;

pub trait EncoderSession {
    /// Encodes the frame provided by `resource`.
    /// `force_keyframe` forces the frame to be encoded as a keyframe.
    /// When the buffer has been successfully processed, a `ProcessedInputBuffer` event will
    /// be readable from the event pipe, with the same `InputBufferId` as returned by this
    /// function.
    /// When the corresponding encoded data is ready, `ProcessedOutputBuffer` events will be
    /// readable from the event pipe, with the same timestamp as provided `timestamp`.
    fn encode(
        &mut self,
        resource: GuestResource,
        timestamp: u64,
        force_keyframe: bool,
    ) -> VideoResult<InputBufferId>;

    /// Provides an output `resource` to store encoded output, where `offset` and `size` define the
    /// region of memory to use.
    /// When the buffer has been filled with encoded output, a `ProcessedOutputBuffer` event will be
    /// readable from the event pipe, with the same `OutputBufferId` as returned by this function.
    fn use_output_buffer(
        &mut self,
        resource: GuestResourceHandle,
        offset: u32,
        size: u32,
    ) -> VideoResult<OutputBufferId>;

    /// Requests the encoder to flush. When completed, an `EncoderEvent::FlushResponse` event will
    /// be readable from the event pipe.
    fn flush(&mut self) -> VideoResult<()>;

    /// Requests the encoder to use new encoding parameters provided by `bitrate` and `framerate`.
    fn request_encoding_params_change(
        &mut self,
        bitrate: Bitrate,
        framerate: u32,
    ) -> VideoResult<()>;

    /// Returns the event pipe on which the availability of events will be signaled. Note that the
    /// returned value is borrowed and only valid as long as the session is alive.
    fn event_pipe(&self) -> &dyn AsRawDescriptor;

    /// Performs a blocking read for an encoder event. This function should only be called when
    /// the file descriptor returned by `event_pipe` is readable.
    fn read_event(&mut self) -> VideoResult<EncoderEvent>;
}

pub trait Encoder {
    type Session: EncoderSession;

    fn query_capabilities(&self) -> VideoResult<EncoderCapabilities>;
    fn start_session(&mut self, config: SessionConfig) -> VideoResult<Self::Session>;
    fn stop_session(&mut self, session: Self::Session) -> VideoResult<()>;
}

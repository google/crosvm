// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io;
use std::io::Read;
use std::slice;
use std::sync::Arc;

use async_trait::async_trait;
use audio_streams::AsyncPlaybackBuffer;
use audio_streams::AsyncPlaybackBufferStream;
use base::error;
use base::warn;
use cros_async::Executor;
use data_model::Le32;
use futures::channel::mpsc::UnboundedReceiver;
use futures::channel::mpsc::UnboundedSender;
use futures::SinkExt;
use serde::Deserialize;
use serde::Serialize;
use sync::Mutex;
use vm_memory::GuestMemory;
use win_audio::async_stream::WinAudioStreamSourceGenerator;
use win_audio::intermediate_resampler_buffer::IntermediateResamplerBuffer;
use win_audio::AudioSharedFormat;
use win_audio::WinAudioServer;
use win_audio::WinStreamSourceGenerator;

use crate::virtio::snd::common_backend::async_funcs::get_reader_and_writer;
use crate::virtio::snd::common_backend::async_funcs::PlaybackBufferWriter;
use crate::virtio::snd::common_backend::stream_info::StreamInfo;
use crate::virtio::snd::common_backend::DirectionalStream;
use crate::virtio::snd::common_backend::Error;
use crate::virtio::snd::common_backend::PcmResponse;
use crate::virtio::snd::common_backend::SndData;
use crate::virtio::snd::constants::StatusCode;
use crate::virtio::snd::layout::virtio_snd_pcm_status;
use crate::virtio::snd::parameters::Error as ParametersError;
use crate::virtio::snd::parameters::Parameters;
use crate::virtio::DescriptorChain;
use crate::virtio::Reader;

pub(crate) use base::set_audio_thread_priority;

pub(crate) type SysAudioStreamSourceGenerator = Box<dyn WinStreamSourceGenerator>;
pub(crate) type SysAudioStreamSource = Box<dyn WinAudioServer>;
pub(crate) type SysBufferWriter = WinBufferWriter;

pub(crate) struct SysAsyncStream {
    pub(crate) async_playback_buffer_stream: Box<dyn AsyncPlaybackBufferStream>,
    pub(crate) audio_shared_format: AudioSharedFormat,
}

pub(crate) struct SysAsyncStreamObjects {
    pub(crate) stream: DirectionalStream,
    pub(crate) pcm_sender: UnboundedSender<PcmResponse>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum StreamSourceBackend {
    WINAUDIO,
}

// Implemented to make backend serialization possible, since we deserialize from str.
impl From<StreamSourceBackend> for String {
    fn from(backend: StreamSourceBackend) -> Self {
        match backend {
            StreamSourceBackend::WINAUDIO => "winaudio".to_owned(),
        }
    }
}

impl TryFrom<&str> for StreamSourceBackend {
    type Error = ParametersError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "winaudio" => Ok(StreamSourceBackend::WINAUDIO),
            _ => Err(ParametersError::InvalidBackend),
        }
    }
}

pub(crate) fn create_stream_source_generators(
    _backend: StreamSourceBackend,
    _params: &Parameters,
    _snd_data: &SndData,
) -> Vec<SysAudioStreamSourceGenerator> {
    vec![Box::new(WinAudioStreamSourceGenerator {})]
}

impl StreamInfo {
    pub(crate) async fn set_up_async_playback_stream(
        &mut self,
        frame_size: usize,
        ex: &Executor,
    ) -> Result<SysAsyncStream, Error> {
        let (async_playback_buffer_stream, audio_shared_format) = self
            .stream_source
            .as_mut()
            .ok_or(Error::EmptyStreamSource)?
            .new_async_playback_stream_and_get_shared_format(
                self.channels as usize,
                self.format,
                self.frame_rate as usize,
                // `buffer_size` in `audio_streams` API indicates the buffer size in bytes that the stream
                // consumes (or transmits) each time (next_playback/capture_buffer).
                // `period_bytes` in virtio-snd device (or ALSA) indicates the device transmits (or
                // consumes) for each PCM message.
                // Therefore, `buffer_size` in `audio_streams` == `period_bytes` in virtio-snd.
                self.period_bytes / frame_size,
                ex,
            )
            .map_err(Error::CreateStream)?;
        Ok(SysAsyncStream {
            async_playback_buffer_stream,
            audio_shared_format,
        })
    }
}

pub(crate) struct WinBufferWriter {
    guest_period_bytes: usize,
    shared_audio_engine_period_bytes: usize,
    guest_num_channels: usize,
    intermediate_resampler_buffer: IntermediateResamplerBuffer,
}

impl WinBufferWriter {
    fn needs_prefill(&self) -> bool {
        self.intermediate_resampler_buffer.ring_buf.len()
            + (self
                .intermediate_resampler_buffer
                .guest_period_in_target_sample_rate_frames
                * self.guest_num_channels)
            <= self
                .intermediate_resampler_buffer
                .shared_audio_engine_period_in_frames
                * self.guest_num_channels
    }

    fn write_to_resampler_buffer(&mut self, reader: &mut Reader) -> Result<usize, Error> {
        let written = reader.read_to_cb(
            |iovs| {
                let mut written = 0;
                for iov in iovs {
                    let buffer_slice = unsafe { slice::from_raw_parts(iov.as_ptr(), iov.size()) };
                    self.intermediate_resampler_buffer
                        .convert_and_add(buffer_slice);
                    written += iov.size();
                }
                written
            },
            self.guest_period_bytes,
        );

        if written != self.guest_period_bytes {
            error!(
                "{} written bytes != guest period bytes of {}",
                written, self.guest_period_bytes
            );
            Err(Error::InvalidBufferSize)
        } else {
            Ok(written)
        }
    }
}

#[async_trait(?Send)]
impl PlaybackBufferWriter for WinBufferWriter {
    fn new(
        guest_period_bytes: usize,
        frame_size: usize,
        frame_rate: usize,
        guest_num_channels: usize,
        audio_shared_format: AudioSharedFormat,
    ) -> Self {
        WinBufferWriter {
            guest_period_bytes,
            shared_audio_engine_period_bytes: audio_shared_format
                .shared_audio_engine_period_in_frames
                * audio_shared_format.bit_depth
                / 8
                * audio_shared_format.channels,
            guest_num_channels,
            intermediate_resampler_buffer: IntermediateResamplerBuffer::new(
                /* from */ frame_rate,
                /* to */ audio_shared_format.frame_rate,
                guest_period_bytes / frame_size,
                audio_shared_format.shared_audio_engine_period_in_frames,
                audio_shared_format.channels,
                audio_shared_format.channel_mask,
            )
            .expect("Failed to create intermediate resampler buffer"),
        }
    }
    fn endpoint_period_bytes(&self) -> usize {
        self.shared_audio_engine_period_bytes
    }
    fn copy_to_buffer(
        &mut self,
        dst_buf: &mut AsyncPlaybackBuffer<'_>,
        reader: &mut Reader,
    ) -> Result<usize, Error> {
        self.write_to_resampler_buffer(reader)?;

        if let Some(next_period) = self.intermediate_resampler_buffer.get_next_period() {
            dst_buf
                .copy_cb(next_period.len(), |out| out.copy_from_slice(next_period))
                .map_err(Error::Io)
        } else {
            warn!("Getting the next period failed. Most likely the resampler is being primed.");
            dst_buf
                .copy_from(&mut io::repeat(0).take(self.shared_audio_engine_period_bytes as u64))
                .map_err(Error::Io)
        }
    }

    async fn check_and_prefill(
        &mut self,
        desc_receiver: &mut UnboundedReceiver<DescriptorChain>,
        sender: &mut UnboundedSender<PcmResponse>,
    ) -> Result<(), Error> {
        if !self.needs_prefill() {
            return Ok(());
        }

        match desc_receiver.try_next() {
            Err(e) => {
                error!(
                    " Prefill Underrun. No new DescriptorChain while running: {}",
                    e
                );
            }
            Ok(None) => {
                error!(" Prefill Unreachable. status should be Quit when the channel is closed");
                return Err(Error::InvalidPCMWorkerState);
            }
            Ok(Some(desc_chain)) => {
                let (mut reader, writer) = get_reader_and_writer(&desc_chain);
                self.write_to_resampler_buffer(&mut reader)?;

                sender
                    .send(PcmResponse {
                        desc_chain,
                        status: Ok(0).into(),
                        writer,
                        done: None,
                    })
                    .await
                    .map_err(Error::MpscSend)?;
            }
        };
        Ok(())
    }
}

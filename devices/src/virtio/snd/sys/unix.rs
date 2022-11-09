// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use async_trait::async_trait;
use audio_streams::AsyncPlaybackBufferStream;
use audio_streams::StreamSource;
use audio_streams::StreamSourceGenerator;
use base::set_rt_prio_limit;
use base::set_rt_round_robin;
use base::warn;
use cros_async::Executor;
use futures::channel::mpsc::UnboundedSender;
#[cfg(feature = "audio_cras")]
use libcras::CrasStreamSourceGenerator;

use crate::virtio::common_backend::PcmResponse;
use crate::virtio::snd::common_backend::async_funcs::PlaybackBufferWriter;
use crate::virtio::snd::common_backend::stream_info::StreamInfo;
use crate::virtio::snd::common_backend::DirectionalStream;
use crate::virtio::snd::common_backend::Error;
use crate::virtio::snd::common_backend::SndData;
use crate::virtio::snd::parameters::Error as ParametersError;
use crate::virtio::snd::parameters::Parameters;

const AUDIO_THREAD_RTPRIO: u16 = 10; // Matches other cros audio clients.

pub(crate) type SysAudioStreamSourceGenerator = Box<dyn StreamSourceGenerator>;
pub(crate) type SysAudioStreamSource = Box<dyn StreamSource>;
pub(crate) type SysBufferWriter = UnixBufferWriter;

pub(crate) struct SysAsyncStream {
    pub(crate) async_playback_buffer_stream: Box<dyn AsyncPlaybackBufferStream>,
}

pub(crate) struct SysAsyncStreamObjects {
    pub(crate) stream: DirectionalStream,
    pub(crate) pcm_sender: UnboundedSender<PcmResponse>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamSourceBackend {
    #[cfg(feature = "audio_cras")]
    CRAS,
}

impl TryFrom<&str> for StreamSourceBackend {
    type Error = ParametersError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            #[cfg(feature = "audio_cras")]
            "cras" => Ok(StreamSourceBackend::CRAS),
            _ => Err(ParametersError::InvalidBackend),
        }
    }
}

#[cfg(feature = "audio_cras")]
pub(crate) fn create_cras_stream_source_generators(
    params: &Parameters,
    snd_data: &SndData,
) -> Vec<Box<dyn StreamSourceGenerator>> {
    let mut generators: Vec<Box<dyn StreamSourceGenerator>> = Vec::new();
    generators.resize_with(snd_data.pcm_info_len(), || {
        Box::new(CrasStreamSourceGenerator::new(
            params.capture,
            params.client_type,
            params.socket_type,
        ))
    });
    generators
}

#[allow(unused_variables)]
pub(crate) fn create_stream_source_generators(
    backend: StreamSourceBackend,
    params: &Parameters,
    snd_data: &SndData,
) -> Vec<Box<dyn StreamSourceGenerator>> {
    match backend {
        #[cfg(feature = "audio_cras")]
        StreamSourceBackend::CRAS => create_cras_stream_source_generators(params, snd_data),
    }
}

pub(crate) fn set_audio_thread_priority() {
    if let Err(e) = set_rt_prio_limit(u64::from(AUDIO_THREAD_RTPRIO))
        .and_then(|_| set_rt_round_robin(i32::from(AUDIO_THREAD_RTPRIO)))
    {
        warn!("Failed to set audio thread to real time: {}", e);
    }
}

impl StreamInfo {
    /// (*)
    /// `buffer_size` in `audio_streams` API indicates the buffer size in bytes that the stream
    /// consumes (or transmits) each time (next_playback/capture_buffer).
    /// `period_bytes` in virtio-snd device (or ALSA) indicates the device transmits (or
    /// consumes) for each PCM message.
    /// Therefore, `buffer_size` in `audio_streams` == `period_bytes` in virtio-snd.
    pub(crate) async fn set_up_async_playback_stream(
        &mut self,
        frame_size: usize,
        ex: &Executor,
    ) -> Result<SysAsyncStream, Error> {
        Ok(SysAsyncStream {
            async_playback_buffer_stream: self
                .stream_source
                .as_mut()
                .ok_or(Error::EmptyStreamSource)?
                .async_new_async_playback_stream(
                    self.channels as usize,
                    self.format,
                    self.frame_rate,
                    // See (*)
                    self.period_bytes / frame_size,
                    ex,
                )
                .await
                .map_err(Error::CreateStream)?
                .1,
        })
    }
}

pub(crate) struct UnixBufferWriter {
    guest_period_bytes: usize,
}

#[async_trait(?Send)]
impl PlaybackBufferWriter for UnixBufferWriter {
    fn new(guest_period_bytes: usize) -> Self {
        UnixBufferWriter { guest_period_bytes }
    }
    fn endpoint_period_bytes(&self) -> usize {
        self.guest_period_bytes
    }
}

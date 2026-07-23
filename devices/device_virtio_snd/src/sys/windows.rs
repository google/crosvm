// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(b/275406212): Deleted resampler code to make upstream easier. The resample
// will be in win_audio now
use std::rc::Rc;
use std::sync::Arc;

use async_trait::async_trait;
use audio_streams::capture::AsyncCaptureBuffer;
use audio_streams::capture::AsyncCaptureBufferStream;
use audio_streams::AsyncPlaybackBuffer;
use audio_streams::AsyncPlaybackBufferStream;
use audio_streams::BoxError;
pub(crate) use base::set_audio_thread_priority;
use cros_async::sync::RwLock as AsyncRwLock;
use cros_async::Executor;
use devices::virtio::Reader;
use futures::channel::mpsc::UnboundedSender;
use serde::Deserialize;
use serde::Serialize;
use win_audio::async_stream::WinAudioStreamSourceGenerator;
use win_audio::WinAudioServer;
use win_audio::WinStreamSourceGenerator;

use crate::common_backend::async_funcs::CaptureBufferReader;
use crate::common_backend::async_funcs::PlaybackBufferWriter;
use crate::common_backend::stream_info::StreamInfo;
use crate::common_backend::DirectionalStream;
use crate::common_backend::Error;
use crate::common_backend::PcmResponse;
use crate::common_backend::SndData;
use crate::parameters::Error as ParametersError;
use crate::parameters::Parameters;

pub(crate) type SysAudioStreamSourceGenerator = Box<dyn WinStreamSourceGenerator>;
pub(crate) type SysAudioStreamSource = Box<dyn WinAudioServer>;
pub(crate) type SysBufferReader = WinBufferReader;

pub struct SysDirectionOutput {
    pub async_playback_buffer_stream:
        Arc<AsyncRwLock<Box<dyn audio_streams::AsyncPlaybackBufferStream>>>,
    pub buffer_writer: Rc<AsyncRwLock<Box<dyn PlaybackBufferWriter>>>,
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
    vec![
        Box::new(WinAudioStreamSourceGenerator {}),
        Box::new(WinAudioStreamSourceGenerator {}),
    ]
}

impl StreamInfo {
    async fn set_up_async_playback_stream(
        &mut self,
        frame_size: usize,
        audio_client_guid: Option<String>,
        ex: &Executor,
    ) -> Result<Box<dyn AsyncPlaybackBufferStream>, Error> {
        let (async_playback_buffer_stream, _) = self
            .stream_source
            .as_mut()
            .ok_or(Error::EmptyStreamSource)?
            .new_async_playback_stream_and_get_shared_format(
                self.channels as usize,
                self.format,
                self.frame_rate as usize,
                // `buffer_size` in `audio_streams` API indicates the buffer size in bytes that the
                // stream consumes (or transmits) each time
                // (next_playback/capture_buffer). `period_bytes` in virtio-snd
                // device (or ALSA) indicates the device transmits (or
                // consumes) for each PCM message.
                // Therefore, `buffer_size` in `audio_streams` == `period_bytes` in virtio-snd.
                self.period_bytes / frame_size,
                ex,
                audio_client_guid,
            )
            .map_err(Error::CreateStream)?;
        Ok(async_playback_buffer_stream)
    }

    pub(crate) async fn set_up_async_capture_stream(
        &mut self,
        frame_size: usize,
        ex: &Executor,
    ) -> Result<SysBufferReader, Error> {
        let (async_capture_buffer_stream, _audio_shared_format) = self
            .stream_source
            .as_mut()
            .ok_or(Error::EmptyStreamSource)?
            .new_async_capture_stream_and_get_shared_format(
                self.channels as usize,
                self.format,
                self.frame_rate,
                self.period_bytes / frame_size,
                ex,
            )
            .map_err(Error::CreateStream)?;
        let buffer_reader = WinBufferReader::new(async_capture_buffer_stream);
        Ok(buffer_reader)
    }

    pub(crate) async fn create_directionstream_output(
        &mut self,
        frame_size: usize,
        audio_client_guid: Option<String>,
        ex: &Executor,
    ) -> Result<DirectionalStream, Error> {
        if self.playback_stream_cache.is_none() {
            let async_playback_buffer_stream = self
                .set_up_async_playback_stream(frame_size, audio_client_guid, ex)
                .await?;

            let buffer_writer = WinBufferWriter::new(self.period_bytes);

            self.playback_stream_cache = Some((
                Arc::new(AsyncRwLock::new(async_playback_buffer_stream)),
                Rc::new(AsyncRwLock::new(Box::new(buffer_writer))),
            ));
        }
        let playback_stream_cache = self
            .playback_stream_cache
            .as_ref()
            .expect("playback stream cache is None. This shouldn't be possible");

        Ok(DirectionalStream::Output(SysDirectionOutput {
            async_playback_buffer_stream: playback_stream_cache.0.clone(),
            buffer_writer: playback_stream_cache.1.clone(),
        }))
    }
}

pub(crate) struct WinBufferReader {
    async_stream: Box<dyn AsyncCaptureBufferStream>,
}

impl WinBufferReader {
    fn new(async_stream: Box<dyn AsyncCaptureBufferStream>) -> Self {
        WinBufferReader { async_stream }
    }
}

#[async_trait(?Send)]
impl CaptureBufferReader for WinBufferReader {
    async fn get_next_capture_period(
        &mut self,
        ex: &Executor,
    ) -> Result<AsyncCaptureBuffer, BoxError> {
        self.async_stream.next_capture_buffer(ex).await
    }
}

pub(crate) struct WinBufferWriter {
    guest_period_bytes: usize,
}

#[async_trait(?Send)]
impl PlaybackBufferWriter for WinBufferWriter {
    fn new(guest_period_bytes: usize) -> Self {
        WinBufferWriter { guest_period_bytes }
    }

    fn endpoint_period_bytes(&self) -> usize {
        self.guest_period_bytes
    }

    // This method implementation may diverge downstream due to vendor specific requirements.
    fn copy_to_buffer(
        &mut self,
        dst_buf: &mut AsyncPlaybackBuffer<'_>,
        reader: &mut Reader,
    ) -> Result<usize, Error> {
        dst_buf.copy_from(reader).map_err(Error::Io)
    }
}

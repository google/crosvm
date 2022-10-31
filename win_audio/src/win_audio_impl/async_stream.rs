// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem::MaybeUninit;

use async_trait::async_trait;
use audio_streams::AsyncBufferCommit;
use audio_streams::AsyncPlaybackBuffer;
use audio_streams::AsyncPlaybackBufferStream;
use audio_streams::BoxError;
use audio_streams::NoopStream;
use audio_streams::NoopStreamControl;
use audio_streams::SampleFormat;
use audio_streams::StreamControl;
use audio_streams::StreamSource;
use audio_streams::StreamSourceGenerator;
use base::error;
use base::warn;

use crate::DeviceRenderer;
use crate::RenderError;
use crate::WinAudio;
use crate::WinAudioRenderer;

pub struct WinAudioStreamSourceGenerator {}

impl StreamSourceGenerator for WinAudioStreamSourceGenerator {
    fn generate(&self) -> std::result::Result<Box<dyn StreamSource>, BoxError> {
        Ok(Box::new(WinAudio::new()?))
    }
}

impl WinAudio {
    pub(super) fn new_async_playback_stream_helper(
        num_channels: usize,
        _format: SampleFormat,
        frame_rate: u32,
        buffer_size: usize,
        ex: &dyn audio_streams::AudioStreamsExecutor,
    ) -> Result<
        (
            Box<dyn StreamControl>,
            Box<dyn audio_streams::AsyncPlaybackBufferStream>,
        ),
        BoxError,
    > {
        let hr = WinAudio::co_init_once_per_thread();
        let _ = check_hresult!(hr, RenderError::from(hr), "Co Initialized failed");

        let playback_buffer_stream: Box<dyn AsyncPlaybackBufferStream> =
            match WinAudioRenderer::new_async(num_channels, frame_rate, buffer_size, ex) {
                Ok(renderer) => Box::new(renderer),
                Err(e) => {
                    warn!(
                        "Failed to create WinAudioRenderer. Fallback to NoopStream with error: {}",
                        e
                    );
                    Box::new(NoopStream::new(
                        num_channels,
                        SampleFormat::S16LE,
                        frame_rate,
                        buffer_size,
                    ))
                }
            };

        Ok((Box::new(NoopStreamControl::new()), playback_buffer_stream))
    }
}

impl WinAudioRenderer {
    /// Constructor to allow for async audio backend.
    pub fn new_async(
        num_channels: usize,
        frame_rate: u32,
        incoming_buffer_size_in_frames: usize,
        ex: &dyn audio_streams::AudioStreamsExecutor,
    ) -> Result<Self, RenderError> {
        let device = Self::create_device_renderer_and_log_time(
            num_channels,
            frame_rate,
            incoming_buffer_size_in_frames,
            Some(ex),
        )?;
        Ok(Self {
            device,
            num_channels,
            frame_rate,                     // guest frame rate
            incoming_buffer_size_in_frames, // from the guest`
        })
    }
}

#[async_trait(?Send)]
impl AsyncPlaybackBufferStream for WinAudioRenderer {
    async fn next_playback_buffer<'a>(
        &'a mut self,
        _ex: &dyn audio_streams::AudioStreamsExecutor,
    ) -> Result<audio_streams::AsyncPlaybackBuffer<'a>, BoxError> {
        for _ in 0..Self::MAX_REATTACH_TRIES {
            match self.device.async_next_win_buffer().await {
                Ok(_) => {
                    return self
                        .device
                        .async_playback_buffer()
                        .map_err(|e| Box::new(e) as _)
                }
                // If the audio device was disconnected, set up whatever is now the default device
                // and loop to try again.
                Err(RenderError::DeviceInvalidated) => {
                    warn!("Audio device disconnected, switching to new default device");
                    self.reattach_device()?;
                }
                Err(e) => return Err(Box::new(e)),
            }
        }
        error!("Unable to attach to a working audio device, giving up");
        Err(Box::new(RenderError::DeviceInvalidated))
    }
}

impl DeviceRenderer {
    /// Similiar to `next_win_buffer`, this is the async version that will return a wraper around
    /// the WASAPI buffer.
    ///
    /// Unlike `next_win_buffer`, there is no timeout if `async_ready_to_read_event` doesn't fire.
    /// This should be fine, since the end result with or without the timeout will be no audio.
    async fn async_next_win_buffer(&mut self) -> Result<(), RenderError> {
        self.win_buffer = MaybeUninit::uninit().as_mut_ptr();

        // We will wait for windows to tell us when it is ready to take in the next set of
        // audio samples from the guest
        loop {
            let async_ready_to_read_event = self
                .async_ready_to_read_event
                .as_ref()
                .ok_or(RenderError::MissingEventAsync)?;
            async_ready_to_read_event.wait().await.map_err(|e| {
                RenderError::AsyncError(
                    e,
                    "Failed to wait for async event to get next playback buffer.".to_string(),
                )
            })?;

            if self.enough_available_frames()? {
                break;
            }
        }

        self.get_buffer()?;

        Ok(())
    }

    /// Similar to `playback_buffer`. This will return an `AsyncPlaybackBuffer` that allows for
    /// async operations.
    ///
    /// Due to the way WASAPI is, `AsyncPlaybackBuffer` won't actually have any async operations
    /// that will await.
    fn async_playback_buffer(&mut self) -> Result<AsyncPlaybackBuffer, RenderError> {
        // Safe because `win_buffer` is allocated and retrieved from WASAPI. The size requested,
        // which we specified in `next_win_buffer` is exactly
        // `shared_audio_engine_period_in_frames`, so the size parameter should be valid.
        let (frame_size_bytes, buffer_slice) = unsafe {
            Self::get_frame_size_and_buffer_slice(
                self.audio_shared_format.bit_depth as usize,
                self.audio_shared_format.channels as usize,
                self.win_buffer,
                self.audio_shared_format
                    .shared_audio_engine_period_in_frames,
            )?
        };

        AsyncPlaybackBuffer::new(frame_size_bytes, buffer_slice, self)
            .map_err(RenderError::PlaybackBuffer)
    }
}

#[async_trait(?Send)]
impl AsyncBufferCommit for DeviceRenderer {
    async fn commit(&mut self, nframes: usize) {
        // Safe because `audio_render_client` is initialized and parameters passed
        // into `ReleaseBuffer()` are valid
        unsafe {
            let hr = self.audio_render_client.ReleaseBuffer(nframes as u32, 0);
            let _ = check_hresult!(
                hr,
                RenderError::from(hr),
                "Audio Render Client ReleaseBuffer() failed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cros_async::Executor;

    // This test is meant to run through the normal audio playback procedure in order to make
    // debugging easier. The test needs to be ran with a playback device format of 48KHz,
    // stereo, 16bit. This test might not pass on AMD, since its period is 513 instead of 480.
    #[ignore]
    #[test]
    fn test_async() {
        async fn test(ex: &Executor) {
            let stream_source_generator: Box<dyn StreamSourceGenerator> =
                Box::new(WinAudioStreamSourceGenerator {});
            let mut stream_source = stream_source_generator
                .generate()
                .expect("Failed to create stream source.");

            let (_, mut async_pb_stream) = stream_source
                .new_async_playback_stream(2, SampleFormat::S16LE, 48000, 480, ex)
                .expect("Failed to create async playback stream.");

            // The `ex` here won't be used, but it will satisfy the trait function requirement.
            let mut async_pb_buffer = async_pb_stream
                .next_playback_buffer(ex)
                .await
                .expect("Failed to get next playback buffer");

            // The buffer size is calculated by "period * channels * bit depth". The actual buffer
            // from `next_playback_buffer` may vary, depending on the device format and the user's
            // machine.
            let buffer = [1u8; 480 * 2 * 2];

            async_pb_buffer
                .copy_cb(buffer.len(), |out| out.copy_from_slice(&buffer))
                .unwrap();

            async_pb_buffer.commit().await;

            let mut async_pb_buffer = async_pb_stream
                .next_playback_buffer(ex)
                .await
                .expect("Failed to get next playback buffer");

            let buffer = [1u8; 480 * 2 * 2];

            async_pb_buffer
                .copy_cb(buffer.len(), |out| out.copy_from_slice(&buffer))
                .unwrap();

            async_pb_buffer.commit().await;
        }

        let ex = Executor::new().expect("Failed to create executor.");

        ex.run_until(test(&ex)).unwrap();
    }
}

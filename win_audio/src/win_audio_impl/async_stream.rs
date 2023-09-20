// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem::MaybeUninit;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use audio_streams::capture::AsyncCaptureBuffer;
use audio_streams::capture::AsyncCaptureBufferStream;
use audio_streams::AsyncBufferCommit;
use audio_streams::AsyncPlaybackBufferStream;
use audio_streams::AudioStreamsExecutor;
use audio_streams::BoxError;
use audio_streams::NoopStream;
use audio_streams::NoopStreamControl;
use audio_streams::SampleFormat;
use audio_streams::StreamControl;
use audio_streams::StreamSource;
use audio_streams::StreamSourceGenerator;
use base::error;
use base::warn;
use metrics::MetricEventType;

use crate::intermediate_resampler_buffer::CaptureResamplerBuffer;
use crate::intermediate_resampler_buffer::PlaybackResamplerBuffer;
use crate::CaptureError;
use crate::CapturerStream;
use crate::DeviceCapturerWrapper;
use crate::DeviceRenderer;
use crate::DeviceRendererWrapper;
use crate::RenderError;
use crate::RendererStream;
use crate::WinAudio;
use crate::WinAudioCapturer;
use crate::WinAudioError;
use crate::WinAudioRenderer;

use super::NoopBufferCommit;

// These global values are used to prevent metrics upload spam.
const ERROR_METRICS_LOG_LIMIT: usize = 5;
static INIT_ERRORS_LOGGED_COUNT: AtomicUsize = AtomicUsize::new(0);
static PLAYBACK_ERRORS_LOGGED_COUNT: AtomicUsize = AtomicUsize::new(0);

pub struct WinAudioStreamSourceGenerator {}

impl StreamSourceGenerator for WinAudioStreamSourceGenerator {
    fn generate(&self) -> std::result::Result<Box<dyn StreamSource>, BoxError> {
        Ok(Box::new(WinAudio::new()?))
    }
}

impl WinAudio {
    pub(super) fn new_async_playback_stream_helper(
        num_channels: usize,
        format: SampleFormat,
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
        let _ = check_hresult!(hr, WinAudioError::from(hr), "Co Initialized failed");

        let playback_buffer_stream: Box<dyn AsyncPlaybackBufferStream> =
            match WinAudioRenderer::new_async(num_channels, format, frame_rate, buffer_size, ex) {
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
        guest_bit_depth: SampleFormat,
        frame_rate: u32,
        incoming_buffer_size_in_frames: usize,
        ex: &dyn audio_streams::AudioStreamsExecutor,
    ) -> Result<Self, RenderError> {
        let device = DeviceRendererWrapper::new(
            num_channels,
            guest_bit_depth,
            frame_rate,
            incoming_buffer_size_in_frames,
            Some(ex),
        )
        .map_err(|e| {
            match &e {
                RenderError::WinAudioError(win_audio_error) => {
                    log_init_error_with_limit(win_audio_error.into());
                }
                _ => {
                    log_init_error_with_limit((&WinAudioError::Unknown).into());
                    error!(
                        "Unhandled NoopStream forced error. These errors should not have been \
                     returned: {}",
                        e
                    );
                }
            }
            e
        })?;

        Ok(Self { device })
    }

    fn unregister_notification_client_and_make_new_device_renderer(
        &mut self,
        ex: &dyn audio_streams::AudioStreamsExecutor,
    ) -> Result<(), BoxError> {
        base::info!("Device found. Will attempt to make a DeviceRenderer");
        let device_renderer = DeviceRendererWrapper::create_device_renderer_and_log_time(
            self.device.num_channels,
            self.device.guest_frame_rate,
            self.device.incoming_buffer_size_in_frames,
            Some(ex),
        )
        .map_err(|e| {
            match &e {
                RenderError::WinAudioError(win_audio_error) => {
                    log_playback_error_with_limit(win_audio_error.into())
                }
                _ => log_playback_error_with_limit((&WinAudioError::Unknown).into()),
            }
            Box::new(e)
        })?;

        let audio_shared_format = device_renderer.audio_shared_format;

        let playback_resampler_buffer = PlaybackResamplerBuffer::new(
            self.device.guest_frame_rate as usize,
            audio_shared_format.frame_rate,
            self.device.incoming_buffer_size_in_frames,
            audio_shared_format.shared_audio_engine_period_in_frames,
            audio_shared_format.channels,
            audio_shared_format.channel_mask,
        )
        .expect("Failed to create PlaybackResamplerBuffer");

        self.device.renderer_stream =
            RendererStream::Device((device_renderer, playback_resampler_buffer));

        Ok(())
    }
}

/// Attach `descriptor` to the event code `AudioNoopStreamForced` and upload to clearcut.
///
/// This method will stop uploading after `ERRO_METRICS_LOG_LIMIT` uploads in order to prevent
/// metrics upload spam.
pub(crate) fn log_init_error_with_limit(descriptor: i64) {
    if INIT_ERRORS_LOGGED_COUNT.load(Ordering::SeqCst) <= ERROR_METRICS_LOG_LIMIT {
        metrics::log_descriptor(MetricEventType::AudioNoopStreamForced, descriptor);
        INIT_ERRORS_LOGGED_COUNT.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait(?Send)]
impl AsyncPlaybackBufferStream for WinAudioRenderer {
    async fn next_playback_buffer<'a>(
        &'a mut self,
        ex: &dyn audio_streams::AudioStreamsExecutor,
    ) -> Result<audio_streams::AsyncPlaybackBuffer<'a>, BoxError> {
        // Check to see if a new device is available, if so, create a new `DeviceRenderer`.
        if let RendererStream::Noop(noop_renderer) = &self.device.renderer_stream {
            if noop_renderer
                .is_device_available
                .fetch_and(false, Ordering::SeqCst)
            {
                match self.unregister_notification_client_and_make_new_device_renderer(ex) {
                    Ok(()) => {}
                    Err(e) => warn!(
                        "Making a new DeviceRenderer failed in the middle of playback. \
                            Will continue using NoopStream and listening for new devices: {}",
                        e
                    ),
                };
            }
        }

        if let RendererStream::Device((device_renderer, _)) = &mut self.device.renderer_stream {
            if device_renderer.should_get_next_win_buffer {
                if let Err(e) = device_renderer.async_next_win_buffer().await {
                    Self::handle_playback_logging_on_error(&e);
                    // At this point, the `DeviceRenderer` doesn't exist, so we assume that
                    // there were no available audio devices.
                    base::info!(
                        "async_next_win_buffer failed. Starting NoopStream and start \
                        listening for a new default device"
                    );
                    self.device.renderer_stream =
                        DeviceRendererWrapper::create_noop_stream_with_device_notification(
                            self.device.num_channels,
                            self.device.guest_frame_rate,
                            self.device.incoming_buffer_size_in_frames,
                        )
                        .map_err(|e| {
                            match &e {
                                RenderError::WinAudioError(win_audio_error) => {
                                    log_playback_error_with_limit(win_audio_error.into())
                                }
                                _ => {
                                    log_playback_error_with_limit((&WinAudioError::Unknown).into())
                                }
                            }
                            e
                        })?;
                }
            }
        }

        if let RendererStream::Noop(noop_renderer) = &mut self.device.renderer_stream {
            // This will trigger the sleep so that virtio sound doesn't write to win_audio too
            // quickly, which will cause underruns. No audio samples will actually be written to
            // this buffer, but it doesn't matter becuase those samples are meant to be dropped
            // anyways.
            AsyncPlaybackBufferStream::next_playback_buffer(&mut noop_renderer.noop_stream, ex)
                .await?;
        }

        self.device
            .get_intermediate_async_buffer()
            .map_err(|e| Box::new(e) as _)
    }
}

#[async_trait(?Send)]
impl AsyncBufferCommit for DeviceRendererWrapper {
    async fn commit(&mut self, nframes: usize) {
        if nframes != self.incoming_buffer_size_in_frames {
            warn!(
                "AsyncBufferCommit commited {} frames, instead of a full period of {}",
                nframes, self.incoming_buffer_size_in_frames
            );
        }

        match &mut self.renderer_stream {
            RendererStream::Device((device_renderer, playback_resampler_buffer)) => {
                // `intermediate_buffer` will contain audio samples from CrosVm's emulated audio
                // device (ie. Virtio Sound). First, we will add the audio samples to the resampler
                // buffer.
                playback_resampler_buffer.convert_and_add(self.intermediate_buffer.as_slice());

                if playback_resampler_buffer.is_priming {
                    if device_renderer.win_buffer.is_null() {
                        error!("AsyncBufferCommit: win_buffer is null");
                        return;
                    }

                    let format = device_renderer.audio_shared_format;
                    let shared_audio_engine_period_bytes =
                        format.get_shared_audio_engine_period_in_bytes();
                    Self::write_slice_to_wasapi_buffer_and_release_buffer(
                        device_renderer,
                        &vec![0; shared_audio_engine_period_bytes],
                    );

                    // WASAPI's `GetBuffer` should be called next because we either wrote to the
                    // Windows endpoint buffer or the audio samples were dropped.
                    device_renderer.should_get_next_win_buffer = true;
                    return;
                }

                if let Some(next_period) = playback_resampler_buffer.get_next_period() {
                    if device_renderer.win_buffer.is_null() {
                        error!("AsyncBufferCommit: win_buffer is null");
                        return;
                    }
                    Self::write_slice_to_wasapi_buffer_and_release_buffer(
                        device_renderer,
                        next_period,
                    );
                    device_renderer.should_get_next_win_buffer = true;
                } else {
                    // Don't call WASAPI's `GetBuffer` because the resampler didn't have enough
                    // audio samples write a full period in the Windows endpoint buffer.
                    device_renderer.should_get_next_win_buffer = false;
                }
            }
            // For the `Noop` case, we can just drop the incoming audio samples.
            RendererStream::Noop(_) => {}
        }
    }
}

impl DeviceRendererWrapper {
    fn write_slice_to_wasapi_buffer_and_release_buffer(
        device_renderer: &DeviceRenderer,
        slice_to_write: &[u8],
    ) {
        let format = device_renderer.audio_shared_format;
        let shared_audio_engine_period_bytes = format.get_shared_audio_engine_period_in_bytes();

        let win_buffer_slice = unsafe {
            std::slice::from_raw_parts_mut(
                device_renderer.win_buffer,
                shared_audio_engine_period_bytes,
            )
        };

        win_buffer_slice.copy_from_slice(slice_to_write);
        unsafe {
            let hr = device_renderer
                .audio_render_client
                .ReleaseBuffer(format.shared_audio_engine_period_in_frames as u32, 0);
            if let Err(e) = check_hresult!(
                hr,
                WinAudioError::ReleaseBufferError(hr),
                "Audio Render Client ReleaseBuffer() failed"
            ) {
                log_playback_error_with_limit((&e).into());
            }
        }
    }
}

pub(crate) fn log_playback_error_with_limit(descriptor: i64) {
    if PLAYBACK_ERRORS_LOGGED_COUNT.load(Ordering::SeqCst) <= ERROR_METRICS_LOG_LIMIT {
        metrics::log_descriptor(MetricEventType::AudioPlaybackError, descriptor);
        PLAYBACK_ERRORS_LOGGED_COUNT.fetch_add(1, Ordering::SeqCst);
    }
}

impl DeviceRenderer {
    /// Similiar to `next_win_buffer`, this is the async version that will return a wrapper
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
                .ok_or(RenderError::WinAudioError(WinAudioError::MissingEventAsync))?;
            async_ready_to_read_event.wait().await.map_err(|e| {
                RenderError::WinAudioError(WinAudioError::AsyncError(
                    e,
                    "Failed to wait for async event to get next playback buffer.".to_string(),
                ))
            })?;

            if self.enough_available_frames()? {
                break;
            }
        }

        self.get_buffer()?;

        Ok(())
    }
}

impl WinAudioCapturer {
    pub fn new_async(
        num_channels: usize,
        guest_bit_depth: SampleFormat,
        frame_rate: u32,
        outgoing_buffer_size_in_frames: usize,
        ex: &dyn audio_streams::AudioStreamsExecutor,
    ) -> Result<Self, CaptureError> {
        let device = DeviceCapturerWrapper::new(
            num_channels,
            guest_bit_depth,
            frame_rate,
            outgoing_buffer_size_in_frames,
            Some(ex),
        )?;

        Ok(Self { device })
    }

    fn unregister_notification_client_and_make_new_device_capturer(
        &mut self,
        ex: &dyn AudioStreamsExecutor,
    ) -> Result<(), BoxError> {
        let device_capturer = DeviceCapturerWrapper::create_device_capturer_and_log_time(
            self.device.num_channels,
            self.device.guest_frame_rate,
            self.device.outgoing_buffer_size_in_frames,
            Some(ex),
        )
        .map_err(Box::new)?;

        let audio_shared_format = device_capturer.audio_shared_format;

        let capture_resampler_buffer = CaptureResamplerBuffer::new_input_resampler(
            audio_shared_format.frame_rate,
            self.device.guest_frame_rate as usize,
            self.device.outgoing_buffer_size_in_frames,
            audio_shared_format.channels,
            audio_shared_format.channel_mask,
        )
        .expect("Failed to create CaptureResamplerBuffer.");

        self.device.capturer_stream =
            CapturerStream::Device((device_capturer, capture_resampler_buffer, NoopBufferCommit));

        Ok(())
    }
}

#[async_trait(?Send)]
impl AsyncCaptureBufferStream for WinAudioCapturer {
    async fn next_capture_buffer<'a>(
        &'a mut self,
        ex: &dyn AudioStreamsExecutor,
    ) -> Result<AsyncCaptureBuffer<'a>, BoxError> {
        // In the `Noop` state, check to see if there is a new device connected. If so, create a
        // `DeviceCapturer`.
        if let CapturerStream::Noop(noop_capturer) = &self.device.capturer_stream {
            if noop_capturer
                .is_device_available
                .fetch_and(false, Ordering::SeqCst)
            {
                match self.unregister_notification_client_and_make_new_device_capturer(ex) {
                    Ok(()) => {}
                    Err(e) => warn!(
                        "Making a new DeviceCapturer failed in the middle of capture \
                    Will continue using NoopCaptureStream and listening for new devices: {}",
                        e
                    ),
                }
            }
        }

        // Try to drain bytes from the Windows buffer into the capture resample buffer, which acts
        // as a sink. If any part fails, the `Noop` state is set.
        if let CapturerStream::Device((device_capturer, capture_resampler_buffer, _)) =
            &mut self.device.capturer_stream
        {
            match DeviceCapturerWrapper::drain_until_bytes_avaialable(
                device_capturer,
                capture_resampler_buffer,
                self.device.outgoing_buffer_size_in_frames,
            )
            .await
            {
                Ok(()) => {}
                Err(e) => {
                    warn!(
                        "Making a new DeviceCapturer failed in the middle of capture. \
                        Will continue using NoopStream and listening for new devices: {}",
                        e
                    );
                    self.device.capturer_stream =
                        DeviceCapturerWrapper::create_noop_capture_stream_with_device_notification(
                            self.device.num_channels,
                            self.device.guest_bit_depth,
                            self.device.guest_frame_rate,
                            self.device.outgoing_buffer_size_in_frames,
                        )
                        .map_err(Box::new)?;
                }
            };
        }

        // Return the buffer to be written to shared memory.
        match &mut self.device.capturer_stream {
            CapturerStream::Device((_, capture_resampler_buffer, noop_buffer_commit)) => {
                DeviceCapturerWrapper::get_async_capture_buffer(
                    capture_resampler_buffer,
                    noop_buffer_commit,
                )
                .map_err(|e| Box::new(e) as _)
            }
            CapturerStream::Noop(noop_capturer) => {
                AsyncCaptureBufferStream::next_capture_buffer(
                    &mut noop_capturer.noop_capture_stream,
                    ex,
                )
                .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use cros_async::Executor;

    use crate::WinStreamSourceGenerator;

    use super::*;

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
                .expect("Failed to copy samples from buffer to win_buffer");

            async_pb_buffer.commit().await;
        }

        let ex = Executor::new().expect("Failed to create executor.");

        ex.run_until(test(&ex)).unwrap();
    }

    // This test is meant to run through the normal audio capture procedure in order to make
    // debugging easier.
    #[ignore]
    #[test]
    fn test_async_capture() {
        async fn test(ex: &Executor) {
            let stream_source_generator: Box<dyn WinStreamSourceGenerator> =
                Box::new(WinAudioStreamSourceGenerator {});
            let mut stream_source = stream_source_generator
                .generate()
                .expect("Failed to create stream source.");

            let (mut async_cp_stream, _shared_format) = stream_source
                .new_async_capture_stream_and_get_shared_format(
                    2,
                    SampleFormat::S16LE,
                    48000,
                    480,
                    ex,
                )
                .expect("Failed to create async capture stream.");

            let mut async_cp_buffer = async_cp_stream
                .next_capture_buffer(ex)
                .await
                .expect("Failed to get next capture buffer");

            // Capacity of 480 frames, where there are 2 channels and 2 bytes per sample.
            let mut buffer_to_send_to_guest = Vec::with_capacity(480 * 2 * 2);

            async_cp_buffer
                .copy_cb(buffer_to_send_to_guest.len(), |win_buffer| {
                    buffer_to_send_to_guest.copy_from_slice(win_buffer);
                })
                .expect("Failed to copy samples from win_buffer to buffer");
        }

        let ex = Executor::new().expect("Failed to create executor.");

        ex.run_until(test(&ex)).unwrap();
    }
}

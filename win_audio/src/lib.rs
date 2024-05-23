// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Do nothing on unix as win_audio is windows only.
#![cfg(windows)]
#![allow(non_upper_case_globals)]
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/r8brain_sys/bindings.rs"
));

macro_rules! check_hresult {
    ($hr: expr, $error: expr, $msg: expr) => {
        if winapi::shared::winerror::FAILED($hr) {
            base::warn!("{}: {}", $msg, $hr);
            Err($error)
        } else {
            Ok($hr)
        }
    };
}

pub mod intermediate_resampler_buffer;
mod win_audio_impl;
use std::error;
use std::sync::Arc;

use audio_streams::capture::AsyncCaptureBufferStream;
use audio_streams::capture::NoopCaptureStream;
use audio_streams::AsyncPlaybackBufferStream;
use audio_streams::NoopStream;
use audio_streams::NoopStreamSource;
use audio_streams::NoopStreamSourceGenerator;
use audio_streams::PlaybackBufferStream;
use audio_streams::SampleFormat;
use audio_streams::StreamSource;
use audio_util::FileStreamSourceGenerator;
use base::error;
use base::info;
use base::warn;
pub use intermediate_resampler_buffer::ANDROID_CAPTURE_FRAME_SIZE_BYTES;
pub use intermediate_resampler_buffer::BYTES_PER_32FLOAT;
use sync::Mutex;
use win_audio_impl::async_stream::WinAudioStreamSourceGenerator;
pub use win_audio_impl::*;

pub type BoxError = Box<dyn error::Error + Send + Sync>;

pub trait WinStreamSourceGenerator: Send + Sync {
    fn generate(&self) -> Result<Box<dyn WinAudioServer>, BoxError>;
}

impl WinStreamSourceGenerator for WinAudioStreamSourceGenerator {
    fn generate(&self) -> std::result::Result<Box<dyn WinAudioServer>, BoxError> {
        Ok(Box::new(WinAudio::new()?))
    }
}

impl WinStreamSourceGenerator for NoopStreamSourceGenerator {
    fn generate(&self) -> Result<Box<dyn WinAudioServer>, BoxError> {
        Ok(Box::new(NoopStreamSource))
    }
}

impl WinStreamSourceGenerator for FileStreamSourceGenerator {
    fn generate(&self) -> Result<Box<dyn WinAudioServer>, BoxError> {
        unimplemented!();
    }
}

/// Contains information about the audio engine's properties, such as its audio sample format
/// and its period in frames.
///
/// This does exclude whether the bit depth is in the form of floats or ints. The bit depth form
/// isn't used for sample rate conversion so it's excluded.
#[derive(Clone, Copy)]
pub struct AudioSharedFormat {
    pub bit_depth: usize,
    pub frame_rate: usize,
    pub shared_audio_engine_period_in_frames: usize,
    pub channels: usize,
    // Only available for WAVEFORMATEXTENSIBLE
    pub channel_mask: Option<u32>,
}

impl AudioSharedFormat {
    fn get_shared_audio_engine_period_in_bytes(&self) -> usize {
        let frame_size_bytes = self.bit_depth * self.channels / 8;
        self.shared_audio_engine_period_in_frames * frame_size_bytes
    }
}

/// Implementation of StreamSource which will create the playback stream for the Windows
/// audio engine.
///
/// Extending the StreamSource trait will allow us to make necessary changes without modifying
/// the third party audiostream library.
pub trait WinAudioServer: StreamSource {
    fn new_playback_stream_and_get_shared_format(
        &mut self,
        num_channels: usize,
        format: SampleFormat,
        frame_rate: usize,
        buffer_size: usize,
    ) -> Result<(Arc<Mutex<Box<dyn PlaybackBufferStream>>>, AudioSharedFormat), BoxError>;

    fn new_async_playback_stream_and_get_shared_format(
        &mut self,
        _num_channels: usize,
        _format: SampleFormat,
        _frame_rate: usize,
        _buffer_size: usize,
        _ex: &dyn audio_streams::AudioStreamsExecutor,
        _audio_client_guid: Option<String>,
    ) -> Result<(Box<dyn AsyncPlaybackBufferStream>, AudioSharedFormat), BoxError> {
        unimplemented!()
    }

    fn new_async_capture_stream_and_get_shared_format(
        &mut self,
        _num_channels: usize,
        _format: SampleFormat,
        _frame_rate: u32,
        _buffer_size: usize,
        _ex: &dyn audio_streams::AudioStreamsExecutor,
    ) -> Result<(Box<dyn AsyncCaptureBufferStream>, AudioSharedFormat), BoxError> {
        unimplemented!()
    }

    /// Evict the playback stream cache so that the audio device can be released, thus allowing
    /// for machines to go to sleep.
    fn evict_playback_stream_cache(&mut self) {
        unimplemented!()
    }

    /// Returns true if audio server is a noop stream. This determine if evicting a cache is worth
    /// doing
    fn is_noop_stream(&self) -> bool;
}

impl WinAudioServer for WinAudio {
    fn new_playback_stream_and_get_shared_format(
        &mut self,
        num_channels: usize,
        format: SampleFormat,
        frame_rate: usize,
        buffer_size: usize,
    ) -> Result<(Arc<Mutex<Box<dyn PlaybackBufferStream>>>, AudioSharedFormat), BoxError> {
        let hr = WinAudio::co_init_once_per_thread();
        let _ = check_hresult!(hr, WinAudioError::from(hr), "Co Initialized failed");

        // Return the existing stream if we have one.
        // This is mainly to reduce audio skips caused by a buffer underrun on the guest. An
        // underrun causes the guest to stop the audio stream, but then start it back up when the
        // guest buffer is filled again.
        if let Some((playback_buffer_stream, audio_format)) =
            self.cached_playback_buffer_stream.as_ref()
        {
            info!("Reusing playback_buffer_stream.");
            return Ok((playback_buffer_stream.clone(), *audio_format));
        }

        let (playback_buffer_stream, audio_shared_format): (
            Arc<Mutex<Box<dyn PlaybackBufferStream>>>,
            AudioSharedFormat,
        ) = match win_audio_impl::WinAudioRenderer::new(
            num_channels,
            format,
            frame_rate as u32,
            buffer_size,
        ) {
            Ok(renderer) => {
                let audio_shared_format = renderer.get_audio_shared_format();
                let renderer_arc = Arc::new(Mutex::new(
                    Box::new(renderer) as Box<dyn PlaybackBufferStream>
                ));
                self.cached_playback_buffer_stream =
                    Some((renderer_arc.clone(), audio_shared_format));
                (renderer_arc, audio_shared_format)
            }
            Err(e) => {
                error!(
                    "Failed to create WinAudioRenderer and in an unrecoverable state. Fallback to \
                     NoopStream with error: {}",
                    e
                );
                (
                    Arc::new(Mutex::new(Box::new(NoopStream::new(
                        num_channels,
                        SampleFormat::S16LE,
                        frame_rate as u32,
                        buffer_size,
                    )))),
                    AudioSharedFormat {
                        bit_depth: 16,
                        frame_rate,
                        channels: 2,
                        shared_audio_engine_period_in_frames: frame_rate / 100,
                        channel_mask: None,
                    },
                )
            }
        };

        Ok((playback_buffer_stream, audio_shared_format))
    }

    // TODO(b/275406212): AudioSharedFormat not used outside of this crate anymore. Clean up before
    // upstreaming.
    fn new_async_playback_stream_and_get_shared_format(
        &mut self,
        num_channels: usize,
        guest_bit_depth: SampleFormat,
        frame_rate: usize,
        buffer_size: usize,
        ex: &dyn audio_streams::AudioStreamsExecutor,
        audio_client_guid: Option<String>,
    ) -> Result<(Box<dyn AsyncPlaybackBufferStream>, AudioSharedFormat), BoxError> {
        let hr = WinAudio::co_init_once_per_thread();
        let _ = check_hresult!(hr, WinAudioError::from(hr), "Co Initialized failed");

        let (async_playback_buffer_stream, audio_shared_format): (
            Box<dyn AsyncPlaybackBufferStream>,
            AudioSharedFormat,
        ) = match win_audio_impl::WinAudioRenderer::new_async(
            num_channels,
            guest_bit_depth,
            frame_rate as u32,
            buffer_size,
            ex,
            audio_client_guid,
        ) {
            Ok(renderer) => {
                let audio_shared_format = renderer.get_audio_shared_format();
                let renderer_box = Box::new(renderer) as Box<dyn AsyncPlaybackBufferStream>;
                (renderer_box, audio_shared_format)
            }
            Err(e) => {
                error!(
                    "Failed to create WinAudioRenderer and in an unrecoverable state. Fallback to \
                     NoopStream with error: {}",
                    e
                );
                (
                    Box::new(NoopStream::new(
                        num_channels,
                        SampleFormat::S32LE,
                        frame_rate as u32,
                        buffer_size,
                    )),
                    AudioSharedFormat {
                        bit_depth: 32,
                        frame_rate,
                        channels: 2,
                        shared_audio_engine_period_in_frames: frame_rate / 100,
                        channel_mask: None,
                    },
                )
            }
        };

        Ok((async_playback_buffer_stream, audio_shared_format))
    }

    // TODO(b/275406212): AudioSharedFormat not used outside of this crate anymore. Clean up before
    // upstreaming.
    fn new_async_capture_stream_and_get_shared_format(
        &mut self,
        num_channels: usize,
        guest_bit_depth: SampleFormat,
        frame_rate: u32,
        buffer_size: usize,
        ex: &dyn audio_streams::AudioStreamsExecutor,
    ) -> Result<(Box<dyn AsyncCaptureBufferStream>, AudioSharedFormat), BoxError> {
        let hr = WinAudio::co_init_once_per_thread();
        let _ = check_hresult!(hr, WinAudioError::from(hr), "Co Initialized failed");

        let (capturer, audio_shared_format): (
            Box<dyn AsyncCaptureBufferStream>,
            AudioSharedFormat,
        ) = match WinAudioCapturer::new_async(
            num_channels,
            guest_bit_depth,
            frame_rate,
            buffer_size,
            ex,
        ) {
            Ok(capturer) => {
                let audio_shared_format = capturer.get_audio_shared_format();
                (Box::new(capturer), audio_shared_format)
            }
            Err(e) => {
                warn!("Failed to create WinAudioCapturer. Fallback to NoopCaptureStream with error: {}", e);
                (
                    Box::new(NoopCaptureStream::new(
                        num_channels,
                        SampleFormat::S32LE,
                        frame_rate,
                        buffer_size,
                    )),
                    AudioSharedFormat {
                        bit_depth: 32,
                        frame_rate: frame_rate as usize,
                        channels: 2,
                        shared_audio_engine_period_in_frames: frame_rate as usize / 100,
                        channel_mask: None,
                    },
                )
            }
        };

        Ok((capturer, audio_shared_format))
    }

    fn evict_playback_stream_cache(&mut self) {
        self.cached_playback_buffer_stream = None;
    }

    fn is_noop_stream(&self) -> bool {
        false
    }
}

impl WinAudioServer for NoopStreamSource {
    fn new_playback_stream_and_get_shared_format(
        &mut self,
        num_channels: usize,
        format: SampleFormat,
        frame_rate: usize,
        buffer_size: usize,
    ) -> Result<(Arc<Mutex<Box<dyn PlaybackBufferStream>>>, AudioSharedFormat), BoxError> {
        let (_, playback_buffer_stream) = self
            .new_playback_stream(num_channels, format, frame_rate as u32, buffer_size)
            .unwrap();
        Ok((
            Arc::new(Mutex::new(playback_buffer_stream)),
            AudioSharedFormat {
                bit_depth: 16,
                frame_rate,
                channels: 2,
                shared_audio_engine_period_in_frames: frame_rate / 100,
                channel_mask: None,
            },
        ))
    }

    fn new_async_playback_stream_and_get_shared_format(
        &mut self,
        num_channels: usize,
        format: SampleFormat,
        frame_rate: usize,
        buffer_size: usize,
        ex: &dyn audio_streams::AudioStreamsExecutor,
        _audio_client_guid: Option<String>,
    ) -> Result<(Box<dyn AsyncPlaybackBufferStream>, AudioSharedFormat), BoxError> {
        let (_, playback_stream) = self
            .new_async_playback_stream(num_channels, format, frame_rate as u32, buffer_size, ex)
            .unwrap();

        // Set shared format to be the same as the incoming audio format.
        let format = AudioSharedFormat {
            bit_depth: format.sample_bytes() * 8,
            frame_rate,
            channels: num_channels,
            shared_audio_engine_period_in_frames: buffer_size * format.sample_bytes(),
            channel_mask: None,
        };
        Ok((playback_stream, format))
    }

    fn is_noop_stream(&self) -> bool {
        true
    }
}

pub fn create_win_audio_device() -> Result<WinAudio, BoxError> {
    WinAudio::new()
}

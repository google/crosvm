// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(windows)]
#![allow(non_upper_case_globals)]
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/r8brain_sys/bindings.rs"
));

macro_rules! check_hresult {
    ($hr: expr, $error: expr, $msg: expr) => {
        if winapi::shared::winerror::FAILED($hr) {
            base::warn!("{}", $msg);
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

use audio_streams::NoopStream;
use audio_streams::NoopStreamSource;
use audio_streams::PlaybackBufferStream;
use audio_streams::SampleFormat;
use audio_streams::StreamSource;
use base::info;
use base::warn;
use sync::Mutex;
use win_audio_impl::*;

pub type BoxError = Box<dyn error::Error + Send + Sync>;

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

    /// Evict the playback stream cache so that the audio device can be released, thus allowing
    /// for machines to go to sleep.
    fn evict_playback_stream_cache(&mut self);

    /// Returns true if audio server is a noop stream. This determine if evicting a cache is worth
    /// doing
    fn is_noop_stream(&self) -> bool;
}

impl WinAudioServer for WinAudio {
    fn new_playback_stream_and_get_shared_format(
        &mut self,
        num_channels: usize,
        _format: SampleFormat,
        frame_rate: usize,
        buffer_size: usize,
    ) -> Result<(Arc<Mutex<Box<dyn PlaybackBufferStream>>>, AudioSharedFormat), BoxError> {
        let hr = WinAudio::co_init_once_per_thread();
        let _ = check_hresult!(hr, RenderError::from(hr), "Co Initialized failed");

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
            frame_rate as u32,
            buffer_size,
        ) {
            Ok(renderer) => {
                let audio_shared_format = renderer.device.audio_shared_format;
                let renderer_arc = Arc::new(Mutex::new(
                    Box::new(renderer) as Box<dyn PlaybackBufferStream>
                ));
                self.cached_playback_buffer_stream =
                    Some((renderer_arc.clone(), audio_shared_format));
                (renderer_arc, audio_shared_format)
            }
            Err(e) => {
                warn!(
                    "Failed to create WinAudioRenderer. Fallback to NoopStream with error: {}",
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

    fn evict_playback_stream_cache(&mut self) {
        unimplemented!()
    }

    fn is_noop_stream(&self) -> bool {
        true
    }
}

pub fn create_win_audio_device() -> Result<WinAudio, BoxError> {
    WinAudio::new()
}

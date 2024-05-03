// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(feature = "libaaudio_stub")]
mod libaaudio_stub;

use std::os::raw::c_void;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use async_trait::async_trait;
use audio_streams::AsyncBufferCommit;
use audio_streams::AsyncPlaybackBuffer;
use audio_streams::AsyncPlaybackBufferStream;
use audio_streams::AudioStreamsExecutor;
use audio_streams::BoxError;
use audio_streams::BufferCommit;
use audio_streams::NoopStreamControl;
use audio_streams::PlaybackBuffer;
use audio_streams::PlaybackBufferStream;
use audio_streams::SampleFormat;
use audio_streams::StreamControl;
use audio_streams::StreamSource;
use audio_streams::StreamSourceGenerator;
use base::warn;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AAudioError {
    #[error("Failed to create stream builder")]
    StreamBuilderCreation,
    #[error("Failed to open stream")]
    StreamOpen,
    #[error("Failed to start stream")]
    StreamStart,
    #[error("Failed to delete stream builder")]
    StreamBuilderDelete,
}

// Opaque blob
#[repr(C)]
struct AAudioStream {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

// Opaque blob
#[repr(C)]
struct AAudioStreamBuilder {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

type AaudioFormatT = i32;
type AaudioResultT = i32;
const AAUDIO_OK: AaudioResultT = 0;

extern "C" {
    fn AAudio_createStreamBuilder(builder: *mut *mut AAudioStreamBuilder) -> AaudioResultT;
    fn AAudioStreamBuilder_delete(builder: *mut AAudioStreamBuilder) -> AaudioResultT;
    fn AAudioStreamBuilder_setBufferCapacityInFrames(
        builder: *mut AAudioStreamBuilder,
        num_frames: i32,
    );
    fn AAudioStreamBuilder_setFormat(builder: *mut AAudioStreamBuilder, format: AaudioFormatT);
    fn AAudioStreamBuilder_setSampleRate(builder: *mut AAudioStreamBuilder, sample_rate: i32);
    fn AAudioStreamBuilder_setChannelCount(builder: *mut AAudioStreamBuilder, channel_count: i32);
    fn AAudioStreamBuilder_openStream(
        builder: *mut AAudioStreamBuilder,
        stream: *mut *mut AAudioStream,
    ) -> AaudioResultT;
    fn AAudioStream_requestStart(stream: *mut AAudioStream) -> AaudioResultT;
    fn AAudioStream_write(
        stream: *mut AAudioStream,
        buffer: *const c_void,
        num_frames: i32,
        timeout_nanoseconds: i64,
    ) -> AaudioResultT;
    fn AAudioStream_close(stream: *mut AAudioStream) -> AaudioResultT;
}

struct AAudioStreamPtr {
    // TODO: Use callback function to avoid possible thread preemption and glitches cause by
    // using AAudio APIs in different threads.
    stream_ptr: *mut AAudioStream,
}

// SAFETY:
// AudioStream.drop.buffer_ptr: *const u8 points to AudioStream.buffer, which would be alive
// whenever AudioStream.drop.buffer_ptr is alive.
unsafe impl Send for AndroidAudioStreamCommit {}

struct AudioStream {
    buffer: Box<[u8]>,
    frame_size: usize,
    interval: Duration,
    next_frame: Duration,
    start_time: Option<Instant>,
    buffer_drop: AndroidAudioStreamCommit,
}

struct AndroidAudioStreamCommit {
    buffer_ptr: *const u8,
    stream: AAudioStreamPtr,
}

impl BufferCommit for AndroidAudioStreamCommit {
    fn commit(&mut self, nwritten: usize) {
        // SAFETY:
        // The AAudioStream_write reads buffer for nwritten * frame_size bytes
        // It is safe since nwritten < buffer_size and the buffer.len() == buffer_size * frame_size
        let frames_written: i32 = unsafe {
            AAudioStream_write(
                self.stream.stream_ptr,
                self.buffer_ptr as *const c_void,
                nwritten as i32,
                0, // this call will not wait.
            )
        };
        if frames_written < 0 {
            warn!("AAudio stream write failed.");
        } else if (frames_written as usize) < nwritten {
            // Currently, the frames unable to write by the AAudio API are dropped.
            warn!(
                "Android Audio Stream:  Drop {} frames",
                nwritten - (frames_written as usize)
            );
        }
    }
}

#[async_trait(?Send)]
impl AsyncBufferCommit for AndroidAudioStreamCommit {
    async fn commit(&mut self, nwritten: usize) {
        // SAFETY:
        // The AAudioStream_write reads buffer for nwritten * frame_size bytes
        // It is safe since nwritten < buffer_size and the buffer.len() == buffer_size * frame_size
        let frames_written: i32 = unsafe {
            AAudioStream_write(
                self.stream.stream_ptr,
                self.buffer_ptr as *const c_void,
                nwritten as i32,
                0, // this call will not wait.
            )
        };
        if frames_written < 0 {
            warn!("AAudio stream write failed.");
        } else if (frames_written as usize) < nwritten {
            // Currently, the frames unable to write by the AAudio API are dropped.
            warn!(
                "Android Audio Stream:  Drop {} frames",
                nwritten - (frames_written as usize)
            );
        }
    }
}

impl AudioStream {
    pub fn new(
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        buffer_size: usize,
    ) -> Result<Self, BoxError> {
        let frame_size = format.sample_bytes() * num_channels;
        let interval = Duration::from_millis(buffer_size as u64 * 1000 / frame_rate as u64);

        let mut stream_ptr: *mut AAudioStream = std::ptr::null_mut();
        let mut builder: *mut AAudioStreamBuilder = std::ptr::null_mut();
        // SAFETY:
        // Interfacing with the AAudio C API. Assumes correct linking
        // and `builder` and `stream_ptr` pointers are valid and properly initialized.
        unsafe {
            if AAudio_createStreamBuilder(&mut builder) != AAUDIO_OK {
                return Err(Box::new(AAudioError::StreamBuilderCreation));
            }
            AAudioStreamBuilder_setBufferCapacityInFrames(builder, buffer_size as i32 * 2);
            AAudioStreamBuilder_setFormat(builder, format as AaudioFormatT);
            AAudioStreamBuilder_setSampleRate(builder, frame_rate as i32);
            AAudioStreamBuilder_setChannelCount(builder, num_channels as i32);
            if AAudioStreamBuilder_openStream(builder, &mut stream_ptr) != AAUDIO_OK {
                return Err(Box::new(AAudioError::StreamOpen));
            }
            if AAudioStreamBuilder_delete(builder) != AAUDIO_OK {
                return Err(Box::new(AAudioError::StreamBuilderDelete));
            }
            if AAudioStream_requestStart(stream_ptr) != AAUDIO_OK {
                return Err(Box::new(AAudioError::StreamStart));
            }
        }
        let buffer = vec![0; buffer_size * frame_size].into_boxed_slice();
        let stream = AAudioStreamPtr { stream_ptr };
        let buffer_drop = AndroidAudioStreamCommit {
            stream,
            buffer_ptr: buffer.as_ptr(),
        };
        Ok(AudioStream {
            buffer,
            frame_size,
            interval,
            next_frame: interval,
            start_time: None,
            buffer_drop,
        })
    }
}

impl PlaybackBufferStream for AudioStream {
    fn next_playback_buffer<'b, 's: 'b>(&'s mut self) -> Result<PlaybackBuffer<'b>, BoxError> {
        if let Some(start_time) = self.start_time {
            let elapsed = start_time.elapsed();
            if elapsed < self.next_frame {
                thread::sleep(self.next_frame - elapsed);
            }
            self.next_frame += self.interval;
        } else {
            self.start_time = Some(Instant::now());
            self.next_frame = self.interval;
        }
        Ok(
            PlaybackBuffer::new(self.frame_size, self.buffer.as_mut(), &mut self.buffer_drop)
                .map_err(Box::new)?,
        )
    }
}

#[async_trait(?Send)]
impl AsyncPlaybackBufferStream for AudioStream {
    async fn next_playback_buffer<'a>(
        &'a mut self,
        ex: &dyn AudioStreamsExecutor,
    ) -> Result<AsyncPlaybackBuffer<'a>, BoxError> {
        if let Some(start_time) = self.start_time {
            let elapsed = start_time.elapsed();
            if elapsed < self.next_frame {
                ex.delay(self.next_frame - elapsed).await?;
            }
            self.next_frame += self.interval;
        } else {
            self.start_time = Some(Instant::now());
            self.next_frame = self.interval;
        }
        Ok(
            AsyncPlaybackBuffer::new(self.frame_size, self.buffer.as_mut(), &mut self.buffer_drop)
                .map_err(Box::new)?,
        )
    }
}

impl Drop for AAudioStreamPtr {
    fn drop(&mut self) {
        // SAFETY:
        // Interfacing with the AAudio C API. Assumes correct linking
        // and `stream_ptr` are valid and properly initialized.
        if unsafe { AAudioStream_close(self.stream_ptr) } != AAUDIO_OK {
            warn!("AAudio stream close failed.");
        }
    }
}

#[derive(Default)]
struct AndroidAudioStreamSource;

impl StreamSource for AndroidAudioStreamSource {
    #[allow(clippy::type_complexity)]
    fn new_playback_stream(
        &mut self,
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        buffer_size: usize,
    ) -> Result<(Box<dyn StreamControl>, Box<dyn PlaybackBufferStream>), BoxError> {
        match AudioStream::new(num_channels, format, frame_rate, buffer_size) {
            Ok(audio_stream) => Ok((Box::new(NoopStreamControl::new()), Box::new(audio_stream))),
            Err(err) => Err(err),
        }
    }

    #[allow(clippy::type_complexity)]
    fn new_async_playback_stream(
        &mut self,
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        buffer_size: usize,
        _ex: &dyn AudioStreamsExecutor,
    ) -> Result<(Box<dyn StreamControl>, Box<dyn AsyncPlaybackBufferStream>), BoxError> {
        match AudioStream::new(num_channels, format, frame_rate, buffer_size) {
            Ok(audio_stream) => Ok((Box::new(NoopStreamControl::new()), Box::new(audio_stream))),
            Err(err) => Err(err),
        }
    }
}

#[derive(Default)]
pub struct AndroidAudioStreamSourceGenerator;

impl AndroidAudioStreamSourceGenerator {
    pub fn new() -> Self {
        AndroidAudioStreamSourceGenerator {}
    }
}

/// `AndroidAudioStreamSourceGenerator` is a struct that implements [`StreamSourceGenerator`]
/// for `AndroidAudioStreamSource`.
impl StreamSourceGenerator for AndroidAudioStreamSourceGenerator {
    fn generate(&self) -> Result<Box<dyn StreamSource>, BoxError> {
        Ok(Box::new(AndroidAudioStreamSource))
    }
}

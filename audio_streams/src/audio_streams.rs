// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides an interface for playing and recording audio.
//!
//! When implementing an audio playback system, the `StreamSource` trait is implemented.
//! Implementors of this trait allow creation of `PlaybackBufferStream` objects. The
//! `PlaybackBufferStream` provides the actual audio buffers to be filled with audio samples. These
//! buffers are obtained by calling `next_playback_buffer`.
//!
//! Users playing audio fill the provided buffers with audio. When a `PlaybackBuffer` is dropped,
//! the samples written to it are committed to the `PlaybackBufferStream` it came from.
//!
//! ```
//! use audio_streams::{BoxError, SampleFormat, StreamSource, NoopStreamSource};
//! use std::io::Write;
//!
//! const buffer_size: usize = 120;
//! const num_channels: usize = 2;
//!
//! # fn main() -> std::result::Result<(), BoxError> {
//! let mut stream_source = NoopStreamSource::new();
//! let sample_format = SampleFormat::S16LE;
//! let frame_size = num_channels * sample_format.sample_bytes();
//!
//! let (_, mut stream) = stream_source
//!     .new_playback_stream(num_channels, sample_format, 48000, buffer_size)?;
//! // Play 10 buffers of DC.
//! let mut buf = Vec::new();
//! buf.resize(buffer_size * frame_size, 0xa5u8);
//! for _ in 0..10 {
//!     let mut stream_buffer = stream.next_playback_buffer()?;
//!     assert_eq!(stream_buffer.write(&buf)?, buffer_size * frame_size);
//! }
//! # Ok (())
//! # }
//! ```

use async_trait::async_trait;
use std::cmp::min;
use std::error;
use std::fmt::{self, Display};
use std::io::{self, Write};
use std::os::unix::io::RawFd;
use std::result::Result;
use std::str::FromStr;
use std::time::{Duration, Instant};

use cros_async::{Executor, TimerAsync};

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum SampleFormat {
    U8,
    S16LE,
    S24LE,
    S32LE,
}

impl SampleFormat {
    pub fn sample_bytes(self) -> usize {
        use SampleFormat::*;
        match self {
            U8 => 1,
            S16LE => 2,
            S24LE => 4, // Not a typo, S24_LE samples are stored in 4 byte chunks.
            S32LE => 4,
        }
    }
}

impl Display for SampleFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use SampleFormat::*;
        match self {
            U8 => write!(f, "Unsigned 8 bit"),
            S16LE => write!(f, "Signed 16 bit Little Endian"),
            S24LE => write!(f, "Signed 24 bit Little Endian"),
            S32LE => write!(f, "Signed 32 bit Little Endian"),
        }
    }
}

/// Valid directions of an audio stream.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum StreamDirection {
    Playback,
    Capture,
}

/// Valid effects for an audio stream.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum StreamEffect {
    NoEffect,
    EchoCancellation,
}

pub mod capture;
pub mod shm_streams;

impl Default for StreamEffect {
    fn default() -> Self {
        StreamEffect::NoEffect
    }
}

/// Errors that can pass across threads.
pub type BoxError = Box<dyn error::Error + Send + Sync>;

/// Errors that are possible from a `StreamEffect`.
#[derive(Debug)]
pub enum StreamEffectError {
    InvalidEffect,
}

impl error::Error for StreamEffectError {}

impl Display for StreamEffectError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StreamEffectError::InvalidEffect => write!(f, "Must be in [EchoCancellation, aec]"),
        }
    }
}

impl FromStr for StreamEffect {
    type Err = StreamEffectError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "EchoCancellation" | "aec" => Ok(StreamEffect::EchoCancellation),
            _ => Err(StreamEffectError::InvalidEffect),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Unimplemented,
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Unimplemented => write!(f, "Unimplemented"),
        }
    }
}

/// `StreamSource` creates streams for playback or capture of audio.
pub trait StreamSource: Send {
    /// Returns a stream control and buffer generator object. These are separate as the buffer
    /// generator might want to be passed to the audio stream.
    #[allow(clippy::type_complexity)]
    fn new_playback_stream(
        &mut self,
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        buffer_size: usize,
    ) -> Result<(Box<dyn StreamControl>, Box<dyn PlaybackBufferStream>), BoxError>;

    /// Returns a stream control and async buffer generator object. These are separate as the buffer
    /// generator might want to be passed to the audio stream.
    #[allow(clippy::type_complexity)]
    fn new_async_playback_stream(
        &mut self,
        _num_channels: usize,
        _format: SampleFormat,
        _frame_rate: u32,
        _buffer_size: usize,
        _ex: &Executor,
    ) -> Result<(Box<dyn StreamControl>, Box<dyn AsyncPlaybackBufferStream>), BoxError> {
        Err(Box::new(Error::Unimplemented))
    }

    /// Returns a stream control and buffer generator object. These are separate as the buffer
    /// generator might want to be passed to the audio stream.
    /// Default implementation returns `NoopStreamControl` and `NoopCaptureStream`.
    #[allow(clippy::type_complexity)]
    fn new_capture_stream(
        &mut self,
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        buffer_size: usize,
    ) -> Result<
        (
            Box<dyn StreamControl>,
            Box<dyn capture::CaptureBufferStream>,
        ),
        BoxError,
    > {
        Ok((
            Box::new(NoopStreamControl::new()),
            Box::new(capture::NoopCaptureStream::new(
                num_channels,
                format,
                frame_rate,
                buffer_size,
            )),
        ))
    }

    /// Returns a stream control and async buffer generator object. These are separate as the buffer
    /// generator might want to be passed to the audio stream.
    /// Default implementation returns `NoopStreamControl` and `NoopCaptureStream`.
    #[allow(clippy::type_complexity)]
    fn new_async_capture_stream(
        &mut self,
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        buffer_size: usize,
        _ex: &Executor,
    ) -> Result<
        (
            Box<dyn StreamControl>,
            Box<dyn capture::AsyncCaptureBufferStream>,
        ),
        BoxError,
    > {
        Ok((
            Box::new(NoopStreamControl::new()),
            Box::new(capture::NoopCaptureStream::new(
                num_channels,
                format,
                frame_rate,
                buffer_size,
            )),
        ))
    }

    /// Returns any open file descriptors needed by the implementor. The FD list helps users of the
    /// StreamSource enter Linux jails making sure not to close needed FDs.
    fn keep_fds(&self) -> Option<Vec<RawFd>> {
        None
    }
}

/// `PlaybackBufferStream` provides `PlaybackBuffer`s to fill with audio samples for playback.
pub trait PlaybackBufferStream: Send {
    fn next_playback_buffer(&mut self) -> Result<PlaybackBuffer, BoxError>;
}

/// `PlaybackBufferStream` provides `PlaybackBuffer`s asynchronously to fill with audio samples for
/// playback.
#[async_trait(?Send)]
pub trait AsyncPlaybackBufferStream: Send {
    async fn next_playback_buffer<'a>(
        &'a mut self,
        ex: &Executor,
    ) -> Result<PlaybackBuffer<'a>, BoxError>;
}

/// `StreamControl` provides a way to set the volume and mute states of a stream. `StreamControl`
/// is separate from the stream so it can be owned by a different thread if needed.
pub trait StreamControl: Send + Sync {
    fn set_volume(&mut self, _scaler: f64) {}
    fn set_mute(&mut self, _mute: bool) {}
}

/// `BufferDrop` is used as a callback mechanism for `PlaybackBuffer` objects. It is meant to be
/// implemented by the audio stream, allowing arbitrary code to be run after a buffer is filled or
/// read by the user.
pub trait BufferDrop {
    /// Called when an audio buffer is dropped. `nframes` indicates the number of audio frames that
    /// were read or written to the device.
    fn trigger(&mut self, nframes: usize);
}

/// Errors that are possible from a `PlaybackBuffer`.
#[derive(Debug)]
pub enum PlaybackBufferError {
    InvalidLength,
}

impl error::Error for PlaybackBufferError {}

impl Display for PlaybackBufferError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PlaybackBufferError::InvalidLength => write!(f, "Invalid buffer length"),
        }
    }
}

/// `AudioBuffer` is one buffer that holds buffer_size audio frames and its drop function.
/// It is the inner data of `PlaybackBuffer` and `CaptureBuffer`.
struct AudioBuffer<'a> {
    buffer: &'a mut [u8],
    offset: usize,     // Read or Write offset in frames.
    frame_size: usize, // Size of a frame in bytes.
    drop: &'a mut dyn BufferDrop,
}

/// `PlaybackBuffer` is one buffer that holds buffer_size audio frames. It is used to temporarily
/// allow access to an audio buffer and notifes the owning stream of write completion when dropped.
pub struct PlaybackBuffer<'a> {
    buffer: AudioBuffer<'a>,
}

impl<'a> PlaybackBuffer<'a> {
    /// Creates a new `PlaybackBuffer` that holds a reference to the backing memory specified in
    /// `buffer`.
    pub fn new<F>(
        frame_size: usize,
        buffer: &'a mut [u8],
        drop: &'a mut F,
    ) -> Result<Self, PlaybackBufferError>
    where
        F: BufferDrop,
    {
        if buffer.len() % frame_size != 0 {
            return Err(PlaybackBufferError::InvalidLength);
        }

        Ok(PlaybackBuffer {
            buffer: AudioBuffer {
                buffer,
                offset: 0,
                frame_size,
                drop,
            },
        })
    }

    /// Returns the number of audio frames that fit in the buffer.
    pub fn frame_capacity(&self) -> usize {
        self.buffer.buffer.len() / self.buffer.frame_size
    }

    /// Writes up to `size` bytes directly to this buffer inside of the given callback function.
    pub fn copy_cb<F: FnOnce(&mut [u8])>(&mut self, size: usize, cb: F) {
        // only write complete frames.
        let len = min(
            size / self.buffer.frame_size * self.buffer.frame_size,
            self.buffer.buffer.len() - self.buffer.offset,
        );
        cb(&mut self.buffer.buffer[self.buffer.offset..(self.buffer.offset + len)]);
        self.buffer.offset += len;
    }
}

impl<'a> Write for PlaybackBuffer<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // only write complete frames.
        let len = buf.len() / self.buffer.frame_size * self.buffer.frame_size;
        let written = (&mut self.buffer.buffer[self.buffer.offset..]).write(&buf[..len])?;
        self.buffer.offset += written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> Drop for PlaybackBuffer<'a> {
    fn drop(&mut self) {
        self.buffer
            .drop
            .trigger(self.buffer.offset / self.buffer.frame_size);
    }
}

/// Stream that accepts playback samples but drops them.
pub struct NoopStream {
    buffer: Vec<u8>,
    frame_size: usize,
    interval: Duration,
    next_frame: Duration,
    start_time: Option<Instant>,
    buffer_drop: NoopBufferDrop,
}

/// NoopStream data that is needed from the buffer complete callback.
struct NoopBufferDrop {
    which_buffer: bool,
}

impl BufferDrop for NoopBufferDrop {
    fn trigger(&mut self, _nwritten: usize) {
        // When a buffer completes, switch to the other one.
        self.which_buffer ^= true;
    }
}

impl NoopStream {
    pub fn new(
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        buffer_size: usize,
    ) -> Self {
        let frame_size = format.sample_bytes() * num_channels;
        let interval = Duration::from_millis(buffer_size as u64 * 1000 / frame_rate as u64);
        NoopStream {
            buffer: vec![0; buffer_size * frame_size],
            frame_size,
            interval,
            next_frame: interval,
            start_time: None,
            buffer_drop: NoopBufferDrop {
                which_buffer: false,
            },
        }
    }
}

impl PlaybackBufferStream for NoopStream {
    fn next_playback_buffer(&mut self) -> Result<PlaybackBuffer, BoxError> {
        if let Some(start_time) = self.start_time {
            let elapsed = start_time.elapsed();
            if elapsed < self.next_frame {
                std::thread::sleep(self.next_frame - elapsed);
            }
            self.next_frame += self.interval;
        } else {
            self.start_time = Some(Instant::now());
            self.next_frame = self.interval;
        }
        Ok(PlaybackBuffer::new(
            self.frame_size,
            &mut self.buffer,
            &mut self.buffer_drop,
        )?)
    }
}

#[async_trait(?Send)]
impl AsyncPlaybackBufferStream for NoopStream {
    async fn next_playback_buffer<'a>(
        &'a mut self,
        ex: &Executor,
    ) -> Result<PlaybackBuffer<'a>, BoxError> {
        if let Some(start_time) = self.start_time {
            let elapsed = start_time.elapsed();
            if elapsed < self.next_frame {
                TimerAsync::sleep(ex, self.next_frame - elapsed).await?;
            }
            self.next_frame += self.interval;
        } else {
            self.start_time = Some(Instant::now());
            self.next_frame = self.interval;
        }
        Ok(PlaybackBuffer::new(
            self.frame_size,
            &mut self.buffer,
            &mut self.buffer_drop,
        )?)
    }
}

/// No-op control for `NoopStream`s.
#[derive(Default)]
pub struct NoopStreamControl;

impl NoopStreamControl {
    pub fn new() -> Self {
        NoopStreamControl {}
    }
}

impl StreamControl for NoopStreamControl {}

/// Source of `NoopStream` and `NoopStreamControl` objects.
#[derive(Default)]
pub struct NoopStreamSource;

impl NoopStreamSource {
    pub fn new() -> Self {
        NoopStreamSource {}
    }
}

impl StreamSource for NoopStreamSource {
    #[allow(clippy::type_complexity)]
    fn new_playback_stream(
        &mut self,
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        buffer_size: usize,
    ) -> Result<(Box<dyn StreamControl>, Box<dyn PlaybackBufferStream>), BoxError> {
        Ok((
            Box::new(NoopStreamControl::new()),
            Box::new(NoopStream::new(
                num_channels,
                format,
                frame_rate,
                buffer_size,
            )),
        ))
    }

    #[allow(clippy::type_complexity)]
    fn new_async_playback_stream(
        &mut self,
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        buffer_size: usize,
        _ex: &Executor,
    ) -> Result<(Box<dyn StreamControl>, Box<dyn AsyncPlaybackBufferStream>), BoxError> {
        Ok((
            Box::new(NoopStreamControl::new()),
            Box::new(NoopStream::new(
                num_channels,
                format,
                frame_rate,
                buffer_size,
            )),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_buffer_length() {
        // Playback buffers can't be created with a size that isn't divisible by the frame size.
        let mut pb_buf = [0xa5u8; 480 * 2 * 2 + 1];
        let mut buffer_drop = NoopBufferDrop {
            which_buffer: false,
        };
        assert!(PlaybackBuffer::new(2, &mut pb_buf, &mut buffer_drop).is_err());
    }

    #[test]
    fn trigger() {
        struct TestDrop {
            frame_count: usize,
        }
        impl BufferDrop for TestDrop {
            fn trigger(&mut self, nwritten: usize) {
                self.frame_count += nwritten;
            }
        }
        let mut test_drop = TestDrop { frame_count: 0 };
        {
            const FRAME_SIZE: usize = 4;
            let mut buf = [0u8; 480 * FRAME_SIZE];
            let mut pb_buf = PlaybackBuffer::new(FRAME_SIZE, &mut buf, &mut test_drop).unwrap();
            pb_buf.write_all(&[0xa5u8; 480 * FRAME_SIZE]).unwrap();
        }
        assert_eq!(test_drop.frame_count, 480);
    }

    #[test]
    fn sixteen_bit_stereo() {
        let mut server = NoopStreamSource::new();
        let (_, mut stream) = server
            .new_playback_stream(2, SampleFormat::S16LE, 48000, 480)
            .unwrap();
        let mut stream_buffer = stream.next_playback_buffer().unwrap();
        assert_eq!(stream_buffer.frame_capacity(), 480);
        let pb_buf = [0xa5u8; 480 * 2 * 2];
        assert_eq!(stream_buffer.write(&pb_buf).unwrap(), 480 * 2 * 2);
    }

    #[test]
    fn consumption_rate() {
        let mut server = NoopStreamSource::new();
        let (_, mut stream) = server
            .new_playback_stream(2, SampleFormat::S16LE, 48000, 480)
            .unwrap();
        let start = Instant::now();
        {
            let mut stream_buffer = stream.next_playback_buffer().unwrap();
            let pb_buf = [0xa5u8; 480 * 2 * 2];
            assert_eq!(stream_buffer.write(&pb_buf).unwrap(), 480 * 2 * 2);
        }
        // The second call should block until the first buffer is consumed.
        let _stream_buffer = stream.next_playback_buffer().unwrap();
        let elapsed = start.elapsed();
        assert!(
            elapsed > Duration::from_millis(10),
            "next_playback_buffer didn't block long enough {}",
            elapsed.subsec_millis()
        );
    }

    #[test]
    fn consumption_rate_async() {
        async fn this_test(ex: &Executor) {
            let mut server = NoopStreamSource::new();
            let (_, mut stream) = server
                .new_async_playback_stream(2, SampleFormat::S16LE, 48000, 480, ex)
                .unwrap();
            let start = Instant::now();
            {
                let mut stream_buffer = stream.next_playback_buffer(ex).await.unwrap();
                let pb_buf = [0xa5u8; 480 * 2 * 2];
                assert_eq!(stream_buffer.write(&pb_buf).unwrap(), 480 * 2 * 2);
            }
            // The second call should block until the first buffer is consumed.
            let _stream_buffer = stream.next_playback_buffer(ex).await.unwrap();
            let elapsed = start.elapsed();
            assert!(
                elapsed > Duration::from_millis(10),
                "next_playback_buffer didn't block long enough {}",
                elapsed.subsec_millis()
            );
        }

        let ex = Executor::new().expect("failed to create executor");
        ex.run_until(this_test(&ex)).unwrap();
    }
}

// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides an interface for playing and recording audio.
//!
//! When implementing an audio playback system, the `StreamSource` trait is implemented.
//! Implementors of this trait allow creation of `PlaybackBufferStream` objects. The
//! `PlaybackBufferStream` provides the actual audio buffers to be filled with audio samples. These
//! buffers can be filled with `write_playback_buffer`.
//!
//! Users playing audio fill the provided buffers with audio. When a `PlaybackBuffer` is dropped,
//! the samples written to it are committed to the `PlaybackBufferStream` it came from.
//!
//! ```
//! use audio_streams::{BoxError, PlaybackBuffer, SampleFormat, StreamSource, NoopStreamSource};
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
//!     let mut copy_cb = |stream_buffer: &mut PlaybackBuffer| {
//!         assert_eq!(stream_buffer.write(&buf)?, buffer_size * frame_size);
//!         Ok(())
//!     };
//!     stream.write_playback_buffer(&mut copy_cb)?;
//! }
//! # Ok (())
//! # }
//! ```
pub mod async_api;

use std::cmp::min;
use std::error;
use std::fmt;
use std::fmt::Display;
use std::io;
use std::io::Read;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::io::RawFd as RawDescriptor;
#[cfg(windows)]
use std::os::windows::io::RawHandle as RawDescriptor;
use std::result::Result;
use std::str::FromStr;
use std::time::Duration;
use std::time::Instant;

pub use async_api::AsyncStream;
pub use async_api::AudioStreamsExecutor;
use async_trait::async_trait;
use remain::sorted;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

impl FromStr for SampleFormat {
    type Err = SampleFormatError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "U8" => Ok(SampleFormat::U8),
            "S16_LE" => Ok(SampleFormat::S16LE),
            "S24_LE" => Ok(SampleFormat::S24LE),
            "S32_LE" => Ok(SampleFormat::S32LE),
            _ => Err(SampleFormatError::InvalidSampleFormat),
        }
    }
}

/// Errors that are possible from a `SampleFormat`.
#[sorted]
#[derive(Error, Debug)]
pub enum SampleFormatError {
    #[error("Must be in [U8, S16_LE, S24_LE, S32_LE]")]
    InvalidSampleFormat,
}

/// Valid directions of an audio stream.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StreamDirection {
    Playback,
    Capture,
}

/// Valid effects for an audio stream.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum StreamEffect {
    #[default]
    NoEffect,
    #[serde(alias = "aec")]
    EchoCancellation,
}

pub mod capture;
pub mod shm_streams;

/// Errors that can pass across threads.
pub type BoxError = Box<dyn error::Error + Send + Sync>;

/// Errors that are possible from a `StreamEffect`.
#[sorted]
#[derive(Error, Debug)]
pub enum StreamEffectError {
    #[error("Must be in [EchoCancellation, aec]")]
    InvalidEffect,
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

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Unimplemented")]
    Unimplemented,
}

/// `StreamSourceGenerator` is a trait used to abstract types that create [`StreamSource`].
/// It can be used when multiple types of `StreamSource` are needed.
pub trait StreamSourceGenerator: Sync + Send {
    fn generate(&self) -> Result<Box<dyn StreamSource>, BoxError>;
}

/// `StreamSource` creates streams for playback or capture of audio.
#[async_trait(?Send)]
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
        _ex: &dyn AudioStreamsExecutor,
    ) -> Result<(Box<dyn StreamControl>, Box<dyn AsyncPlaybackBufferStream>), BoxError> {
        Err(Box::new(Error::Unimplemented))
    }

    /// Returns a stream control and async buffer generator object asynchronously.
    /// Default implementation calls and blocks on `new_async_playback_stream()`.
    #[allow(clippy::type_complexity)]
    async fn async_new_async_playback_stream(
        &mut self,
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        buffer_size: usize,
        ex: &dyn AudioStreamsExecutor,
    ) -> Result<(Box<dyn StreamControl>, Box<dyn AsyncPlaybackBufferStream>), BoxError> {
        self.new_async_playback_stream(num_channels, format, frame_rate, buffer_size, ex)
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
        _effects: &[StreamEffect],
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
        _effects: &[StreamEffect],
        _ex: &dyn AudioStreamsExecutor,
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

    /// Returns a stream control and async buffer generator object asynchronously.
    /// Default implementation calls and blocks on `new_async_capture_stream()`.
    #[allow(clippy::type_complexity)]
    async fn async_new_async_capture_stream(
        &mut self,
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        buffer_size: usize,
        effects: &[StreamEffect],
        ex: &dyn AudioStreamsExecutor,
    ) -> Result<
        (
            Box<dyn StreamControl>,
            Box<dyn capture::AsyncCaptureBufferStream>,
        ),
        BoxError,
    > {
        self.new_async_capture_stream(num_channels, format, frame_rate, buffer_size, effects, ex)
    }

    /// Returns any open file descriptors needed by the implementor. The FD list helps users of the
    /// StreamSource enter Linux jails making sure not to close needed FDs.
    fn keep_rds(&self) -> Option<Vec<RawDescriptor>> {
        None
    }
}

/// `PlaybackBufferStream` provides `PlaybackBuffer`s to fill with audio samples for playback.
pub trait PlaybackBufferStream: Send {
    fn next_playback_buffer<'b, 's: 'b>(&'s mut self) -> Result<PlaybackBuffer<'b>, BoxError>;

    /// Call `f` with a `PlaybackBuffer`, and trigger the buffer done call back after. `f` should
    /// write playback data to the given `PlaybackBuffer`.
    fn write_playback_buffer<'b, 's: 'b>(
        &'s mut self,
        f: &mut dyn FnMut(&mut PlaybackBuffer<'b>) -> Result<(), BoxError>,
    ) -> Result<(), BoxError> {
        let mut buf = self.next_playback_buffer()?;
        f(&mut buf)?;
        buf.commit();
        Ok(())
    }
}

impl<S: PlaybackBufferStream + ?Sized> PlaybackBufferStream for &mut S {
    fn next_playback_buffer<'b, 's: 'b>(&'s mut self) -> Result<PlaybackBuffer<'b>, BoxError> {
        (**self).next_playback_buffer()
    }
}

/// `PlaybackBufferStream` provides `PlaybackBuffer`s asynchronously to fill with audio samples for
/// playback.
#[async_trait(?Send)]
pub trait AsyncPlaybackBufferStream: Send {
    async fn next_playback_buffer<'a>(
        &'a mut self,
        _ex: &dyn AudioStreamsExecutor,
    ) -> Result<AsyncPlaybackBuffer<'a>, BoxError>;
}

#[async_trait(?Send)]
impl<S: AsyncPlaybackBufferStream + ?Sized> AsyncPlaybackBufferStream for &mut S {
    async fn next_playback_buffer<'a>(
        &'a mut self,
        ex: &dyn AudioStreamsExecutor,
    ) -> Result<AsyncPlaybackBuffer<'a>, BoxError> {
        (**self).next_playback_buffer(ex).await
    }
}

/// Call `f` with a `AsyncPlaybackBuffer`, and trigger the buffer done call back after. `f` should
/// write playback data to the given `AsyncPlaybackBuffer`.
///
/// This cannot be a trait method because trait methods with generic parameters are not object safe.
pub async fn async_write_playback_buffer<F>(
    stream: &mut dyn AsyncPlaybackBufferStream,
    f: F,
    ex: &dyn AudioStreamsExecutor,
) -> Result<(), BoxError>
where
    F: for<'a> FnOnce(&'a mut AsyncPlaybackBuffer) -> Result<(), BoxError>,
{
    let mut buf = stream.next_playback_buffer(ex).await?;
    f(&mut buf)?;
    buf.commit().await;
    Ok(())
}

/// `StreamControl` provides a way to set the volume and mute states of a stream. `StreamControl`
/// is separate from the stream so it can be owned by a different thread if needed.
pub trait StreamControl: Send + Sync {
    fn set_volume(&mut self, _scaler: f64) {}
    fn set_mute(&mut self, _mute: bool) {}
}

/// `BufferCommit` is a cleanup funcion that must be called before dropping the buffer,
/// allowing arbitrary code to be run after the buffer is filled or read by the user.
pub trait BufferCommit {
    /// `write_playback_buffer` or `read_capture_buffer` would trigger this automatically. `nframes`
    /// indicates the number of audio frames that were read or written to the device.
    fn commit(&mut self, nframes: usize);
    /// `latency_bytes` the current device latency.
    /// For playback it means how many bytes need to be consumed
    /// before the current playback buffer will be played.
    /// For capture it means the latency in terms of bytes that the capture buffer was recorded.
    fn latency_bytes(&self) -> u32 {
        0
    }
}

/// `AsyncBufferCommit` is a cleanup funcion that must be called before dropping the buffer,
/// allowing arbitrary code to be run after the buffer is filled or read by the user.
#[async_trait(?Send)]
pub trait AsyncBufferCommit {
    /// `async_write_playback_buffer` or `async_read_capture_buffer` would trigger this
    /// automatically. `nframes` indicates the number of audio frames that were read or written to
    /// the device.
    async fn commit(&mut self, nframes: usize);
    /// `latency_bytes` the current device latency.
    /// For playback it means how many bytes need to be consumed
    /// before the current playback buffer will be played.
    /// For capture it means the latency in terms of bytes that the capture buffer was recorded.
    fn latency_bytes(&self) -> u32 {
        0
    }
}

/// Errors that are possible from a `PlaybackBuffer`.
#[sorted]
#[derive(Error, Debug)]
pub enum PlaybackBufferError {
    #[error("Invalid buffer length")]
    InvalidLength,
    #[error("Slicing of playback buffer out of bounds")]
    SliceOutOfBounds,
}

/// `AudioBuffer` is one buffer that holds buffer_size audio frames.
/// It is the inner data of `PlaybackBuffer` and `CaptureBuffer`.
struct AudioBuffer<'a> {
    buffer: &'a mut [u8],
    offset: usize,     // Read or Write offset in frames.
    frame_size: usize, // Size of a frame in bytes.
}

impl<'a> AudioBuffer<'a> {
    /// Returns the number of audio frames that fit in the buffer.
    pub fn frame_capacity(&self) -> usize {
        self.buffer.len() / self.frame_size
    }

    fn calc_len(&self, size: usize) -> usize {
        min(
            size / self.frame_size * self.frame_size,
            self.buffer.len() - self.offset,
        )
    }

    /// Writes up to `size` bytes directly to this buffer inside of the given callback function.
    pub fn write_copy_cb<F: FnOnce(&mut [u8])>(&mut self, size: usize, cb: F) -> io::Result<usize> {
        // only write complete frames.
        let len = self.calc_len(size);
        cb(&mut self.buffer[self.offset..(self.offset + len)]);
        self.offset += len;
        Ok(len)
    }

    /// Reads up to `size` bytes directly from this buffer inside of the given callback function.
    pub fn read_copy_cb<F: FnOnce(&[u8])>(&mut self, size: usize, cb: F) -> io::Result<usize> {
        let len = self.calc_len(size);
        cb(&self.buffer[self.offset..(self.offset + len)]);
        self.offset += len;
        Ok(len)
    }

    /// Copy data from an io::Reader
    pub fn copy_from(&mut self, reader: &mut dyn Read) -> io::Result<usize> {
        let bytes = reader.read(&mut self.buffer[self.offset..])?;
        self.offset += bytes;
        Ok(bytes)
    }

    /// Copy data to an io::Write
    pub fn copy_to(&mut self, writer: &mut dyn Write) -> io::Result<usize> {
        let bytes = writer.write(&self.buffer[self.offset..])?;
        self.offset += bytes;
        Ok(bytes)
    }
}

impl<'a> Write for AudioBuffer<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = (&mut self.buffer[self.offset..]).write(&buf[..buf.len()])?;
        self.offset += written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> Read for AudioBuffer<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = buf.len() / self.frame_size * self.frame_size;
        let written = (&mut buf[..len]).write(&self.buffer[self.offset..])?;
        self.offset += written;
        Ok(written)
    }
}

/// `PlaybackBuffer` is one buffer that holds buffer_size audio frames. It is used to temporarily
/// allow access to an audio buffer and notifes the owning stream of write completion when dropped.
pub struct PlaybackBuffer<'a> {
    buffer: AudioBuffer<'a>,
    drop: &'a mut dyn BufferCommit,
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
        F: BufferCommit,
    {
        if buffer.len() % frame_size != 0 {
            return Err(PlaybackBufferError::InvalidLength);
        }

        Ok(PlaybackBuffer {
            buffer: AudioBuffer {
                buffer,
                offset: 0,
                frame_size,
            },
            drop,
        })
    }

    /// Returns the number of audio frames that fit in the buffer.
    pub fn frame_capacity(&self) -> usize {
        self.buffer.frame_capacity()
    }

    /// This triggers the commit of `BufferCommit`. This should be called after the data is copied
    /// to the buffer.
    pub fn commit(&mut self) {
        self.drop
            .commit(self.buffer.offset / self.buffer.frame_size);
    }

    /// It returns how many bytes need to be consumed
    /// before the current playback buffer will be played.
    pub fn latency_bytes(&self) -> u32 {
        self.drop.latency_bytes()
    }

    /// Writes up to `size` bytes directly to this buffer inside of the given callback function.
    pub fn copy_cb<F: FnOnce(&mut [u8])>(&mut self, size: usize, cb: F) -> io::Result<usize> {
        self.buffer.write_copy_cb(size, cb)
    }
}

impl<'a> Write for PlaybackBuffer<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.buffer.flush()
    }
}

/// `AsyncPlaybackBuffer` is the async version of `PlaybackBuffer`.
pub struct AsyncPlaybackBuffer<'a> {
    buffer: AudioBuffer<'a>,
    trigger: &'a mut dyn AsyncBufferCommit,
}

impl<'a> AsyncPlaybackBuffer<'a> {
    /// Creates a new `AsyncPlaybackBuffer` that holds a reference to the backing memory specified
    /// in `buffer`.
    pub fn new<F>(
        frame_size: usize,
        buffer: &'a mut [u8],
        trigger: &'a mut F,
    ) -> Result<Self, PlaybackBufferError>
    where
        F: AsyncBufferCommit,
    {
        if buffer.len() % frame_size != 0 {
            return Err(PlaybackBufferError::InvalidLength);
        }

        Ok(AsyncPlaybackBuffer {
            buffer: AudioBuffer {
                buffer,
                offset: 0,
                frame_size,
            },
            trigger,
        })
    }

    /// Returns the number of audio frames that fit in the buffer.
    pub fn frame_capacity(&self) -> usize {
        self.buffer.frame_capacity()
    }

    /// This triggers the callback of `AsyncBufferCommit`. This should be called after the data is
    /// copied to the buffer.
    pub async fn commit(&mut self) {
        self.trigger
            .commit(self.buffer.offset / self.buffer.frame_size)
            .await;
    }

    /// It returns the latency in terms of bytes that the capture buffer was recorded.
    pub fn latency_bytes(&self) -> u32 {
        self.trigger.latency_bytes()
    }

    /// Writes up to `size` bytes directly to this buffer inside of the given callback function.
    pub fn copy_cb<F: FnOnce(&mut [u8])>(&mut self, size: usize, cb: F) -> io::Result<usize> {
        self.buffer.write_copy_cb(size, cb)
    }

    /// Copy data from an io::Reader
    pub fn copy_from(&mut self, reader: &mut dyn Read) -> io::Result<usize> {
        self.buffer.copy_from(reader)
    }
}

impl<'a> Write for AsyncPlaybackBuffer<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.buffer.flush()
    }
}
/// Stream that accepts playback samples but drops them.
pub struct NoopStream {
    buffer: Vec<u8>,
    frame_size: usize,
    interval: Duration,
    next_frame: Duration,
    start_time: Option<Instant>,
    buffer_drop: NoopBufferCommit,
}

/// NoopStream data that is needed from the buffer complete callback.
struct NoopBufferCommit {
    which_buffer: bool,
}

impl BufferCommit for NoopBufferCommit {
    fn commit(&mut self, _nwritten: usize) {
        // When a buffer completes, switch to the other one.
        self.which_buffer ^= true;
    }
}

#[async_trait(?Send)]
impl AsyncBufferCommit for NoopBufferCommit {
    async fn commit(&mut self, _nwritten: usize) {
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
            buffer_drop: NoopBufferCommit {
                which_buffer: false,
            },
        }
    }
}

impl PlaybackBufferStream for NoopStream {
    fn next_playback_buffer<'b, 's: 'b>(&'s mut self) -> Result<PlaybackBuffer<'b>, BoxError> {
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
        Ok(AsyncPlaybackBuffer::new(
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
        _ex: &dyn AudioStreamsExecutor,
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

/// `NoopStreamSourceGenerator` is a struct that implements [`StreamSourceGenerator`]
/// to generate [`NoopStreamSource`].
pub struct NoopStreamSourceGenerator;

impl NoopStreamSourceGenerator {
    pub fn new() -> Self {
        NoopStreamSourceGenerator {}
    }
}

impl Default for NoopStreamSourceGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamSourceGenerator for NoopStreamSourceGenerator {
    fn generate(&self) -> Result<Box<dyn StreamSource>, BoxError> {
        Ok(Box::new(NoopStreamSource))
    }
}

#[cfg(test)]
mod tests {
    use futures::FutureExt;
    use io::Write;

    use super::async_api::test::TestExecutor;
    use super::*;

    #[test]
    fn invalid_buffer_length() {
        // Playback buffers can't be created with a size that isn't divisible by the frame size.
        let mut pb_buf = [0xa5u8; 480 * 2 * 2 + 1];
        let mut buffer_drop = NoopBufferCommit {
            which_buffer: false,
        };
        assert!(PlaybackBuffer::new(2, &mut pb_buf, &mut buffer_drop).is_err());
    }

    #[test]
    fn audio_buffer_copy_from() {
        const PERIOD_SIZE: usize = 8192;
        const NUM_CHANNELS: usize = 6;
        const FRAME_SIZE: usize = NUM_CHANNELS * 2;
        let mut dst_buf = [0u8; PERIOD_SIZE * FRAME_SIZE];
        let src_buf = [0xa5u8; PERIOD_SIZE * FRAME_SIZE];
        let mut aud_buf = AudioBuffer {
            buffer: &mut dst_buf,
            offset: 0,
            frame_size: FRAME_SIZE,
        };
        aud_buf
            .copy_from(&mut &src_buf[..])
            .expect("all data should be copied.");
        assert_eq!(dst_buf, src_buf);
    }

    #[test]
    fn audio_buffer_copy_from_repeat() {
        const PERIOD_SIZE: usize = 8192;
        const NUM_CHANNELS: usize = 6;
        const FRAME_SIZE: usize = NUM_CHANNELS * 2;
        let mut dst_buf = [0u8; PERIOD_SIZE * FRAME_SIZE];
        let mut aud_buf = AudioBuffer {
            buffer: &mut dst_buf,
            offset: 0,
            frame_size: FRAME_SIZE,
        };
        let bytes = aud_buf
            .copy_from(&mut io::repeat(1))
            .expect("all data should be copied.");
        assert_eq!(bytes, PERIOD_SIZE * FRAME_SIZE);
        assert_eq!(dst_buf, [1u8; PERIOD_SIZE * FRAME_SIZE]);
    }

    #[test]
    fn audio_buffer_copy_to() {
        const PERIOD_SIZE: usize = 8192;
        const NUM_CHANNELS: usize = 6;
        const FRAME_SIZE: usize = NUM_CHANNELS * 2;
        let mut dst_buf = [0u8; PERIOD_SIZE * FRAME_SIZE];
        let mut src_buf = [0xa5u8; PERIOD_SIZE * FRAME_SIZE];
        let mut aud_buf = AudioBuffer {
            buffer: &mut src_buf,
            offset: 0,
            frame_size: FRAME_SIZE,
        };
        aud_buf
            .copy_to(&mut &mut dst_buf[..])
            .expect("all data should be copied.");
        assert_eq!(dst_buf, src_buf);
    }

    #[test]
    fn audio_buffer_copy_to_sink() {
        const PERIOD_SIZE: usize = 8192;
        const NUM_CHANNELS: usize = 6;
        const FRAME_SIZE: usize = NUM_CHANNELS * 2;
        let mut src_buf = [0xa5u8; PERIOD_SIZE * FRAME_SIZE];
        let mut aud_buf = AudioBuffer {
            buffer: &mut src_buf,
            offset: 0,
            frame_size: FRAME_SIZE,
        };
        let bytes = aud_buf
            .copy_to(&mut io::sink())
            .expect("all data should be copied.");
        assert_eq!(bytes, PERIOD_SIZE * FRAME_SIZE);
    }

    #[test]
    fn io_copy_audio_buffer() {
        const PERIOD_SIZE: usize = 8192;
        const NUM_CHANNELS: usize = 6;
        const FRAME_SIZE: usize = NUM_CHANNELS * 2;
        let mut dst_buf = [0u8; PERIOD_SIZE * FRAME_SIZE];
        let src_buf = [0xa5u8; PERIOD_SIZE * FRAME_SIZE];
        let mut aud_buf = AudioBuffer {
            buffer: &mut dst_buf,
            offset: 0,
            frame_size: FRAME_SIZE,
        };
        io::copy(&mut &src_buf[..], &mut aud_buf).expect("all data should be copied.");
        assert_eq!(dst_buf, src_buf);
    }

    #[test]
    fn commit() {
        struct TestCommit {
            frame_count: usize,
        }
        impl BufferCommit for TestCommit {
            fn commit(&mut self, nwritten: usize) {
                self.frame_count += nwritten;
            }
        }
        let mut test_commit = TestCommit { frame_count: 0 };
        {
            const FRAME_SIZE: usize = 4;
            let mut buf = [0u8; 480 * FRAME_SIZE];
            let mut pb_buf = PlaybackBuffer::new(FRAME_SIZE, &mut buf, &mut test_commit).unwrap();
            pb_buf.write_all(&[0xa5u8; 480 * FRAME_SIZE]).unwrap();
            pb_buf.commit();
        }
        assert_eq!(test_commit.frame_count, 480);
    }

    #[test]
    fn sixteen_bit_stereo() {
        let mut server = NoopStreamSource::new();
        let (_, mut stream) = server
            .new_playback_stream(2, SampleFormat::S16LE, 48000, 480)
            .unwrap();
        let mut copy_cb = |buf: &mut PlaybackBuffer| {
            assert_eq!(buf.buffer.frame_capacity(), 480);
            let pb_buf = [0xa5u8; 480 * 2 * 2];
            assert_eq!(buf.write(&pb_buf).unwrap(), 480 * 2 * 2);
            Ok(())
        };
        stream.write_playback_buffer(&mut copy_cb).unwrap();
    }

    #[test]
    fn consumption_rate() {
        let mut server = NoopStreamSource::new();
        let (_, mut stream) = server
            .new_playback_stream(2, SampleFormat::S16LE, 48000, 480)
            .unwrap();
        let start = Instant::now();
        {
            let mut copy_cb = |buf: &mut PlaybackBuffer| {
                let pb_buf = [0xa5u8; 480 * 2 * 2];
                assert_eq!(buf.write(&pb_buf).unwrap(), 480 * 2 * 2);
                Ok(())
            };
            stream.write_playback_buffer(&mut copy_cb).unwrap();
        }
        // The second call should block until the first buffer is consumed.
        let mut assert_cb = |_: &mut PlaybackBuffer| {
            let elapsed = start.elapsed();
            assert!(
                elapsed > Duration::from_millis(10),
                "next_playback_buffer didn't block long enough {}",
                elapsed.subsec_millis()
            );
            Ok(())
        };
        stream.write_playback_buffer(&mut assert_cb).unwrap();
    }

    #[test]
    fn async_commit() {
        struct TestCommit {
            frame_count: usize,
        }
        #[async_trait(?Send)]
        impl AsyncBufferCommit for TestCommit {
            async fn commit(&mut self, nwritten: usize) {
                self.frame_count += nwritten;
            }
        }
        async fn this_test() {
            let mut test_commit = TestCommit { frame_count: 0 };
            {
                const FRAME_SIZE: usize = 4;
                let mut buf = [0u8; 480 * FRAME_SIZE];
                let mut pb_buf =
                    AsyncPlaybackBuffer::new(FRAME_SIZE, &mut buf, &mut test_commit).unwrap();
                pb_buf.write_all(&[0xa5u8; 480 * FRAME_SIZE]).unwrap();
                pb_buf.commit().await;
            }
            assert_eq!(test_commit.frame_count, 480);
        }

        this_test().now_or_never();
    }

    #[test]
    fn consumption_rate_async() {
        async fn this_test(ex: &TestExecutor) {
            let mut server = NoopStreamSource::new();
            let (_, mut stream) = server
                .new_async_playback_stream(2, SampleFormat::S16LE, 48000, 480, ex)
                .unwrap();
            let start = Instant::now();
            {
                let copy_func = |buf: &mut AsyncPlaybackBuffer| {
                    let pb_buf = [0xa5u8; 480 * 2 * 2];
                    assert_eq!(buf.write(&pb_buf).unwrap(), 480 * 2 * 2);
                    Ok(())
                };
                async_write_playback_buffer(&mut *stream, copy_func, ex)
                    .await
                    .unwrap();
            }
            // The second call should block until the first buffer is consumed.
            let assert_func = |_: &mut AsyncPlaybackBuffer| {
                let elapsed = start.elapsed();
                assert!(
                    elapsed > Duration::from_millis(10),
                    "write_playback_buffer didn't block long enough {}",
                    elapsed.subsec_millis()
                );
                Ok(())
            };

            async_write_playback_buffer(&mut *stream, assert_func, ex)
                .await
                .unwrap();
        }

        let ex = TestExecutor {};
        this_test(&ex).now_or_never();
    }

    #[test]
    fn generate_noop_stream_source() {
        let generator: Box<dyn StreamSourceGenerator> = Box::new(NoopStreamSourceGenerator::new());
        generator
            .generate()
            .expect("failed to generate stream source");
    }
}

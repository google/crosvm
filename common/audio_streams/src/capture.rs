// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! ```
//! use audio_streams::{BoxError, capture::CaptureBuffer, SampleFormat, StreamSource,
//!     NoopStreamSource};
//! use std::io::Read;
//!
//! const buffer_size: usize = 120;
//! const num_channels: usize = 2;
//!
//! # fn main() -> std::result::Result<(),BoxError> {
//! let mut stream_source = NoopStreamSource::new();
//! let sample_format = SampleFormat::S16LE;
//! let frame_size = num_channels * sample_format.sample_bytes();
//!
//! let (_, mut stream) = stream_source
//!     .new_capture_stream(num_channels, sample_format, 48000, buffer_size, &[])?;
//! // Capture 10 buffers of zeros.
//! let mut buf = Vec::new();
//! buf.resize(buffer_size * frame_size, 0xa5u8);
//! for _ in 0..10 {
//!     let mut copy_func = |stream_buffer: &mut CaptureBuffer| {
//!         assert_eq!(stream_buffer.read(&mut buf)?, buffer_size * frame_size);
//!         Ok(())
//!     };
//!     stream.read_capture_buffer(&mut copy_func)?;
//! }
//! # Ok (())
//! # }
//! ```

use std::io;
use std::io::Read;
use std::io::Write;
use std::time::Duration;
use std::time::Instant;

use async_trait::async_trait;
use remain::sorted;
use thiserror::Error;

use super::async_api::AudioStreamsExecutor;
use super::AsyncBufferCommit;
use super::AudioBuffer;
use super::BoxError;
use super::BufferCommit;
use super::NoopBufferCommit;
use super::SampleFormat;

/// `CaptureBufferStream` provides `CaptureBuffer`s to read with audio samples from capture.
pub trait CaptureBufferStream: Send {
    fn next_capture_buffer<'b, 's: 'b>(&'s mut self) -> Result<CaptureBuffer<'b>, BoxError>;

    /// Call `f` with a `CaptureBuffer`, and trigger the buffer done call back after. `f` can read
    /// the capture data from the given `CaptureBuffer`.
    fn read_capture_buffer<'b, 's: 'b>(
        &'s mut self,
        f: &mut dyn FnMut(&mut CaptureBuffer<'b>) -> Result<(), BoxError>,
    ) -> Result<(), BoxError> {
        let mut buf = self.next_capture_buffer()?;
        f(&mut buf)?;
        buf.commit();
        Ok(())
    }
}

impl<S: CaptureBufferStream + ?Sized> CaptureBufferStream for &mut S {
    fn next_capture_buffer<'b, 's: 'b>(&'s mut self) -> Result<CaptureBuffer<'b>, BoxError> {
        (**self).next_capture_buffer()
    }
}

#[async_trait(?Send)]
pub trait AsyncCaptureBufferStream: Send {
    async fn next_capture_buffer<'a>(
        &'a mut self,
        _ex: &dyn AudioStreamsExecutor,
    ) -> Result<AsyncCaptureBuffer<'a>, BoxError>;
}

#[async_trait(?Send)]
impl<S: AsyncCaptureBufferStream + ?Sized> AsyncCaptureBufferStream for &mut S {
    async fn next_capture_buffer<'a>(
        &'a mut self,
        ex: &dyn AudioStreamsExecutor,
    ) -> Result<AsyncCaptureBuffer<'a>, BoxError> {
        (**self).next_capture_buffer(ex).await
    }
}

/// `CaptureBuffer` contains a block of audio samples got from capture stream. It provides
/// temporary view to those samples and will notifies capture stream when dropped.
/// Note that it'll always send `buffer.len() / frame_size` to drop function when it got destroyed
/// since `CaptureBufferStream` assumes that users get all the samples from the buffer.
pub struct CaptureBuffer<'a> {
    buffer: AudioBuffer<'a>,
    drop: &'a mut dyn BufferCommit,
}

/// Async version of 'CaptureBuffer`
pub struct AsyncCaptureBuffer<'a> {
    buffer: AudioBuffer<'a>,
    trigger: &'a mut dyn AsyncBufferCommit,
}

/// Errors that are possible from a `CaptureBuffer`.
#[sorted]
#[derive(Error, Debug)]
pub enum CaptureBufferError {
    #[error("Invalid buffer length")]
    InvalidLength,
}

impl<'a> CaptureBuffer<'a> {
    /// Creates a new `CaptureBuffer` that holds a reference to the backing memory specified in
    /// `buffer`.
    pub fn new<F>(
        frame_size: usize,
        buffer: &'a mut [u8],
        drop: &'a mut F,
    ) -> Result<Self, CaptureBufferError>
    where
        F: BufferCommit,
    {
        if buffer.len() % frame_size != 0 {
            return Err(CaptureBufferError::InvalidLength);
        }

        Ok(CaptureBuffer {
            buffer: AudioBuffer {
                buffer,
                frame_size,
                offset: 0,
            },
            drop,
        })
    }

    /// Returns the number of audio frames that fit in the buffer.
    pub fn frame_capacity(&self) -> usize {
        self.buffer.frame_capacity()
    }

    /// This triggers the callback of `BufferCommit`. This should be called after the data is read
    /// from the buffer.
    ///
    /// Always sends `frame_capacity`.
    pub fn commit(&mut self) {
        self.drop.commit(self.frame_capacity());
    }

    pub fn latency_bytes(&self) -> u32 {
        self.drop.latency_bytes()
    }

    /// Reads up to `size` bytes directly from this buffer inside of the given callback function.
    pub fn copy_cb<F: FnOnce(&[u8])>(&mut self, size: usize, cb: F) -> io::Result<usize> {
        self.buffer.read_copy_cb(size, cb)
    }
}

impl<'a> Read for CaptureBuffer<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.buffer.read(buf)
    }
}

impl<'a> AsyncCaptureBuffer<'a> {
    /// Creates a new `AsyncCaptureBuffer` that holds a reference to the backing memory specified in
    /// `buffer`.
    pub fn new<F>(
        frame_size: usize,
        buffer: &'a mut [u8],
        trigger: &'a mut F,
    ) -> Result<Self, CaptureBufferError>
    where
        F: AsyncBufferCommit,
    {
        if buffer.len() % frame_size != 0 {
            return Err(CaptureBufferError::InvalidLength);
        }

        Ok(AsyncCaptureBuffer {
            buffer: AudioBuffer {
                buffer,
                frame_size,
                offset: 0,
            },
            trigger,
        })
    }

    /// Returns the number of audio frames that fit in the buffer.
    pub fn frame_capacity(&self) -> usize {
        self.buffer.frame_capacity()
    }

    /// This triggers the callback of `AsyncBufferCommit`. This should be called after the data is
    /// read from the buffer.
    ///
    /// Always sends `frame_capacity`.
    pub async fn commit(&mut self) {
        self.trigger.commit(self.frame_capacity()).await;
    }

    pub fn latency_bytes(&self) -> u32 {
        self.trigger.latency_bytes()
    }

    /// Reads up to `size` bytes directly from this buffer inside of the given callback function.
    pub fn copy_cb<F: FnOnce(&[u8])>(&mut self, size: usize, cb: F) -> io::Result<usize> {
        self.buffer.read_copy_cb(size, cb)
    }

    /// Copy data to an io::Write
    pub fn copy_to(&mut self, writer: &mut dyn Write) -> io::Result<usize> {
        self.buffer.copy_to(writer)
    }
}

impl<'a> Read for AsyncCaptureBuffer<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.buffer.read(buf)
    }
}

/// Stream that provides null capture samples.
pub struct NoopCaptureStream {
    buffer: Vec<u8>,
    frame_size: usize,
    interval: Duration,
    next_frame: Duration,
    start_time: Option<Instant>,
    buffer_drop: NoopBufferCommit,
}

impl NoopCaptureStream {
    pub fn new(
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        buffer_size: usize,
    ) -> Self {
        let frame_size = format.sample_bytes() * num_channels;
        let interval = Duration::from_millis(buffer_size as u64 * 1000 / frame_rate as u64);
        NoopCaptureStream {
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

impl CaptureBufferStream for NoopCaptureStream {
    fn next_capture_buffer<'b, 's: 'b>(&'s mut self) -> Result<CaptureBuffer<'b>, BoxError> {
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
        Ok(CaptureBuffer::new(
            self.frame_size,
            &mut self.buffer,
            &mut self.buffer_drop,
        )?)
    }
}

#[async_trait(?Send)]
impl AsyncCaptureBufferStream for NoopCaptureStream {
    async fn next_capture_buffer<'a>(
        &'a mut self,
        ex: &dyn AudioStreamsExecutor,
    ) -> Result<AsyncCaptureBuffer<'a>, BoxError> {
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
        Ok(AsyncCaptureBuffer::new(
            self.frame_size,
            &mut self.buffer,
            &mut self.buffer_drop,
        )?)
    }
}

/// Call `f` with a `AsyncCaptureBuffer`, and trigger the buffer done call back after. `f` can read
/// the capture data from the given `AsyncCaptureBuffer`.
///
/// This cannot be a trait method because trait methods with generic parameters are not object safe.
pub async fn async_read_capture_buffer<F>(
    stream: &mut dyn AsyncCaptureBufferStream,
    f: F,
    ex: &dyn AudioStreamsExecutor,
) -> Result<(), BoxError>
where
    F: FnOnce(&mut AsyncCaptureBuffer) -> Result<(), BoxError>,
{
    let mut buf = stream.next_capture_buffer(ex).await?;
    f(&mut buf)?;
    buf.commit().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use futures::FutureExt;

    use super::super::async_api::test::TestExecutor;
    use super::super::*;
    use super::*;

    #[test]
    fn invalid_buffer_length() {
        // Capture buffers can't be created with a size that isn't divisible by the frame size.
        let mut cp_buf = [0xa5u8; 480 * 2 * 2 + 1];
        let mut buffer_drop = NoopBufferCommit {
            which_buffer: false,
        };
        assert!(CaptureBuffer::new(2, &mut cp_buf, &mut buffer_drop).is_err());
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
            let mut cp_buf = CaptureBuffer::new(FRAME_SIZE, &mut buf, &mut test_commit).unwrap();
            let mut local_buf = [0u8; 240 * FRAME_SIZE];
            assert_eq!(cp_buf.read(&mut local_buf).unwrap(), 240 * FRAME_SIZE);
            cp_buf.commit();
        }
        // This should be 480 no matter how many samples are read.
        assert_eq!(test_commit.frame_count, 480);
    }

    #[test]
    fn sixteen_bit_stereo() {
        let mut server = NoopStreamSource::new();
        let (_, mut stream) = server
            .new_capture_stream(2, SampleFormat::S16LE, 48000, 480, &[])
            .unwrap();
        let mut copy_func = |b: &mut CaptureBuffer| {
            assert_eq!(b.buffer.frame_capacity(), 480);
            let mut pb_buf = [0xa5u8; 480 * 2 * 2];
            assert_eq!(b.read(&mut pb_buf).unwrap(), 480 * 2 * 2);
            Ok(())
        };
        stream.read_capture_buffer(&mut copy_func).unwrap();
    }

    #[test]
    fn consumption_rate() {
        let mut server = NoopStreamSource::new();
        let (_, mut stream) = server
            .new_capture_stream(2, SampleFormat::S16LE, 48000, 480, &[])
            .unwrap();
        let start = Instant::now();
        {
            let mut copy_func = |b: &mut CaptureBuffer| {
                let mut cp_buf = [0xa5u8; 480 * 2 * 2];
                assert_eq!(b.read(&mut cp_buf).unwrap(), 480 * 2 * 2);
                for buf in cp_buf.iter() {
                    assert_eq!(*buf, 0, "Read samples should all be zeros.");
                }
                Ok(())
            };
            stream.read_capture_buffer(&mut copy_func).unwrap();
        }
        // The second call should block until the first buffer is consumed.
        let mut assert_func = |_: &mut CaptureBuffer| {
            let elapsed = start.elapsed();
            assert!(
                elapsed > Duration::from_millis(10),
                "next_capture_buffer didn't block long enough {}",
                elapsed.subsec_millis()
            );
            Ok(())
        };
        stream.read_capture_buffer(&mut assert_func).unwrap();
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
                let mut cp_buf =
                    AsyncCaptureBuffer::new(FRAME_SIZE, &mut buf, &mut test_commit).unwrap();
                let mut local_buf = [0u8; 240 * FRAME_SIZE];
                assert_eq!(cp_buf.read(&mut local_buf).unwrap(), 240 * FRAME_SIZE);
                cp_buf.commit().await;
            }
            // This should be 480 no matter how many samples are read.
            assert_eq!(test_commit.frame_count, 480);
        }

        this_test().now_or_never();
    }

    #[test]
    fn consumption_rate_async() {
        async fn this_test(ex: &TestExecutor) {
            let mut server = NoopStreamSource::new();
            let (_, mut stream) = server
                .new_async_capture_stream(2, SampleFormat::S16LE, 48000, 480, &[], ex)
                .unwrap();
            let start = Instant::now();
            {
                let copy_func = |buf: &mut AsyncCaptureBuffer| {
                    let mut cp_buf = [0xa5u8; 480 * 2 * 2];
                    assert_eq!(buf.read(&mut cp_buf).unwrap(), 480 * 2 * 2);
                    for buf in cp_buf.iter() {
                        assert_eq!(*buf, 0, "Read samples should all be zeros.");
                    }
                    Ok(())
                };
                async_read_capture_buffer(&mut *stream, copy_func, ex)
                    .await
                    .unwrap();
            }
            // The second call should block until the first buffer is consumed.
            let assert_func = |_: &mut AsyncCaptureBuffer| {
                let elapsed = start.elapsed();
                assert!(
                    elapsed > Duration::from_millis(10),
                    "write_playback_buffer didn't block long enough {}",
                    elapsed.subsec_millis()
                );
                Ok(())
            };
            async_read_capture_buffer(&mut *stream, assert_func, ex)
                .await
                .unwrap();
        }

        let ex = TestExecutor {};
        this_test(&ex).now_or_never();
    }
}

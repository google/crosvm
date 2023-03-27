// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::io::Error as IOError;
use std::slice;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use async_trait::async_trait;
use audio_streams::AsyncBufferCommit;
use audio_streams::AsyncPlaybackBuffer;
use audio_streams::AsyncPlaybackBufferStream;
use audio_streams::AudioStreamsExecutor;
use audio_streams::BoxError;
use audio_streams::NoopStreamControl;
use audio_streams::SampleFormat;
use audio_streams::StreamControl;
use audio_streams::StreamSource;
use audio_streams::StreamSourceGenerator;
use base::warn;
use base::MappedRegion;
use base::MemoryMapping;
use base::MemoryMappingBuilder;
use base::MmapError;
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Failed to build memory mapping: {0}")]
    BuildMemoryMapping(MmapError),
    #[error("Failed to clone file descriptor: {0}")]
    Clone(IOError),
    #[error("Not implemented")]
    Unimplemented,
}

/// An Audio Stream that can be used to write playback buffer to a file.
/// `FileStream` doesn't directly open and write to file. It receives
/// an mmap of a file instead.
///
/// Note that `FileStream` also needs the mmap-ed file has allocated some spaces
/// to be written. If the playback buffer exceeds the allocated spaces,
/// it will invoke `panic!`
pub struct FileStream {
    /// A MemoryMapping that will hold the copy of the playback buffer.
    memory_mapping: AudioMemoryMapping,
    /// Number of bytes that has been written.
    offset: Arc<AtomicUsize>,
    /// Number of bytes in a single audio frame.
    frame_size: usize,
    /// Length of the current playback buffer in bytes.
    buffer_mem_length: usize,

    /// Duration of an audio in milliseconds for the current `buffer_size`.
    interval_ms: Duration,
    /// Time marker of correct time to return next buffer.
    next_frame: Duration,
    /// Timestamp that records when the stream starts.
    start_time: Option<Instant>,
    /// Type that will be called before the buffer is dropped.
    buffer_drop: FileStreamBufferCommit,
}

impl FileStream {
    fn new(
        memory_mapping: AudioMemoryMapping,
        offset: Arc<AtomicUsize>,
        frame_size: usize,
        buffer_mem_length: usize,
        interval_ms: Duration,
    ) -> Self {
        let max_offset = memory_mapping.size();
        FileStream {
            memory_mapping,
            offset: offset.clone(),
            frame_size,
            buffer_mem_length,

            interval_ms,
            next_frame: interval_ms,
            start_time: None,
            buffer_drop: FileStreamBufferCommit {
                frame_size,
                offset,
                max_offset,
            },
        }
    }
}

#[async_trait(?Send)]
impl AsyncPlaybackBufferStream for FileStream {
    async fn next_playback_buffer<'a>(
        &'a mut self,
        ex: &dyn AudioStreamsExecutor,
    ) -> Result<AsyncPlaybackBuffer<'a>, BoxError> {
        if let Some(start_time) = self.start_time {
            let elapsed = start_time.elapsed();
            if elapsed < self.next_frame {
                ex.delay(self.next_frame - elapsed).await?;
            }
            self.next_frame += self.interval_ms;
        } else {
            self.start_time = Some(Instant::now());
            self.next_frame = self.interval_ms;
        }

        let offset = self.offset.load(Ordering::Relaxed);
        let buffer = self
            .memory_mapping
            .get_slice_mut(offset, self.buffer_mem_length);

        Ok(AsyncPlaybackBuffer::new(
            self.frame_size,
            buffer,
            &mut self.buffer_drop,
        )?)
    }
}

struct FileStreamSource {
    file: File,
    file_size: usize,
    offset: Arc<AtomicUsize>,
}

impl FileStreamSource {
    fn new(file: File, file_size: usize, offset: Arc<AtomicUsize>) -> Self {
        FileStreamSource {
            file,
            file_size,
            offset,
        }
    }
}

impl StreamSource for FileStreamSource {
    fn new_async_playback_stream(
        &mut self,
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        buffer_size: usize,
        _ex: &dyn AudioStreamsExecutor,
    ) -> Result<(Box<dyn StreamControl>, Box<dyn AsyncPlaybackBufferStream>), BoxError> {
        let memory_mapping = MemoryMappingBuilder::new(self.file_size)
            .from_file(&self.file)
            .build()
            .map_err(Error::BuildMemoryMapping)?;

        let frame_size = format.sample_bytes() * num_channels;
        let buffer_mem_length = buffer_size * frame_size;
        let memory_mapping = AudioMemoryMapping::new(memory_mapping, buffer_mem_length);
        let interval_ms = Duration::from_millis(buffer_size as u64 * 1000 / frame_rate as u64);
        Ok((
            Box::new(NoopStreamControl::new()),
            Box::new(FileStream::new(
                memory_mapping,
                self.offset.clone(),
                frame_size,
                buffer_mem_length,
                interval_ms,
            )),
        ))
    }

    fn new_playback_stream(
        &mut self,
        _num_channels: usize,
        _format: SampleFormat,
        _frame_rate: u32,
        _buffer_size: usize,
    ) -> Result<
        (
            Box<dyn StreamControl>,
            Box<dyn audio_streams::PlaybackBufferStream>,
        ),
        BoxError,
    > {
        Err(Box::new(Error::Unimplemented))
    }
}

/// `FileStreamSourceGenerator` is a struct that implements [`StreamSourceGenerator`]
/// for `FileStreamSource`.
pub struct FileStreamSourceGenerator {
    /// File descriptor which will be used to write playback buffer.
    file: File,
    /// Size of the output file in bytes.
    file_size: usize,
    /// Number of bytes that has been written to the file.
    offset: Arc<AtomicUsize>,
}

impl FileStreamSourceGenerator {
    /// Creates a new `FileStreamSourceGenerator` by given arguments.
    /// It expects `file` has `file_size` of bytes allocated spaces.
    ///
    /// # Arguments
    ///
    /// * `file` - The file where audio playback buffer will be written.
    /// * `file_size` - The size of bytes allocated for playback_file.
    pub fn new(file: File, file_size: usize) -> Self {
        FileStreamSourceGenerator {
            file,
            file_size,
            offset: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl StreamSourceGenerator for FileStreamSourceGenerator {
    fn generate(&self) -> Result<Box<dyn StreamSource>, BoxError> {
        Ok(Box::new(FileStreamSource::new(
            self.file.try_clone().map_err(Error::Clone)?,
            self.file_size,
            self.offset.clone(),
        )))
    }
}

struct FileStreamBufferCommit {
    frame_size: usize,
    offset: Arc<AtomicUsize>,
    max_offset: usize,
}

#[async_trait(?Send)]
impl AsyncBufferCommit for FileStreamBufferCommit {
    async fn commit(&mut self, nwritten: usize) {
        let written_bytes = nwritten * self.frame_size;
        if self.offset.load(Ordering::Relaxed) + written_bytes < self.max_offset {
            self.offset.fetch_add(written_bytes, Ordering::Relaxed);
        }
    }
}

struct AudioMemoryMapping {
    memory_mapping: MemoryMapping,
    zero_buffer: Vec<u8>,
}

impl AudioMemoryMapping {
    fn new(memory_mapping: MemoryMapping, buffer_mem_length: usize) -> Self {
        AudioMemoryMapping {
            memory_mapping,
            zero_buffer: vec![0; buffer_mem_length],
        }
    }

    fn get_slice_mut(&mut self, offset: usize, len: usize) -> &mut [u8] {
        if offset + len >= self.memory_mapping.size() {
            warn!("Accessing unallocated region");
            return &mut self.zero_buffer;
        }
        // safe because the region returned is owned by self.memory_mapping
        unsafe { slice::from_raw_parts_mut(self.memory_mapping.as_ptr().add(offset), len) }
    }

    fn size(&self) -> usize {
        self.memory_mapping.size()
    }
}

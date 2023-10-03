// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides an implementation of the audio_streams::shm_streams::ShmStream trait using the VioS
//! client.
//! Given that the VioS server doesn't emit an event when the next buffer is expected, this
//! implementation uses thread::sleep to drive the frame timings.

use std::fs::File;
use std::os::unix::io::FromRawFd;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use audio_streams::shm_streams::BufferSet;
use audio_streams::shm_streams::ServerRequest;
use audio_streams::shm_streams::SharedMemory as AudioSharedMemory;
use audio_streams::shm_streams::ShmStream;
use audio_streams::shm_streams::ShmStreamSource;
use audio_streams::BoxError;
use audio_streams::SampleFormat;
use audio_streams::StreamDirection;
use audio_streams::StreamEffect;
use base::error;
use base::linux::SharedMemoryLinux;
use base::Error as SysError;
use base::MemoryMapping;
use base::MemoryMappingBuilder;
use base::RawDescriptor;
use base::SharedMemory;
use data_model::VolatileMemory;
use sync::Mutex;

use super::shm_vios::Error;
use super::shm_vios::Result;
use super::shm_vios::VioSClient;
use super::shm_vios::VioSStreamParams;
use crate::virtio::snd::common::*;
use crate::virtio::snd::constants::*;

// This is the error type used in audio_streams::shm_streams. Unfortunately, it's not declared
// public there so it needs to be re-declared here. It also prevents the usage of anyhow::Error.
type GenericResult<T> = std::result::Result<T, BoxError>;

enum StreamState {
    Available,
    Acquired,
    Active,
}

struct StreamDesc {
    state: Arc<Mutex<StreamState>>,
    direction: StreamDirection,
}

/// Adapter that provides the ShmStreamSource trait around the VioS backend.
pub struct VioSShmStreamSource {
    vios_client: Arc<Mutex<VioSClient>>,
    stream_descs: Vec<StreamDesc>,
}

impl VioSShmStreamSource {
    /// Creates a new stream source given the path to the audio server's socket.
    pub fn new<P: AsRef<Path>>(server: P) -> Result<VioSShmStreamSource> {
        let vios_client = Arc::new(Mutex::new(VioSClient::try_new(server)?));
        let mut stream_descs: Vec<StreamDesc> = Vec::new();
        let mut idx = 0u32;
        while let Some(info) = vios_client.lock().stream_info(idx) {
            stream_descs.push(StreamDesc {
                state: Arc::new(Mutex::new(StreamState::Active)),
                direction: if info.direction == VIRTIO_SND_D_OUTPUT {
                    StreamDirection::Playback
                } else {
                    StreamDirection::Capture
                },
            });
            idx += 1;
        }
        Ok(Self {
            vios_client,
            stream_descs,
        })
    }
}

impl VioSShmStreamSource {
    fn new_stream_inner(
        &mut self,
        stream_id: u32,
        direction: StreamDirection,
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        buffer_size: usize,
        _effects: &[StreamEffect],
        client_shm: &dyn AudioSharedMemory<Error = base::Error>,
        _buffer_offsets: [u64; 2],
    ) -> GenericResult<Box<dyn ShmStream>> {
        let frame_size = num_channels * format.sample_bytes();
        let period_bytes = (frame_size * buffer_size) as u32;
        self.vios_client.lock().prepare_stream(stream_id)?;
        let params = VioSStreamParams {
            buffer_bytes: 2 * period_bytes,
            period_bytes,
            features: 0u32,
            channels: num_channels as u8,
            format: from_sample_format(format),
            rate: virtio_frame_rate(frame_rate)?,
        };
        self.vios_client
            .lock()
            .set_stream_parameters(stream_id, params)?;
        self.vios_client.lock().start_stream(stream_id)?;
        VioSndShmStream::new(
            buffer_size,
            num_channels,
            format,
            frame_rate,
            stream_id,
            direction,
            self.vios_client.clone(),
            client_shm,
            self.stream_descs[stream_id as usize].state.clone(),
        )
    }

    fn get_unused_stream_id(&self, direction: StreamDirection) -> Option<u32> {
        self.stream_descs
            .iter()
            .position(|s| match &*s.state.lock() {
                StreamState::Available => s.direction == direction,
                _ => false,
            })
            .map(|idx| idx as u32)
    }
}

impl ShmStreamSource<base::Error> for VioSShmStreamSource {
    /// Creates a new stream
    #[allow(clippy::too_many_arguments)]
    fn new_stream(
        &mut self,
        direction: StreamDirection,
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        buffer_size: usize,
        effects: &[StreamEffect],
        client_shm: &dyn AudioSharedMemory<Error = base::Error>,
        buffer_offsets: [u64; 2],
    ) -> GenericResult<Box<dyn ShmStream>> {
        self.vios_client.lock().start_bg_thread()?;
        let stream_id = self
            .get_unused_stream_id(direction)
            .ok_or(Box::new(Error::NoStreamsAvailable))?;
        let stream = self
            .new_stream_inner(
                stream_id,
                direction,
                num_channels,
                format,
                frame_rate,
                buffer_size,
                effects,
                client_shm,
                buffer_offsets,
            )
            .map_err(|e| {
                // Attempt to release the stream so that it can be used later. This is a best effort
                // attempt, so we ignore any error it may return.
                let _ = self.vios_client.lock().release_stream(stream_id);
                e
            })?;
        *self.stream_descs[stream_id as usize].state.lock() = StreamState::Acquired;
        Ok(stream)
    }

    /// Get a list of file descriptors used by the implementation.
    ///
    /// Returns any open file descriptors needed by the implementation.
    /// This list helps users of the ShmStreamSource enter Linux jails without
    /// closing needed file descriptors.
    fn keep_fds(&self) -> Vec<RawDescriptor> {
        self.vios_client.lock().keep_rds()
    }
}

/// Adapter around a VioS stream that implements the ShmStream trait.
pub struct VioSndShmStream {
    num_channels: usize,
    frame_rate: u32,
    buffer_size: usize,
    frame_size: usize,
    interval: Duration,
    next_frame: Duration,
    start_time: Instant,
    stream_id: u32,
    direction: StreamDirection,
    vios_client: Arc<Mutex<VioSClient>>,
    client_shm: SharedMemory,
    state: Arc<Mutex<StreamState>>,
}

impl VioSndShmStream {
    /// Creates a new shm stream.
    fn new(
        buffer_size: usize,
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        stream_id: u32,
        direction: StreamDirection,
        vios_client: Arc<Mutex<VioSClient>>,
        client_shm: &dyn AudioSharedMemory<Error = base::Error>,
        state: Arc<Mutex<StreamState>>,
    ) -> GenericResult<Box<dyn ShmStream>> {
        let interval = Duration::from_millis(buffer_size as u64 * 1000 / frame_rate as u64);

        let dup_fd = unsafe {
            // Safe because fcntl doesn't affect memory and client_shm should wrap a known valid
            // file descriptor.
            libc::fcntl(client_shm.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0)
        };
        if dup_fd < 0 {
            return Err(Box::new(Error::DupError(SysError::last())));
        }
        let file = unsafe {
            // safe because we checked the result of libc::fcntl()
            File::from_raw_fd(dup_fd)
        };
        let client_shm_clone = SharedMemory::from_file(file).map_err(Error::BaseMmapError)?;

        Ok(Box::new(Self {
            num_channels,
            frame_rate,
            buffer_size,
            frame_size: format.sample_bytes() * num_channels,
            interval,
            next_frame: interval,
            start_time: Instant::now(),
            stream_id,
            direction,
            vios_client,
            client_shm: client_shm_clone,
            state,
        }))
    }
}

impl ShmStream for VioSndShmStream {
    fn frame_size(&self) -> usize {
        self.frame_size
    }

    fn num_channels(&self) -> usize {
        self.num_channels
    }

    fn frame_rate(&self) -> u32 {
        self.frame_rate
    }

    /// Waits until the next time a frame should be sent to the server. The server may release the
    /// previous buffer much sooner than it needs the next one, so this function may sleep to wait
    /// for the right time.
    fn wait_for_next_action_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> GenericResult<Option<ServerRequest>> {
        let elapsed = self.start_time.elapsed();
        if elapsed < self.next_frame {
            if timeout < self.next_frame - elapsed {
                std::thread::sleep(timeout);
                return Ok(None);
            } else {
                std::thread::sleep(self.next_frame - elapsed);
            }
        }
        self.next_frame += self.interval;
        Ok(Some(ServerRequest::new(self.buffer_size, self)))
    }
}

impl BufferSet for VioSndShmStream {
    fn callback(&mut self, offset: usize, frames: usize) -> GenericResult<()> {
        match self.direction {
            StreamDirection::Playback => {
                let requested_size = frames * self.frame_size;
                let shm_ref = &mut self.client_shm;
                let (_, res) = self.vios_client.lock().inject_audio_data::<Result<()>, _>(
                    self.stream_id,
                    requested_size,
                    |slice| {
                        if requested_size != slice.size() {
                            error!(
                                "Buffer size is different than the requested size: {} vs {}",
                                requested_size,
                                slice.size()
                            );
                        }
                        let size = std::cmp::min(requested_size, slice.size());
                        let (src_mmap, mmap_offset) = mmap_buffer(shm_ref, offset, size)?;
                        let src_slice = src_mmap
                            .get_slice(mmap_offset, size)
                            .map_err(Error::VolatileMemoryError)?;
                        src_slice.copy_to_volatile_slice(slice);
                        Ok(())
                    },
                )?;
                res?;
            }
            StreamDirection::Capture => {
                let requested_size = frames * self.frame_size;
                let shm_ref = &mut self.client_shm;
                let (_, res) = self
                    .vios_client
                    .lock()
                    .request_audio_data::<Result<()>, _>(
                        self.stream_id,
                        requested_size,
                        |slice| {
                            if requested_size != slice.size() {
                                error!(
                                    "Buffer size is different than the requested size: {} vs {}",
                                    requested_size,
                                    slice.size()
                                );
                            }
                            let size = std::cmp::min(requested_size, slice.size());
                            let (dst_mmap, mmap_offset) = mmap_buffer(shm_ref, offset, size)?;
                            let dst_slice = dst_mmap
                                .get_slice(mmap_offset, size)
                                .map_err(Error::VolatileMemoryError)?;
                            slice.copy_to_volatile_slice(dst_slice);
                            Ok(())
                        },
                    )?;
                res?;
            }
        }
        Ok(())
    }

    fn ignore(&mut self) -> GenericResult<()> {
        Ok(())
    }
}

impl Drop for VioSndShmStream {
    fn drop(&mut self) {
        let stream_id = self.stream_id;
        {
            let vios_client = self.vios_client.lock();
            if let Err(e) = vios_client
                .stop_stream(stream_id)
                .and_then(|_| vios_client.release_stream(stream_id))
            {
                error!("Failed to stop and release stream {}: {}", stream_id, e);
            }
        }
        *self.state.lock() = StreamState::Available;
    }
}

/// Memory map a shared memory object to access an audio buffer. The buffer may not be located at an
/// offset aligned to page size, so the offset within the mapped region is returned along with the
/// MemoryMapping struct.
fn mmap_buffer(
    src: &mut SharedMemory,
    offset: usize,
    size: usize,
) -> Result<(MemoryMapping, usize)> {
    // If the buffer is not aligned to page size a bigger region needs to be mapped.
    let aligned_offset = offset & !(base::pagesize() - 1);
    let offset_from_mapping_start = offset - aligned_offset;
    let extended_size = size + offset_from_mapping_start;

    let mmap = MemoryMappingBuilder::new(extended_size)
        .offset(aligned_offset as u64)
        .from_shared_memory(src)
        .build()
        .map_err(Error::GuestMmapError)?;

    Ok((mmap, offset_from_mapping_start))
}

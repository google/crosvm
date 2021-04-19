// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides an implementation of the audio_streams::shm_streams::ShmStream trait using the VioS
//! client.
//! Given that the VioS server doesn't emit an event when the next buffer is expected, this
//! implementation uses thread::sleep to drive the frame timings.

use super::shm_vios::{VioSClient, VioSStreamParams};

use crate::virtio::snd::constants::*;

use audio_streams::shm_streams::{BufferSet, ServerRequest, ShmStream, ShmStreamSource};
use audio_streams::{BoxError, SampleFormat, StreamDirection, StreamEffect};

use base::{error, SharedMemory, SharedMemoryUnix};

use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sys_util::{Error as SysError, SharedMemory as SysSharedMemory};

use super::shm_vios::{Error, Result};

// This is the error type used in audio_streams::shm_streams. Unfortunately, it's not declared
// public there so it needs to be re-declared here. It also prevents the usage of anyhow::Error.
type GenericResult<T> = std::result::Result<T, BoxError>;

/// Adapter that provides the ShmStreamSource trait around the VioS backend.
pub struct VioSShmStreamSource {
    vios_client: Arc<VioSClient>,
}

impl VioSShmStreamSource {
    /// Creates a new stream source given the path to the audio server's socket.
    pub fn new<P: AsRef<Path>>(server: P) -> Result<VioSShmStreamSource> {
        Ok(Self {
            vios_client: Arc::new(VioSClient::try_new(server)?),
        })
    }
}

fn from_sample_format(format: SampleFormat) -> u8 {
    match format {
        SampleFormat::U8 => VIRTIO_SND_PCM_FMT_U8,
        SampleFormat::S16LE => VIRTIO_SND_PCM_FMT_U16,
        SampleFormat::S24LE => VIRTIO_SND_PCM_FMT_U24,
        SampleFormat::S32LE => VIRTIO_SND_PCM_FMT_U32,
    }
}

fn virtio_frame_rate(frame_rate: u32) -> GenericResult<u8> {
    Ok(match frame_rate {
        5512u32 => VIRTIO_SND_PCM_RATE_5512,
        8000u32 => VIRTIO_SND_PCM_RATE_8000,
        11025u32 => VIRTIO_SND_PCM_RATE_11025,
        16000u32 => VIRTIO_SND_PCM_RATE_16000,
        22050u32 => VIRTIO_SND_PCM_RATE_22050,
        32000u32 => VIRTIO_SND_PCM_RATE_32000,
        44100u32 => VIRTIO_SND_PCM_RATE_44100,
        48000u32 => VIRTIO_SND_PCM_RATE_48000,
        64000u32 => VIRTIO_SND_PCM_RATE_64000,
        88200u32 => VIRTIO_SND_PCM_RATE_88200,
        96000u32 => VIRTIO_SND_PCM_RATE_96000,
        176400u32 => VIRTIO_SND_PCM_RATE_176400,
        192000u32 => VIRTIO_SND_PCM_RATE_192000,
        384000u32 => VIRTIO_SND_PCM_RATE_384000,
        _ => {
            return Err(Box::new(Error::UnsupportedFrameRate(frame_rate)));
        }
    })
}

impl ShmStreamSource for VioSShmStreamSource {
    /// Creates a new stream
    #[allow(clippy::too_many_arguments)]
    fn new_stream(
        &mut self,
        direction: StreamDirection,
        num_channels: usize,
        format: SampleFormat,
        frame_rate: u32,
        buffer_size: usize,
        _effects: &[StreamEffect],
        client_shm: &SysSharedMemory,
        _buffer_offsets: [u64; 2],
    ) -> GenericResult<Box<dyn ShmStream>> {
        self.vios_client.ensure_bg_thread_started()?;
        let virtio_dir = match direction {
            StreamDirection::Playback => VIRTIO_SND_D_OUTPUT,
            StreamDirection::Capture => VIRTIO_SND_D_INPUT,
        };
        let frame_size = num_channels * format.sample_bytes();
        let period_bytes = (frame_size * buffer_size) as u32;
        let stream_id = self
            .vios_client
            .get_unused_stream_id(virtio_dir)
            .ok_or(Box::new(Error::NoStreamsAvailable))?;
        // Create the stream object before any errors can be returned to guarantee the stream will
        // be released in all cases
        let stream_box = VioSndShmStream::new(
            buffer_size,
            num_channels,
            format,
            frame_rate,
            stream_id,
            direction,
            self.vios_client.clone(),
            client_shm,
        );
        self.vios_client.prepare_stream(stream_id)?;
        let params = VioSStreamParams {
            buffer_bytes: 2 * period_bytes,
            period_bytes,
            features: 0u32,
            channels: num_channels as u8,
            format: from_sample_format(format),
            rate: virtio_frame_rate(frame_rate)?,
        };
        self.vios_client.set_stream_parameters(stream_id, params)?;
        self.vios_client.start_stream(stream_id)?;
        stream_box
    }

    /// Get a list of file descriptors used by the implementation.
    ///
    /// Returns any open file descriptors needed by the implementation.
    /// This list helps users of the ShmStreamSource enter Linux jails without
    /// closing needed file descriptors.
    fn keep_fds(&self) -> Vec<RawFd> {
        self.vios_client.keep_fds()
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
    vios_client: Arc<VioSClient>,
    client_shm: SharedMemory,
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
        vios_client: Arc<VioSClient>,
        client_shm: &SysSharedMemory,
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
        let client_shm_clone =
            SharedMemory::from_file(file).map_err(|e| Error::BaseMmapError(e))?;

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
                self.vios_client.inject_audio_data(
                    self.stream_id,
                    &mut self.client_shm,
                    offset,
                    frames * self.frame_size,
                )?;
            }
            StreamDirection::Capture => {
                self.vios_client.request_audio_data(
                    self.stream_id,
                    &mut self.client_shm,
                    offset,
                    frames * self.frame_size,
                )?;
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
        if let Err(e) = self
            .vios_client
            .stop_stream(stream_id)
            .and_then(|_| self.vios_client.release_stream(stream_id))
        {
            error!("Failed to stop and release stream {}: {}", stream_id, e);
        }
    }
}

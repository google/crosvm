// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::virtio::snd::constants::*;
use crate::virtio::snd::layout::*;

use base::{
    net::UnixSeqpacket, Error as BaseError, FromRawDescriptor, IntoRawDescriptor, MemoryMapping,
    MemoryMappingBuilder, MmapError, SafeDescriptor, ScmSocket, SharedMemory,
};
use data_model::{DataInit, VolatileMemory, VolatileMemoryError};

use std::fs::File;
use std::io::{Error as IOError, ErrorKind as IOErrorKind, Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;

use thiserror::Error as ThisError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Failed to connect to VioS server: {0:?}")]
    ServerConnectionError(IOError),
    #[error("Failed to communicate with VioS server: {0:?}")]
    ServerError(BaseError),
    #[error("Failed to communicate with VioS server: {0:?}")]
    ServerIOError(IOError),
    #[error("Failed to get size of tx shared memory: {0}")]
    FileSizeError(IOError),
    #[error("Error duplicating file descriptor: {0}")]
    DupError(BaseError),
    #[error("Error accessing VioS server's shared memory: {0}")]
    ServerMmapError(MmapError),
    #[error("Error accessing guest's shared memory: {0}")]
    GuestMmapError(MmapError),
    #[error("Error memory mapping client_shm: {0}")]
    BaseMmapError(BaseError),
    #[error("Error accessing volatile memory: {0}")]
    VolatileMemoryError(VolatileMemoryError),
    #[error("{0}")]
    ProtocolError(ProtocolErrorKind),
    #[error("No PCM streams available")]
    NoStreamsAvailable,
    #[error("No stream with id {0}")]
    InvalidStreamId(u32),
    #[error("Stream is unexpected state: {0:?}")]
    UnexpectedState(StreamState),
    #[error("Invalid operation for stream direction: {0}")]
    WrongDirection(u8),
    #[error("Insuficient space for the new buffer in the queue's buffer area")]
    OutOfSpace,
    #[error("Unsupported frame rate: {0}")]
    UnsupportedFrameRate(u32),
    #[error("Platform not supported")]
    PlatformNotSupported,
    #[error("Command failed with status {0}")]
    CommandFailed(u32),
}

#[derive(ThisError, Debug)]
pub enum ProtocolErrorKind {
    #[error("The server sent a config of the wrong size: {0}")]
    UnexpectedConfigSize(usize),
    #[error("Received {1} file descriptors from the server, expected {0}")]
    UnexpectedNumberOfFileDescriptors(usize, usize), // expected, received
    #[error("Server's version ({0}) doesn't match client's")]
    VersionMismatch(u32),
    #[error("Received a msg with an unexpected size: expected {0}, received {1}")]
    UnexpectedMessageSize(usize, usize), // expected, received
}

/// The client for the VioS backend
///
/// Uses a protocol equivalent to virtio-snd over a shared memory file and a unix socket for
/// notifications.
pub struct VioSClient {
    config: VioSConfig,
    streams: Vec<VioSStreamInfo>,
    control_socket: UnixSeqpacket,
    event_socket: UnixSeqpacket,
    tx: IoBufferQueue,
    rx: IoBufferQueue,
}

impl VioSClient {
    /// Create a new client given the path to the audio server's socket.
    pub fn try_new<P: AsRef<Path>>(server: P) -> Result<VioSClient> {
        let client_socket =
            UnixSeqpacket::connect(server).map_err(|e| Error::ServerConnectionError(e))?;
        let mut config: VioSConfig = Default::default();
        let mut fds: Vec<RawFd> = Vec::new();
        const NUM_FDS: usize = 5;
        fds.resize(NUM_FDS, 0 as RawFd);
        let (recv_size, fd_count) = client_socket
            .recv_with_fds(config.as_mut_slice(), &mut fds)
            .map_err(|e| Error::ServerError(e))?;

        // Resize the vector to the actual number of file descriptors received and wrap them in
        // SafeDescriptors to prevent leaks
        fds.resize(fd_count, -1 as RawFd);
        let mut safe_fds: Vec<SafeDescriptor> = fds
            .into_iter()
            .map(|fd| unsafe {
                // safe because the SafeDescriptor object completely assumes ownership of the fd.
                SafeDescriptor::from_raw_descriptor(fd)
            })
            .collect();

        if recv_size != std::mem::size_of::<VioSConfig>() {
            return Err(Error::ProtocolError(
                ProtocolErrorKind::UnexpectedConfigSize(recv_size),
            ));
        }

        if config.version != VIOS_VERSION {
            return Err(Error::ProtocolError(ProtocolErrorKind::VersionMismatch(
                config.version,
            )));
        }

        fn pop<T: FromRawFd>(
            safe_fds: &mut Vec<SafeDescriptor>,
            expected: usize,
            received: usize,
        ) -> Result<T> {
            unsafe {
                // Safe because we transfer ownership from the SafeDescriptor to T
                Ok(T::from_raw_fd(
                    safe_fds
                        .pop()
                        .ok_or(Error::ProtocolError(
                            ProtocolErrorKind::UnexpectedNumberOfFileDescriptors(
                                expected, received,
                            ),
                        ))?
                        .into_raw_descriptor(),
                ))
            }
        }

        let rx_shm_file = pop::<File>(&mut safe_fds, NUM_FDS, fd_count)?;
        let tx_shm_file = pop::<File>(&mut safe_fds, NUM_FDS, fd_count)?;
        let rx_socket = pop::<UnixSeqpacket>(&mut safe_fds, NUM_FDS, fd_count)?;
        let tx_socket = pop::<UnixSeqpacket>(&mut safe_fds, NUM_FDS, fd_count)?;
        let event_socket = pop::<UnixSeqpacket>(&mut safe_fds, NUM_FDS, fd_count)?;

        if !safe_fds.is_empty() {
            return Err(Error::ProtocolError(
                ProtocolErrorKind::UnexpectedNumberOfFileDescriptors(NUM_FDS, fd_count),
            ));
        }

        let control_socket = client_socket;

        let mut client = VioSClient {
            config,
            streams: Vec::new(),
            control_socket,
            event_socket,
            tx: IoBufferQueue::new(tx_socket, tx_shm_file)?,
            rx: IoBufferQueue::new(rx_socket, rx_shm_file)?,
        };
        client.request_and_cache_streams_info()?;

        Ok(client)
    }

    /// Get a description of the available sound streams.
    pub fn streams(&self) -> &Vec<VioSStreamInfo> {
        &self.streams
    }

    /// Gets an unused stream id of the specified direction. `direction` must be one of
    /// VIRTIO_SND_D_INPUT OR VIRTIO_SND_D_OUTPUT.
    pub fn get_unused_stream_id(&self, direction: u8) -> Option<u32> {
        self.streams
            .iter()
            .filter(|s| s.state == StreamState::Available && s.direction == direction as u8)
            .map(|s| s.id)
            .next()
    }

    /// Configures a stream with the given parameters.
    pub fn set_stream_parameters(
        &mut self,
        stream_id: u32,
        params: VioSStreamParams,
    ) -> Result<()> {
        self.validate_stream_id(stream_id, &[StreamState::Available, StreamState::Acquired])?;
        let raw_params: virtio_snd_pcm_set_params = (stream_id, params).into();
        seq_socket_send(&self.control_socket, raw_params)?;
        self.recv_cmd_status()?;
        self.streams[stream_id as usize].state = StreamState::Acquired;
        Ok(())
    }

    /// Send the PREPARE_STREAM command to the server.
    pub fn prepare_stream(&mut self, stream_id: u32) -> Result<()> {
        self.common_stream_op(
            stream_id,
            &[StreamState::Available, StreamState::Acquired],
            StreamState::Acquired,
            STREAM_PREPARE,
        )
    }

    /// Send the RELEASE_STREAM command to the server.
    pub fn release_stream(&mut self, stream_id: u32) -> Result<()> {
        self.common_stream_op(
            stream_id,
            &[StreamState::Acquired],
            StreamState::Available,
            STREAM_RELEASE,
        )
    }

    /// Send the START_STREAM command to the server.
    pub fn start_stream(&mut self, stream_id: u32) -> Result<()> {
        self.common_stream_op(
            stream_id,
            &[StreamState::Acquired],
            StreamState::Active,
            STREAM_START,
        )
    }

    /// Send the STOP_STREAM command to the server.
    pub fn stop_stream(&mut self, stream_id: u32) -> Result<()> {
        self.common_stream_op(
            stream_id,
            &[StreamState::Active],
            StreamState::Acquired,
            STREAM_STOP,
        )
    }

    /// Send audio frames to the server. The audio data is taken from a shared memory resource.
    pub fn inject_audio_data(
        &mut self,
        stream_id: u32,
        buffer: &mut SharedMemory,
        src_offset: usize,
        size: usize,
    ) -> Result<()> {
        self.validate_stream_id(stream_id, &[StreamState::Active])?;
        if self.streams[stream_id as usize].direction != VIRTIO_SND_D_OUTPUT {
            return Err(Error::WrongDirection(
                self.streams[stream_id as usize].direction,
            ));
        }
        let dst_offset = self.tx.push_buffer(buffer, src_offset, size)?;
        let msg = IoTransferMsg::new(stream_id, dst_offset, size);
        seq_socket_send(&self.tx.socket, msg)
    }

    /// Get a list of file descriptors used by the implementation.
    pub fn keep_fds(&self) -> Vec<RawFd> {
        vec![
            self.control_socket.as_raw_fd(),
            self.event_socket.as_raw_fd(),
            self.tx.socket.as_raw_fd(),
            self.rx.socket.as_raw_fd(),
            self.tx.file.as_raw_fd(),
            self.rx.file.as_raw_fd(),
        ]
    }

    fn validate_stream_id(&self, stream_id: u32, permitted_states: &[StreamState]) -> Result<()> {
        if stream_id >= self.streams.len() as u32 {
            return Err(Error::InvalidStreamId(stream_id));
        }
        if !permitted_states.contains(&self.streams[stream_id as usize].state) {
            return Err(Error::UnexpectedState(
                self.streams[stream_id as usize].state,
            ));
        }
        Ok(())
    }

    fn common_stream_op(
        &mut self,
        stream_id: u32,
        expected_states: &[StreamState],
        new_state: StreamState,
        op: u32,
    ) -> Result<()> {
        self.validate_stream_id(stream_id, expected_states)?;
        let msg = virtio_snd_pcm_hdr {
            hdr: virtio_snd_hdr { code: op.into() },
            stream_id: stream_id.into(),
        };
        seq_socket_send(&self.control_socket, msg)?;
        self.recv_cmd_status()?;
        self.streams[stream_id as usize].state = new_state;
        Ok(())
    }

    fn recv_cmd_status(&mut self) -> Result<()> {
        let mut status: virtio_snd_hdr = Default::default();
        self.control_socket
            .recv(status.as_mut_slice())
            .map_err(|e| Error::ServerIOError(e))?;
        if status.code.to_native() == VIRTIO_SND_S_OK {
            Ok(())
        } else {
            Err(Error::CommandFailed(status.code.to_native()))
        }
    }

    fn request_and_cache_streams_info(&mut self) -> Result<()> {
        let num_streams = self.config.streams as usize;
        let info_size = std::mem::size_of::<virtio_snd_pcm_info>();
        let req = virtio_snd_query_info {
            hdr: virtio_snd_hdr {
                code: STREAM_INFO.into(),
            },
            start_id: 0u32.into(),
            count: (num_streams as u32).into(),
            size: (std::mem::size_of::<virtio_snd_query_info>() as u32).into(),
        };
        seq_socket_send(&self.control_socket, req)?;
        self.recv_cmd_status()?;
        let info_vec = self
            .control_socket
            .recv_as_vec()
            .map_err(|e| Error::ServerIOError(e))?;
        if info_vec.len() != num_streams * info_size {
            return Err(Error::ProtocolError(
                ProtocolErrorKind::UnexpectedMessageSize(num_streams * info_size, info_vec.len()),
            ));
        }
        self.streams = info_vec
            .chunks(info_size)
            .enumerate()
            .map(|(id, info_buffer)| {
                // unwrap is safe because we checked the size of the vector above
                let virtio_stream_info = virtio_snd_pcm_info::from_slice(&info_buffer).unwrap();
                VioSStreamInfo::new(id as u32, &virtio_stream_info)
            })
            .collect();
        Ok(())
    }
}

struct IoBufferQueue {
    socket: UnixSeqpacket,
    file: File,
    mmap: MemoryMapping,
    size: usize,
    next: usize,
}

impl IoBufferQueue {
    fn new(socket: UnixSeqpacket, mut file: File) -> Result<IoBufferQueue> {
        let size = file
            .seek(SeekFrom::End(0))
            .map_err(|e| Error::FileSizeError(e))? as usize;

        let mmap = MemoryMappingBuilder::new(size)
            .from_descriptor(&file)
            .build()
            .map_err(|e| Error::ServerMmapError(e))?;

        Ok(IoBufferQueue {
            socket,
            file,
            mmap,
            size,
            next: 0,
        })
    }

    fn push_buffer(&mut self, src: &mut SharedMemory, offset: usize, size: usize) -> Result<usize> {
        if size > self.size {
            return Err(Error::OutOfSpace);
        }
        let shm_offset = if size > self.size - self.next {
            // Can't fit the new buffer at the end of the area, so put it at the beginning
            0
        } else {
            self.next
        };

        let (src_mmap, mmap_offset) = mmap_buffer(src, offset, size)?;
        let src_slice = src_mmap
            .get_slice(mmap_offset, size)
            .map_err(|e| Error::VolatileMemoryError(e))?;
        let dst_slice = self
            .mmap
            .get_slice(shm_offset, size)
            .map_err(|e| Error::VolatileMemoryError(e))?;
        src_slice.copy_to_volatile_slice(dst_slice);
        self.next = shm_offset + size;
        Ok(shm_offset)
    }
}

/// Description of a stream made available by the server.
pub struct VioSStreamInfo {
    pub id: u32,
    pub hda_fn_nid: u32,
    pub features: u32,
    pub formats: u64,
    pub rates: u64,
    pub direction: u8,
    pub channels_min: u8,
    pub channels_max: u8,
    state: StreamState,
}

impl VioSStreamInfo {
    fn new(id: u32, info: &virtio_snd_pcm_info) -> VioSStreamInfo {
        VioSStreamInfo {
            id,
            hda_fn_nid: info.hdr.hda_fn_nid.to_native(),
            features: info.features.to_native(),
            formats: info.formats.to_native(),
            rates: info.rates.to_native(),
            direction: info.direction,
            channels_min: info.channels_min,
            channels_max: info.channels_max,
            state: StreamState::Available,
        }
    }
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum StreamState {
    Available,
    Acquired,
    Active,
}

/// Groups the parameters used to configure a stream prior to using it.
pub struct VioSStreamParams {
    pub buffer_bytes: u32,
    pub period_bytes: u32,
    pub features: u32,
    pub channels: u8,
    pub format: u8,
    pub rate: u8,
}

impl Into<virtio_snd_pcm_set_params> for (u32, VioSStreamParams) {
    fn into(self) -> virtio_snd_pcm_set_params {
        virtio_snd_pcm_set_params {
            hdr: virtio_snd_pcm_hdr {
                hdr: virtio_snd_hdr {
                    code: STREAM_SET_PARAMS.into(),
                },
                stream_id: self.0.into(),
            },
            buffer_bytes: self.1.buffer_bytes.into(),
            period_bytes: self.1.period_bytes.into(),
            features: self.1.features.into(),
            channels: self.1.channels,
            format: self.1.format,
            rate: self.1.rate,
            padding: 0u8,
        }
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
        .from_descriptor(src)
        .build()
        .map_err(|e| Error::GuestMmapError(e))?;

    Ok((mmap, offset_from_mapping_start))
}

fn seq_socket_send<T: DataInit>(socket: &UnixSeqpacket, data: T) -> Result<()> {
    loop {
        let send_res = socket.send(data.as_slice());
        if let Err(e) = send_res {
            match e.kind() {
                // Retry if interrupted
                IOErrorKind::Interrupted => continue,
                _ => return Err(Error::ServerIOError(e)),
            }
        }
        // Success
        break;
    }
    Ok(())
}

const VIOS_VERSION: u32 = 1;

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct VioSConfig {
    version: u32,
    jacks: u32,
    streams: u32,
    chmaps: u32,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for VioSConfig {}

#[repr(C)]
#[derive(Copy, Clone)]
struct IoTransferMsg {
    io_xfer: virtio_snd_pcm_xfer,
    buffer_offset: u32,
    buffer_len: u32,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for IoTransferMsg {}

impl IoTransferMsg {
    fn new(stream_id: u32, buffer_offset: usize, buffer_len: usize) -> IoTransferMsg {
        IoTransferMsg {
            io_xfer: virtio_snd_pcm_xfer {
                stream_id: stream_id.into(),
            },
            buffer_offset: buffer_offset as u32,
            buffer_len: buffer_len as u32,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct IoStatusMsg {
    status: virtio_snd_pcm_status,
    buffer_offset: u32,
    consumed_len: u32,
}
// Safe because it only has data and has no implicit padding.
unsafe impl DataInit for IoStatusMsg {}

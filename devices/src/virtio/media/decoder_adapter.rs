// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! An adapter from the virtio-media protocol to the video devices originally used with
//! virtio-video.
//!
//! This allows to reuse already-existing crosvm virtio-video devices with
//! virtio-media.

use std::os::fd::BorrowedFd;
use std::sync::Arc;

use base::AsRawDescriptor;
use base::SharedMemory;
use base::WaitContext;
use sync::Mutex;
use virtio_media::devices::video_decoder::StreamParams;
use virtio_media::devices::video_decoder::VideoDecoderBackend;
use virtio_media::devices::video_decoder::VideoDecoderBackendEvent;
use virtio_media::devices::video_decoder::VideoDecoderBackendSession;
use virtio_media::devices::video_decoder::VideoDecoderBufferBacking;
use virtio_media::devices::video_decoder::VideoDecoderSession;
use virtio_media::ioctl::IoctlResult;
use virtio_media::v4l2r;
use virtio_media::v4l2r::bindings;
use virtio_media::v4l2r::ioctl::V4l2MplaneFormat;
use virtio_media::v4l2r::PixelFormat;
use virtio_media::v4l2r::QueueClass;
use virtio_media::v4l2r::QueueDirection;
use virtio_media::v4l2r::QueueType;

use crate::virtio::video::decoder::backend::DecoderEvent;
use crate::virtio::video::decoder::backend::DecoderSession;
use crate::virtio::video::decoder::capability::Capability;
use crate::virtio::video::decoder::DecoderBackend;
use crate::virtio::video::format::Format;
use crate::virtio::video::format::FramePlane;
use crate::virtio::video::format::PlaneFormat;
use crate::virtio::video::resource::GuestMemArea;
use crate::virtio::video::resource::GuestMemHandle;
use crate::virtio::video::resource::GuestResource;
use crate::virtio::video::resource::GuestResourceHandle;

/// Use 1 MB input buffers by default. This should probably be resolution-dependent.
const INPUT_BUFFER_SIZE: u32 = 1024 * 1024;

/// Returns the V4L2 `(bytesperline, sizeimage)` for the given `format` and `coded_size`.
fn buffer_sizes_for_format(format: Format, coded_size: (u32, u32)) -> (u32, u32) {
    match PlaneFormat::get_plane_layout(format, coded_size.0, coded_size.1) {
        None => (0, INPUT_BUFFER_SIZE),
        Some(layout) => (
            layout.first().map(|p| p.stride).unwrap_or(0),
            layout.iter().map(|p| p.plane_size).sum(),
        ),
    }
}

impl From<Format> for PixelFormat {
    fn from(format: Format) -> Self {
        PixelFormat::from_fourcc(match format {
            Format::NV12 => b"NV12",
            Format::YUV420 => b"YV12",
            Format::H264 => b"H264",
            Format::Hevc => b"HEVC",
            Format::VP8 => b"VP80",
            Format::VP9 => b"VP90",
        })
    }
}

impl TryFrom<PixelFormat> for Format {
    type Error = ();

    fn try_from(pixelformat: PixelFormat) -> Result<Self, Self::Error> {
        match &pixelformat.to_fourcc() {
            b"NV12" => Ok(Format::NV12),
            b"YV12" => Ok(Format::YUV420),
            b"H264" => Ok(Format::H264),
            b"HEVC" => Ok(Format::Hevc),
            b"VP80" => Ok(Format::VP8),
            b"VP90" => Ok(Format::VP9),
            _ => Err(()),
        }
    }
}

pub struct VirtioVideoAdapterBuffer {
    // Plane backing memory, for MMAP buffers only.
    shm: Vec<SharedMemory>,
    // Switched to `true` once the buffer's backing memory has been registered with
    // `use_output_buffer`.
    registered: bool,
}

impl VideoDecoderBufferBacking for VirtioVideoAdapterBuffer {
    fn new(queue: QueueType, index: u32, sizes: &[usize]) -> IoctlResult<Self> {
        Ok(Self {
            shm: sizes
                .iter()
                .enumerate()
                .map(|(plane, size)| {
                    SharedMemory::new(
                        format!("virtio_media {:?} {}-{}", queue.direction(), index, plane),
                        *size as u64,
                    )
                })
                .collect::<Result<_, base::Error>>()
                .map_err(|_| libc::ENOMEM)?,
            registered: false,
        })
    }

    fn fd_for_plane(&self, plane_idx: usize) -> Option<BorrowedFd> {
        self.shm.get(plane_idx).map(|shm|
            // SAFETY: the shm'd fd is valid and `BorrowedFd` ensures its use won't outlive us.
            unsafe { BorrowedFd::borrow_raw(shm.descriptor.as_raw_descriptor())})
    }
}

enum EosBuffer {
    /// No EOS buffer queued yet and no EOS pending.
    None,
    /// EOS buffer is available, and no EOS pending.
    Available(u32),
    /// EOS is pending but we have no buffer queued yet.
    Awaiting,
}

pub struct VirtioVideoAdapterSession<D: DecoderBackend> {
    /// Session ID.
    id: u32,

    /// The backend session can only be created once we know the input format.
    backend_session: Option<D::Session>,

    /// Proxy poller. We need this because this backend creates the actual session with a delay,
    /// but the device needs the session FD as soon as it is created.
    poller: WaitContext<u32>,

    /// Shared reference to the device backend. Required so we can create the session lazily.
    backend: Arc<Mutex<D>>,

    input_format: Format,
    output_format: Format,
    /// Coded size currently set for the CAPTURE buffers.
    coded_size: (u32, u32),
    /// Stream parameters, as obtained from the stream itself.
    stream_params: StreamParams,

    /// Whether the initial DRC event has been received. The backend will ignore CAPTURE buffers
    /// queued before that.
    initial_drc_received: bool,
    /// Whether the `set_output_parameters` of the backend needs to be called before a CAPTURE
    /// buffer is sent.
    need_set_output_params: bool,

    /// Indices of CAPTURE buffers that are queued but not send to the backend.
    pending_output_buffers: Vec<(u32, Option<GuestResource>)>,

    /// Index of the capture buffer we kept in order to signal EOS.
    eos_capture_buffer: EosBuffer,

    /// Number of output buffers that have been allocated, as reported by the decoder device.
    ///
    /// This is required to call `set_output_parameters` on the virtio-video session.
    num_output_buffers: usize,
}

impl<D: DecoderBackend> VirtioVideoAdapterSession<D> {
    /// Get the currently existing backend session if it exists, or create it using the current
    /// input format if it doesn't.
    fn get_or_create_session(&mut self) -> IoctlResult<&mut D::Session> {
        let backend_session = match &mut self.backend_session {
            Some(session) => session,
            b @ None => {
                let backend_session =
                    self.backend
                        .lock()
                        .new_session(self.input_format)
                        .map_err(|e| {
                            base::error!(
                                "{:#}",
                                anyhow::anyhow!("while creating backend session: {:#}", e)
                            );
                            libc::EIO
                        })?;
                self.poller
                    .add(backend_session.event_pipe(), self.id)
                    .map_err(|e| {
                        base::error!("failed to listen to events of session {}: {:#}", self.id, e);
                        libc::EIO
                    })?;
                b.get_or_insert(backend_session)
            }
        };

        Ok(backend_session)
    }

    fn try_send_pending_output_buffers(&mut self) -> IoctlResult<()> {
        // We cannot send output buffers until the initial DRC event is received.
        if !self.initial_drc_received {
            return Ok(());
        }

        let _ = self.get_or_create_session();
        // Will always succeed before `get_or_create_session` has been called. Ideally we would use
        // its result directly, but this borrows a mutable reference to `self` which would prevent
        // other borrows later in this method.
        let Some(backend_session) = &mut self.backend_session else {
            unreachable!()
        };

        // Leave early if we have no pending output buffers. This ensures we only set the
        // parameters right before the first buffer is queued.
        if self.pending_output_buffers.is_empty() {
            return Ok(());
        }

        // Set the output parameters if this is the first CAPTURE buffer we queue after a
        // resolution change event.
        if self.need_set_output_params {
            let output_format = self.output_format;

            backend_session
                .set_output_parameters(self.num_output_buffers, output_format)
                .map_err(|_| libc::EIO)?;
            self.need_set_output_params = false;
        }

        for (index, resource) in self.pending_output_buffers.drain(..) {
            match resource {
                Some(resource) => backend_session
                    .use_output_buffer(index as i32, resource)
                    .map_err(|_| libc::EIO)?,
                None => backend_session
                    .reuse_output_buffer(index as i32)
                    .map_err(|_| libc::EIO)?,
            }
        }

        Ok(())
    }
}

impl<D: DecoderBackend> VideoDecoderBackendSession for VirtioVideoAdapterSession<D> {
    type BufferStorage = VirtioVideoAdapterBuffer;

    fn current_format(&self, direction: QueueDirection) -> V4l2MplaneFormat {
        let format = match direction {
            QueueDirection::Output => self.input_format,
            QueueDirection::Capture => self.output_format,
        };
        let (bytesperline, sizeimage) = buffer_sizes_for_format(format, self.coded_size);

        let mut plane_fmt: [bindings::v4l2_plane_pix_format; bindings::VIDEO_MAX_PLANES as usize] =
            Default::default();
        plane_fmt[0] = bindings::v4l2_plane_pix_format {
            bytesperline,
            sizeimage,
            reserved: Default::default(),
        };

        let pix_mp = bindings::v4l2_pix_format_mplane {
            width: self.coded_size.0,
            height: self.coded_size.1,
            pixelformat: PixelFormat::from(format).to_u32(),
            field: bindings::v4l2_field_V4L2_FIELD_NONE,
            plane_fmt,
            num_planes: 1,
            flags: 0,
            ..Default::default()
        };

        V4l2MplaneFormat::from((direction, pix_mp))
    }

    fn stream_params(&self) -> StreamParams {
        self.stream_params.clone()
    }

    fn drain(&mut self) -> IoctlResult<()> {
        if let Some(backend_session) = &mut self.backend_session {
            backend_session.flush().map_err(|_| libc::EIO)
        } else {
            Ok(())
        }
    }

    fn clear_output_buffers(&mut self) -> IoctlResult<()> {
        self.pending_output_buffers.clear();
        self.eos_capture_buffer = EosBuffer::None;
        if let Some(session) = &mut self.backend_session {
            session.clear_output_buffers().map_err(|_| libc::EIO)
        } else {
            Ok(())
        }
    }

    fn next_event(&mut self) -> Option<VideoDecoderBackendEvent> {
        if let Some(backend_session) = &mut self.backend_session {
            let event = backend_session.read_event().unwrap();

            match event {
                DecoderEvent::NotifyEndOfBitstreamBuffer(id) => {
                    Some(VideoDecoderBackendEvent::InputBufferDone {
                        buffer_id: id,
                        error: 0,
                    })
                }
                DecoderEvent::ProvidePictureBuffers {
                    min_num_buffers,
                    width,
                    height,
                    visible_rect,
                } => {
                    self.stream_params = StreamParams {
                        // Add one extra buffer to keep one on the side in order to signal EOS.
                        min_output_buffers: min_num_buffers + 1,
                        coded_size: (width as u32, height as u32),
                        visible_rect: v4l2r::Rect {
                            left: visible_rect.left,
                            top: visible_rect.top,
                            width: visible_rect.right.saturating_sub(visible_rect.left) as u32,
                            height: visible_rect.bottom.saturating_sub(visible_rect.top) as u32,
                        },
                    };
                    self.coded_size = self.stream_params.coded_size;
                    self.need_set_output_params = true;
                    self.initial_drc_received = true;

                    // We can queue pending picture buffers now.
                    if self.try_send_pending_output_buffers().is_err() {
                        base::error!(
                            "failed to send pending output buffers after resolution change event"
                        );
                    }

                    Some(VideoDecoderBackendEvent::StreamFormatChanged)
                }
                DecoderEvent::PictureReady {
                    picture_buffer_id,
                    timestamp,
                    ..
                } => {
                    let timestamp = bindings::timeval {
                        tv_sec: (timestamp / 1_000_000) as i64,
                        tv_usec: (timestamp % 1_000_000) as i64,
                    };
                    let bytes_used = buffer_sizes_for_format(self.output_format, self.coded_size).1;

                    Some(VideoDecoderBackendEvent::FrameCompleted {
                        buffer_id: picture_buffer_id as u32,
                        timestamp,
                        bytes_used: vec![bytes_used],
                        is_last: false,
                    })
                }
                DecoderEvent::FlushCompleted(res) => {
                    if let Err(err) = res {
                        base::error!("flush command failed: {:#}", err);
                    }

                    // Regardless of the result, the flush has completed.
                    // Use the buffer we kept aside for signaling EOS, or wait until the next
                    // buffer is queued so we can use it for that purpose.
                    match self.eos_capture_buffer {
                        EosBuffer::Available(buffer_id) => {
                            Some(VideoDecoderBackendEvent::FrameCompleted {
                                buffer_id,
                                timestamp: Default::default(),
                                bytes_used: vec![0],
                                is_last: true,
                            })
                        }
                        _ => {
                            self.eos_capture_buffer = EosBuffer::Awaiting;
                            None
                        }
                    }
                }
                DecoderEvent::ResetCompleted(_) => todo!(),
                DecoderEvent::NotifyError(_) => todo!(),
            }
        } else {
            None
        }
    }

    fn buffers_allocated(&mut self, direction: QueueDirection, num_buffers: u32) {
        if matches!(direction, QueueDirection::Capture) {
            self.num_output_buffers = num_buffers as usize;
        }
    }

    fn poll_fd(&self) -> Option<BorrowedFd> {
        // SAFETY: safe because WaitContext has a valid FD and BorrowedFd ensures its use doesn't
        // outlive us.
        Some(unsafe { BorrowedFd::borrow_raw(self.poller.as_raw_descriptor()) })
    }

    fn decode(
        &mut self,
        input: &Self::BufferStorage,
        index: u32,
        timestamp: bindings::timeval,
        bytes_used: u32,
    ) -> IoctlResult<()> {
        let backend_session = self.get_or_create_session()?;
        let timestamp = timestamp.tv_sec as u64 * 1_000_000 + timestamp.tv_usec as u64;
        let resource = GuestResourceHandle::GuestPages(GuestMemHandle {
            desc: input.shm[0]
                .descriptor
                .try_clone()
                .map_err(|_| libc::ENOMEM)?,
            mem_areas: vec![GuestMemArea {
                offset: 0,
                length: input.shm[0].size as usize,
            }],
        });

        backend_session
            .decode(index, timestamp, resource, 0, bytes_used)
            .map_err(|_| libc::EIO)
    }

    fn use_as_output(&mut self, index: u32, backing: &mut Self::BufferStorage) -> IoctlResult<()> {
        match self.eos_capture_buffer {
            EosBuffer::None => {
                self.eos_capture_buffer = EosBuffer::Available(index);
                Ok(())
            }
            EosBuffer::Awaiting => {
                // TODO: mmm how do we do that?
                // Answer: we don't! We just return a buffer event with the LAST flag set, and the
                // higher-level event handler takes care of sending eos!
                //
                // ... and how do we trigger the event for that buffer?
                //
                // self.send_eos(self, v4l2_buffer.index());
                Ok(())
            }
            EosBuffer::Available(_) => {
                let resource = if !backing.registered {
                    let resource = GuestResourceHandle::GuestPages(GuestMemHandle {
                        desc: backing.shm[0]
                            .descriptor
                            .try_clone()
                            .map_err(|_| libc::ENOMEM)?,
                        mem_areas: vec![GuestMemArea {
                            offset: 0,
                            length: backing.shm[0].size as usize,
                        }],
                    });

                    let plane_formats = PlaneFormat::get_plane_layout(
                        self.output_format,
                        self.coded_size.0,
                        self.coded_size.1,
                    )
                    .ok_or_else(|| {
                        base::error!("could not obtain plane layout for output buffer");
                        libc::EINVAL
                    })?;

                    let mut buffer_offset = 0;
                    let resource_handle = GuestResource {
                        handle: resource,
                        planes: plane_formats
                            .into_iter()
                            .map(|p| {
                                let plane_offset = buffer_offset;
                                buffer_offset += p.plane_size;

                                FramePlane {
                                    offset: plane_offset as usize,
                                    stride: p.stride as usize,
                                    size: p.plane_size as usize,
                                }
                            })
                            .collect(),
                        width: self.coded_size.0,
                        height: self.coded_size.1,
                        format: self.output_format,
                        guest_cpu_mappable: false,
                    };

                    backing.registered = true;

                    Some(resource_handle)
                } else {
                    None
                };

                self.pending_output_buffers.push((index, resource));

                self.try_send_pending_output_buffers()
            }
        }
    }
}

pub struct VirtioVideoAdapter<D: DecoderBackend> {
    backend: Arc<Mutex<D>>,
    capability: Capability,
}

impl<D: DecoderBackend> VirtioVideoAdapter<D> {
    pub fn new(backend: D) -> Self {
        let capability = backend.get_capabilities();
        Self {
            backend: Arc::new(Mutex::new(backend)),
            capability,
        }
    }
}

impl<D: DecoderBackend> VideoDecoderBackend for VirtioVideoAdapter<D> {
    type Session = VirtioVideoAdapterSession<D>;

    fn new_session(&mut self, id: u32) -> IoctlResult<Self::Session> {
        let first_input_format = self
            .capability
            .input_formats()
            .first()
            .ok_or(libc::ENODEV)?;
        let first_output_format = self
            .capability
            .output_formats()
            .first()
            .ok_or(libc::ENODEV)?;

        let coded_size = first_input_format
            .frame_formats
            .first()
            .map(|f| (f.width.min, f.height.min))
            .unwrap_or((0, 0));

        Ok(VirtioVideoAdapterSession {
            id,
            backend_session: None,
            poller: WaitContext::new().map_err(|_| libc::EIO)?,
            backend: Arc::clone(&self.backend),
            input_format: first_input_format.format,
            coded_size,
            output_format: first_output_format.format,
            stream_params: StreamParams {
                min_output_buffers: 1,
                coded_size,
                visible_rect: v4l2r::Rect {
                    left: 0,
                    top: 0,
                    width: coded_size.0,
                    height: coded_size.1,
                },
            },
            initial_drc_received: false,
            need_set_output_params: false,
            pending_output_buffers: Default::default(),
            num_output_buffers: 0,
            eos_capture_buffer: EosBuffer::None,
        })
    }

    fn close_session(&mut self, _session: Self::Session) {}

    fn enum_formats(
        &self,
        _session: &VideoDecoderSession<Self::Session>,
        direction: QueueDirection,
        index: u32,
    ) -> Option<bindings::v4l2_fmtdesc> {
        let formats = match direction {
            QueueDirection::Output => self.capability.input_formats(),
            QueueDirection::Capture => self.capability.output_formats(),
        };
        let fmt = formats.get(index as usize)?;

        Some(bindings::v4l2_fmtdesc {
            index,
            type_: QueueType::from_dir_and_class(direction, QueueClass::VideoMplane) as u32,
            pixelformat: PixelFormat::from(fmt.format).to_u32(),
            ..Default::default()
        })
    }

    fn frame_sizes(&self, pixel_format: u32) -> Option<bindings::v4l2_frmsize_stepwise> {
        let format = Format::try_from(PixelFormat::from_u32(pixel_format)).ok()?;
        let frame_sizes = self
            .capability
            .input_formats()
            .iter()
            .chain(self.capability.output_formats().iter())
            .find(|f| f.format == format)
            .and_then(|f| f.frame_formats.first())?;

        Some(bindings::v4l2_frmsize_stepwise {
            min_width: frame_sizes.width.min,
            max_width: frame_sizes.width.max,
            step_width: frame_sizes.width.step,
            min_height: frame_sizes.height.min,
            max_height: frame_sizes.height.max,
            step_height: frame_sizes.height.step,
        })
    }

    fn adjust_format(
        &self,
        session: &Self::Session,
        direction: QueueDirection,
        format: V4l2MplaneFormat,
    ) -> V4l2MplaneFormat {
        let pix_mp: &bindings::v4l2_pix_format_mplane = format.as_ref();

        let available_formats = match direction {
            QueueDirection::Output => self.capability.input_formats(),
            QueueDirection::Capture => self.capability.output_formats(),
        };

        let pixel_format = Format::try_from(PixelFormat::from_u32(pix_mp.pixelformat)).ok();

        // If the received pixel format is valid, find the format in our capabilities that matches,
        // otherwise fall back to the first format.
        let Some(matching_format) = pixel_format
            .and_then(|format| available_formats.iter().find(|f| f.format == format))
            .or_else(|| available_formats.first())
        else {
            // There are no formats defined at all for the device, so return a bogus one like a
            // V4L2 device would do.
            return V4l2MplaneFormat::from((direction, Default::default()));
        };

        // Now check that the requested resolution is within the supported range, or fallback to
        // an arbitrary one.
        let (mut width, mut height) = matching_format
            .frame_formats
            .iter()
            .find(|format| {
                let width = pix_mp.width;
                let height = pix_mp.height;
                (format.width.min..format.width.max).contains(&width)
                    && (format.height.min..format.height.max).contains(&height)
            })
            .map(|_| (pix_mp.width, pix_mp.height))
            .unwrap_or_else(|| {
                matching_format
                    .frame_formats
                    .first()
                    .map(|format| {
                        (
                            std::cmp::min(format.width.max, pix_mp.width),
                            (std::cmp::min(format.height.max, pix_mp.height)),
                        )
                    })
                    .unwrap_or((0, 0))
            });

        // CAPTURE resolution cannot be lower than OUTPUT one.
        if direction == QueueDirection::Capture {
            width = std::cmp::max(width, session.coded_size.0);
            height = std::cmp::max(height, session.coded_size.1);
        }

        // We only support one plane per buffer for now.
        let num_planes = 1;
        let (bytesperline, sizeimage) =
            buffer_sizes_for_format(matching_format.format, (width, height));
        let mut plane_fmt: [bindings::v4l2_plane_pix_format; 8] = Default::default();
        plane_fmt[0] = bindings::v4l2_plane_pix_format {
            bytesperline,
            sizeimage,
            reserved: Default::default(),
        };

        V4l2MplaneFormat::from((
            direction,
            bindings::v4l2_pix_format_mplane {
                width,
                height,
                pixelformat: PixelFormat::from(matching_format.format).to_u32(),
                field: bindings::v4l2_field_V4L2_FIELD_NONE,
                plane_fmt,
                num_planes,
                flags: 0,
                ..Default::default()
            },
        ))
    }

    fn apply_format(
        &self,
        session: &mut Self::Session,
        direction: QueueDirection,
        format: &V4l2MplaneFormat,
    ) {
        match direction {
            QueueDirection::Output => {
                session.input_format =
                    Format::try_from(format.pixelformat()).unwrap_or_else(|_| {
                        self.capability
                            .input_formats()
                            .first()
                            .map(|f| f.format)
                            .unwrap_or(Format::H264)
                    });
                let coded_size = format.size();
                // Setting the resolution manually affects the stream parameters.
                if coded_size != (0, 0) {
                    let coded_size = format.size();
                    session.coded_size = coded_size;
                }
            }
            QueueDirection::Capture => {
                session.output_format =
                    Format::try_from(format.pixelformat()).unwrap_or_else(|_| {
                        self.capability
                            .output_formats()
                            .first()
                            .map(|f| f.format)
                            .unwrap_or(Format::NV12)
                    });
            }
        }
    }
}

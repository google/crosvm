// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implementation of the the `Encoder` struct, which is responsible for translation between the
//! virtio protocols and LibVDA APIs.

pub mod backend;

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use backend::*;
use base::debug;
use base::error;
use base::info;
use base::warn;
use base::Tube;
use base::WaitContext;
use vm_memory::GuestMemory;

use crate::virtio::video::async_cmd_desc_map::AsyncCmdDescMap;
use crate::virtio::video::command::QueueType;
use crate::virtio::video::command::VideoCmd;
use crate::virtio::video::control::*;
use crate::virtio::video::device::AsyncCmdResponse;
use crate::virtio::video::device::AsyncCmdTag;
use crate::virtio::video::device::Device;
use crate::virtio::video::device::Token;
use crate::virtio::video::device::VideoCmdResponseType;
use crate::virtio::video::device::VideoEvtResponseType;
use crate::virtio::video::error::VideoError;
use crate::virtio::video::error::VideoResult;
use crate::virtio::video::event::EvtType;
use crate::virtio::video::event::VideoEvt;
use crate::virtio::video::format::find_closest_resolution;
use crate::virtio::video::format::Bitrate;
use crate::virtio::video::format::BitrateMode;
use crate::virtio::video::format::Format;
use crate::virtio::video::format::FormatDesc;
use crate::virtio::video::format::Level;
use crate::virtio::video::format::PlaneFormat;
use crate::virtio::video::format::Profile;
use crate::virtio::video::params::Params;
use crate::virtio::video::protocol;
use crate::virtio::video::resource::*;
use crate::virtio::video::response::CmdResponse;
use crate::virtio::video::EosBufferManager;

pub type InputBufferId = u32;
pub type OutputBufferId = u32;

#[derive(Debug)]
struct QueuedInputResourceParams {
    timestamp: u64,
    in_queue: bool,
}

struct InputResource {
    resource: GuestResource,
    queue_params: Option<QueuedInputResourceParams>,
}

#[derive(Debug)]
struct QueuedOutputResourceParams {
    in_queue: bool,
}

struct OutputResource {
    resource: GuestResource,
    offset: u32,
    queue_params: Option<QueuedOutputResourceParams>,
}

#[derive(Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
enum PendingCommand {
    // TODO(b/193202566): remove this is_ext parameter throughout the code along with
    // support for the old GET_PARAMS and SET_PARAMS commands.
    GetSrcParams { is_ext: bool },
    GetDstParams { is_ext: bool },
    Drain,
    SrcQueueClear,
    DstQueueClear,
}

struct Stream<T: EncoderSession> {
    id: u32,
    src_params: Params,
    dst_params: Params,
    dst_bitrate: Bitrate,
    dst_profile: Profile,
    dst_h264_level: Option<Level>,
    force_keyframe: bool,

    encoder_session: Option<T>,
    received_input_buffers_event: bool,

    src_resources: BTreeMap<u32, InputResource>,
    encoder_input_buffer_ids: BTreeMap<InputBufferId, u32>,

    dst_resources: BTreeMap<u32, OutputResource>,
    encoder_output_buffer_ids: BTreeMap<OutputBufferId, u32>,

    pending_commands: BTreeSet<PendingCommand>,
    eos_manager: EosBufferManager,
}

impl<T: EncoderSession> Stream<T> {
    fn new<E: Encoder<Session = T>>(
        id: u32,
        src_resource_type: ResourceType,
        dst_resource_type: ResourceType,
        desired_format: Format,
        encoder: &EncoderDevice<E>,
    ) -> VideoResult<Self> {
        const MIN_BUFFERS: u32 = 1;
        const MAX_BUFFERS: u32 = 342;
        const DEFAULT_WIDTH: u32 = 640;
        const DEFAULT_HEIGHT: u32 = 480;
        const DEFAULT_BITRATE_TARGET: u32 = 6000;
        const DEFAULT_BITRATE_PEAK: u32 = DEFAULT_BITRATE_TARGET * 2;
        const DEFAULT_BITRATE: Bitrate = Bitrate::Vbr {
            target: DEFAULT_BITRATE_TARGET,
            peak: DEFAULT_BITRATE_PEAK,
        };
        const DEFAULT_BUFFER_SIZE: u32 = 2097152; // 2MB; chosen empirically for 1080p video
        const DEFAULT_FPS: u32 = 30;

        let mut src_params = Params {
            frame_rate: DEFAULT_FPS,
            min_buffers: MIN_BUFFERS,
            max_buffers: MAX_BUFFERS,
            resource_type: src_resource_type,
            ..Default::default()
        };

        let cros_capabilities = &encoder.cros_capabilities;

        cros_capabilities
            .populate_src_params(
                &mut src_params,
                Format::NV12,
                DEFAULT_WIDTH,
                DEFAULT_HEIGHT,
                0,
            )
            .map_err(|_| VideoError::InvalidArgument)?;

        let mut dst_params = Params {
            resource_type: dst_resource_type,
            frame_rate: DEFAULT_FPS,
            frame_width: DEFAULT_WIDTH,
            frame_height: DEFAULT_HEIGHT,
            ..Default::default()
        };

        // In order to support requesting encoder params change, we must know the default frame
        // rate, because VEA's request_encoding_params_change requires both framerate and
        // bitrate to be specified.
        cros_capabilities
            .populate_dst_params(&mut dst_params, desired_format, DEFAULT_BUFFER_SIZE)
            .map_err(|_| VideoError::InvalidArgument)?;
        // `format` is an Option since for the decoder, it is not populated until decoding has
        // started. for encoder, format should always be populated.
        let dest_format = dst_params.format.ok_or(VideoError::InvalidArgument)?;

        let dst_profile = cros_capabilities
            .get_default_profile(&dest_format)
            .ok_or(VideoError::InvalidArgument)?;

        let dst_h264_level = if dest_format == Format::H264 {
            Some(Level::H264_1_0)
        } else {
            None
        };

        Ok(Self {
            id,
            src_params,
            dst_params,
            dst_bitrate: DEFAULT_BITRATE,
            dst_profile,
            dst_h264_level,
            force_keyframe: false,
            encoder_session: None,
            received_input_buffers_event: false,
            src_resources: Default::default(),
            encoder_input_buffer_ids: Default::default(),
            dst_resources: Default::default(),
            encoder_output_buffer_ids: Default::default(),
            pending_commands: Default::default(),
            eos_manager: EosBufferManager::new(id),
        })
    }

    fn has_encode_session(&self) -> bool {
        self.encoder_session.is_some()
    }

    fn set_encode_session<U: Encoder<Session = T>>(
        &mut self,
        encoder: &mut U,
        wait_ctx: &WaitContext<Token>,
    ) -> VideoResult<()> {
        if self.encoder_session.is_some() {
            error!(
                "stream {}: tried to add encode session when one already exists.",
                self.id
            );
            return Err(VideoError::InvalidOperation);
        }

        let new_session = encoder
            .start_session(SessionConfig {
                src_params: self.src_params.clone(),
                dst_params: self.dst_params.clone(),
                dst_profile: self.dst_profile,
                dst_bitrate: self.dst_bitrate,
                dst_h264_level: self.dst_h264_level,
                frame_rate: self.dst_params.frame_rate,
            })
            .map_err(|_| VideoError::InvalidOperation)?;

        let event_pipe = new_session.event_pipe();

        wait_ctx
            .add(event_pipe, Token::Event { id: self.id })
            .map_err(|e| {
                error!(
                    "stream {}: failed to add FD to poll context: {}",
                    self.id, e
                );
                VideoError::InvalidOperation
            })?;
        self.encoder_session.replace(new_session);
        self.received_input_buffers_event = false;
        Ok(())
    }

    fn clear_encode_session(&mut self, wait_ctx: &WaitContext<Token>) -> VideoResult<()> {
        if let Some(session) = self.encoder_session.take() {
            let event_pipe = session.event_pipe();
            wait_ctx.delete(event_pipe).map_err(|e| {
                error!(
                    "stream: {}: failed to remove fd from poll context: {}",
                    self.id, e
                );
                VideoError::InvalidOperation
            })?;
        }
        Ok(())
    }

    fn require_input_buffers(
        &mut self,
        input_count: u32,
        input_frame_width: u32,
        input_frame_height: u32,
        output_buffer_size: u32,
    ) -> Option<Vec<VideoEvtResponseType>> {
        // TODO(alexlau): Does this always arrive after start_session,
        // but before the first encode call?
        // TODO(alexlau): set plane info from input_frame_width and input_frame_height
        self.src_params.min_buffers = input_count;
        self.src_params.max_buffers = 32;
        self.src_params.frame_width = input_frame_width;
        self.src_params.frame_height = input_frame_height;
        self.dst_params.plane_formats[0].plane_size = output_buffer_size;
        self.received_input_buffers_event = true;

        let mut responses = vec![];

        // Respond to any GetParams commands that were waiting.
        let pending_get_src_params = if self
            .pending_commands
            .remove(&PendingCommand::GetSrcParams { is_ext: false })
        {
            Some(false)
        } else if self
            .pending_commands
            .remove(&PendingCommand::GetSrcParams { is_ext: true })
        {
            Some(true)
        } else {
            None
        };
        if let Some(is_ext) = pending_get_src_params {
            responses.push(VideoEvtResponseType::AsyncCmd(
                AsyncCmdResponse::from_response(
                    AsyncCmdTag::GetParams {
                        stream_id: self.id,
                        queue_type: QueueType::Input,
                    },
                    CmdResponse::GetParams {
                        queue_type: QueueType::Input,
                        params: self.src_params.clone(),
                        is_ext,
                    },
                ),
            ));
        }
        let pending_get_dst_params = if self
            .pending_commands
            .remove(&PendingCommand::GetDstParams { is_ext: false })
        {
            Some(false)
        } else if self
            .pending_commands
            .remove(&PendingCommand::GetDstParams { is_ext: true })
        {
            Some(true)
        } else {
            None
        };
        if let Some(is_ext) = pending_get_dst_params {
            responses.push(VideoEvtResponseType::AsyncCmd(
                AsyncCmdResponse::from_response(
                    AsyncCmdTag::GetParams {
                        stream_id: self.id,
                        queue_type: QueueType::Output,
                    },
                    CmdResponse::GetParams {
                        queue_type: QueueType::Output,
                        params: self.dst_params.clone(),
                        is_ext,
                    },
                ),
            ));
        }

        if !responses.is_empty() {
            Some(responses)
        } else {
            None
        }
    }

    fn processed_input_buffer(
        &mut self,
        input_buffer_id: InputBufferId,
    ) -> Option<Vec<VideoEvtResponseType>> {
        let resource_id = *match self.encoder_input_buffer_ids.get(&input_buffer_id) {
            Some(id) => id,
            None => {
                warn!("Received processed input buffer event for input buffer id {}, but missing resource, ResourceDestroyAll?", input_buffer_id);
                return None;
            }
        };

        let resource = match self.src_resources.get_mut(&resource_id) {
            Some(r) => r,
            None => {
                error!(
                    "Received processed input buffer event but missing resource with id {}",
                    resource_id
                );
                return None;
            }
        };

        let queue_params = match resource.queue_params.take() {
            Some(p) => p,
            None => {
                error!(
                    "Received processed input buffer event but resource with id {} was not queued.",
                    resource_id
                );
                return None;
            }
        };

        if !queue_params.in_queue {
            // A QueueClear command occurred after this buffer was queued.
            return None;
        }

        let tag = AsyncCmdTag::Queue {
            stream_id: self.id,
            queue_type: QueueType::Input,
            resource_id,
        };

        let resp = CmdResponse::ResourceQueue {
            timestamp: queue_params.timestamp,
            flags: 0,
            size: 0,
        };

        Some(vec![VideoEvtResponseType::AsyncCmd(
            AsyncCmdResponse::from_response(tag, resp),
        )])
    }

    fn processed_output_buffer(
        &mut self,
        output_buffer_id: OutputBufferId,
        bytesused: u32,
        keyframe: bool,
        timestamp: u64,
    ) -> Option<Vec<VideoEvtResponseType>> {
        let resource_id = *match self.encoder_output_buffer_ids.get(&output_buffer_id) {
            Some(id) => id,
            None => {
                warn!("Received processed output buffer event for output buffer id {}, but missing resource, ResourceDestroyAll?", output_buffer_id);
                return None;
            }
        };

        let resource = match self.dst_resources.get_mut(&resource_id) {
            Some(r) => r,
            None => {
                error!(
                    "Received processed output buffer event but missing resource with id {}",
                    resource_id
                );
                return None;
            }
        };

        let queue_params = match resource.queue_params.take() {
            Some(p) => p,
            None => {
                error!("Received processed output buffer event but resource with id {} was not queued.", resource_id);
                return None;
            }
        };

        if !queue_params.in_queue {
            // A QueueClear command occurred after this buffer was queued.
            return None;
        }

        let tag = AsyncCmdTag::Queue {
            stream_id: self.id,
            queue_type: QueueType::Output,
            resource_id,
        };

        let resp = CmdResponse::ResourceQueue {
            timestamp,
            // At the moment, a buffer is saved in `eos_notification_buffer`, and
            // the EOS flag is populated and returned after a flush() command.
            // TODO(b/149725148): Populate flags once libvda supports it.
            flags: if keyframe {
                protocol::VIRTIO_VIDEO_BUFFER_FLAG_IFRAME
            } else {
                0
            },
            size: bytesused,
        };

        Some(vec![VideoEvtResponseType::AsyncCmd(
            AsyncCmdResponse::from_response(tag, resp),
        )])
    }

    fn flush_response(&mut self, flush_done: bool) -> Option<Vec<VideoEvtResponseType>> {
        let command_response = if flush_done {
            CmdResponse::NoData
        } else {
            error!("Flush could not be completed for stream {}", self.id);
            VideoError::InvalidOperation.into()
        };

        let mut async_responses = vec![];

        // First gather the responses for all completed commands.
        if self.pending_commands.remove(&PendingCommand::Drain) {
            async_responses.push(VideoEvtResponseType::AsyncCmd(
                AsyncCmdResponse::from_response(
                    AsyncCmdTag::Drain { stream_id: self.id },
                    command_response.clone(),
                ),
            ));
        }

        if self.pending_commands.remove(&PendingCommand::SrcQueueClear) {
            async_responses.push(VideoEvtResponseType::AsyncCmd(
                AsyncCmdResponse::from_response(
                    AsyncCmdTag::Clear {
                        stream_id: self.id,
                        queue_type: QueueType::Input,
                    },
                    command_response.clone(),
                ),
            ));
        }

        if self.pending_commands.remove(&PendingCommand::DstQueueClear) {
            async_responses.push(VideoEvtResponseType::AsyncCmd(
                AsyncCmdResponse::from_response(
                    AsyncCmdTag::Clear {
                        stream_id: self.id,
                        queue_type: QueueType::Output,
                    },
                    command_response,
                ),
            ));
        }

        // Then add the EOS buffer to the responses if it is available.
        self.eos_manager.try_complete_eos(async_responses)
    }

    #[allow(clippy::unnecessary_wraps)]
    fn notify_error(&self, error: VideoError) -> Option<Vec<VideoEvtResponseType>> {
        error!(
            "Received encoder error event for stream {}: {}",
            self.id, error
        );
        Some(vec![VideoEvtResponseType::Event(VideoEvt {
            typ: EvtType::Error,
            stream_id: self.id,
        })])
    }
}

pub struct EncoderDevice<T: Encoder> {
    cros_capabilities: EncoderCapabilities,
    encoder: T,
    streams: BTreeMap<u32, Stream<T::Session>>,
    resource_bridge: Tube,
    mem: GuestMemory,
}

impl<T: Encoder> EncoderDevice<T> {
    /// Build a new encoder using the provided `backend`.
    pub fn new(backend: T, resource_bridge: Tube, mem: GuestMemory) -> VideoResult<Self> {
        Ok(Self {
            cros_capabilities: backend.query_capabilities()?,
            encoder: backend,
            streams: Default::default(),
            resource_bridge,
            mem,
        })
    }

    #[allow(clippy::unnecessary_wraps)]
    fn query_capabilities(&self, queue_type: QueueType) -> VideoResult<VideoCmdResponseType> {
        let descs = match queue_type {
            QueueType::Input => self.cros_capabilities.input_format_descs.clone(),
            QueueType::Output => self.cros_capabilities.output_format_descs.clone(),
        };
        Ok(VideoCmdResponseType::Sync(CmdResponse::QueryCapability(
            descs,
        )))
    }

    fn stream_create(
        &mut self,
        stream_id: u32,
        desired_format: Format,
        src_resource_type: ResourceType,
        dst_resource_type: ResourceType,
    ) -> VideoResult<VideoCmdResponseType> {
        if self.streams.contains_key(&stream_id) {
            return Err(VideoError::InvalidStreamId(stream_id));
        }
        let new_stream = Stream::new(
            stream_id,
            src_resource_type,
            dst_resource_type,
            desired_format,
            self,
        )?;

        self.streams.insert(stream_id, new_stream);
        Ok(VideoCmdResponseType::Sync(CmdResponse::NoData))
    }

    fn stream_destroy(&mut self, stream_id: u32) -> VideoResult<VideoCmdResponseType> {
        let mut stream = self
            .streams
            .remove(&stream_id)
            .ok_or(VideoError::InvalidStreamId(stream_id))?;
        // TODO(alexlau): Handle resources that have been queued.
        if let Some(session) = stream.encoder_session.take() {
            if let Err(e) = self.encoder.stop_session(session) {
                error!("Failed to stop encode session {}: {}", stream_id, e);
            }
        }
        Ok(VideoCmdResponseType::Sync(CmdResponse::NoData))
    }

    fn stream_drain(&mut self, stream_id: u32) -> VideoResult<VideoCmdResponseType> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(VideoError::InvalidStreamId(stream_id))?;
        match stream.encoder_session {
            Some(ref mut session) => {
                if stream.pending_commands.contains(&PendingCommand::Drain) {
                    error!("A pending Drain command already exists.");
                    return Err(VideoError::InvalidOperation);
                }
                stream.pending_commands.insert(PendingCommand::Drain);

                if !stream
                    .pending_commands
                    .contains(&PendingCommand::SrcQueueClear)
                    && !stream
                        .pending_commands
                        .contains(&PendingCommand::DstQueueClear)
                {
                    // If a source or dest QueueClear is underway, a flush has
                    // already been sent.
                    if let Err(e) = session.flush() {
                        error!("Flush failed for stream id {}: {}", stream_id, e);
                    }
                }
                Ok(VideoCmdResponseType::Async(AsyncCmdTag::Drain {
                    stream_id,
                }))
            }
            None => {
                // Return an OK response since nothing has been queued yet.
                Ok(VideoCmdResponseType::Sync(CmdResponse::NoData))
            }
        }
    }

    fn resource_create(
        &mut self,
        wait_ctx: &WaitContext<Token>,
        stream_id: u32,
        queue_type: QueueType,
        resource_id: u32,
        plane_offsets: Vec<u32>,
        plane_entries: Vec<Vec<UnresolvedResourceEntry>>,
    ) -> VideoResult<VideoCmdResponseType> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(VideoError::InvalidStreamId(stream_id))?;

        if !stream.has_encode_session() {
            // No encode session would have been created upon the first
            // QBUF if there was no previous S_FMT call.
            stream.set_encode_session(&mut self.encoder, wait_ctx)?;
        }

        let num_planes = plane_offsets.len();

        // We only support single-buffer resources for now.
        let entries = if plane_entries.len() != 1 {
            return Err(VideoError::InvalidArgument);
        } else {
            // unwrap() is safe because we just tested that `plane_entries` had exactly one element.
            plane_entries.get(0).unwrap()
        };

        match queue_type {
            QueueType::Input => {
                // We currently only support single-buffer formats, but some clients may mistake
                // color planes with memory planes and submit several planes to us. This doesn't
                // matter as we will only consider the first one.
                if num_planes < 1 {
                    return Err(VideoError::InvalidParameter);
                }

                if stream.src_resources.contains_key(&resource_id) {
                    debug!("Replacing source resource with id {}", resource_id);
                }

                let resource = match stream.src_params.resource_type {
                    ResourceType::VirtioObject => {
                        // Virtio object resources only have one entry.
                        if entries.len() != 1 {
                            return Err(VideoError::InvalidArgument);
                        }
                        GuestResource::from_virtio_object_entry(
                            // Safe because we confirmed the correct type for the resource.
                            // unwrap() is also safe here because we just tested above that `entries` had
                            // exactly one element.
                            unsafe { entries.get(0).unwrap().object },
                            &self.resource_bridge,
                            &stream.src_params,
                        )
                        .map_err(|_| VideoError::InvalidArgument)?
                    }
                    ResourceType::GuestPages => GuestResource::from_virtio_guest_mem_entry(
                        // Safe because we confirmed the correct type for the resource.
                        unsafe {
                            std::slice::from_raw_parts(
                                entries.as_ptr() as *const protocol::virtio_video_mem_entry,
                                entries.len(),
                            )
                        },
                        &self.mem,
                        &stream.src_params,
                    )
                    .map_err(|_| VideoError::InvalidArgument)?,
                };

                stream.src_resources.insert(
                    resource_id,
                    InputResource {
                        resource,
                        queue_params: None,
                    },
                );
            }
            QueueType::Output => {
                // Bitstream buffers always have only one plane.
                if num_planes != 1 {
                    return Err(VideoError::InvalidParameter);
                }

                if stream.dst_resources.contains_key(&resource_id) {
                    debug!("Replacing dest resource with id {}", resource_id);
                }

                let resource = match stream.dst_params.resource_type {
                    ResourceType::VirtioObject => {
                        // Virtio object resources only have one entry.
                        if entries.len() != 1 {
                            return Err(VideoError::InvalidArgument);
                        }
                        GuestResource::from_virtio_object_entry(
                            // Safe because we confirmed the correct type for the resource.
                            // unwrap() is also safe here because we just tested above that `entries` had
                            // exactly one element.
                            unsafe { entries.get(0).unwrap().object },
                            &self.resource_bridge,
                            &stream.dst_params,
                        )
                        .map_err(|_| VideoError::InvalidArgument)?
                    }
                    ResourceType::GuestPages => GuestResource::from_virtio_guest_mem_entry(
                        // Safe because we confirmed the correct type for the resource.
                        unsafe {
                            std::slice::from_raw_parts(
                                entries.as_ptr() as *const protocol::virtio_video_mem_entry,
                                entries.len(),
                            )
                        },
                        &self.mem,
                        &stream.dst_params,
                    )
                    .map_err(|_| VideoError::InvalidArgument)?,
                };

                let offset = plane_offsets[0];
                stream.dst_resources.insert(
                    resource_id,
                    OutputResource {
                        resource,
                        offset,
                        queue_params: None,
                    },
                );
            }
        }

        Ok(VideoCmdResponseType::Sync(CmdResponse::NoData))
    }

    fn resource_queue(
        &mut self,
        stream_id: u32,
        queue_type: QueueType,
        resource_id: u32,
        timestamp: u64,
        data_sizes: Vec<u32>,
    ) -> VideoResult<VideoCmdResponseType> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(VideoError::InvalidStreamId(stream_id))?;

        let encoder_session = match stream.encoder_session {
            Some(ref mut e) => e,
            None => {
                // The encoder session is created on the first ResourceCreate,
                // so it should exist here.
                error!("Encoder session did not exist at resource_queue.");
                return Err(VideoError::InvalidOperation);
            }
        };

        match queue_type {
            QueueType::Input => {
                // We currently only support single-buffer formats, but some clients may mistake
                // color planes with memory planes and submit several planes to us. This doesn't
                // matter as we will only consider the first one.
                if data_sizes.is_empty() {
                    return Err(VideoError::InvalidParameter);
                }

                let src_resource = stream.src_resources.get_mut(&resource_id).ok_or(
                    VideoError::InvalidResourceId {
                        stream_id,
                        resource_id,
                    },
                )?;

                let force_keyframe = std::mem::replace(&mut stream.force_keyframe, false);

                match encoder_session.encode(
                    src_resource
                        .resource
                        .try_clone()
                        .map_err(|_| VideoError::InvalidArgument)?,
                    timestamp,
                    force_keyframe,
                ) {
                    Ok(input_buffer_id) => {
                        if let Some(last_resource_id) = stream
                            .encoder_input_buffer_ids
                            .insert(input_buffer_id, resource_id)
                        {
                            error!(
                                "encoder input id {} was already mapped to resource id {}",
                                input_buffer_id, last_resource_id
                            );
                            return Err(VideoError::InvalidOperation);
                        }
                        let queue_params = QueuedInputResourceParams {
                            timestamp,
                            in_queue: true,
                        };
                        if let Some(last_queue_params) =
                            src_resource.queue_params.replace(queue_params)
                        {
                            if last_queue_params.in_queue {
                                error!(
                                    "resource {} was already queued ({:?})",
                                    resource_id, last_queue_params
                                );
                                return Err(VideoError::InvalidOperation);
                            }
                        }
                    }
                    Err(e) => {
                        // TODO(alexlau): Return the actual error
                        error!("encode failed: {}", e);
                        return Err(VideoError::InvalidOperation);
                    }
                }
                Ok(VideoCmdResponseType::Async(AsyncCmdTag::Queue {
                    stream_id,
                    queue_type: QueueType::Input,
                    resource_id,
                }))
            }
            QueueType::Output => {
                // Bitstream buffers always have only one plane.
                if data_sizes.len() != 1 {
                    return Err(VideoError::InvalidParameter);
                }

                let dst_resource = stream.dst_resources.get_mut(&resource_id).ok_or(
                    VideoError::InvalidResourceId {
                        stream_id,
                        resource_id,
                    },
                )?;

                // data_sizes is always 0 for output buffers. We should fetch them from the
                // negotiated parameters, although right now the VirtioObject backend uses the
                // buffer's metadata instead.
                let buffer_size = dst_resource.resource.planes[0].size as u32;

                // Stores an output buffer to notify EOS.
                // This is necessary because libvda is unable to indicate EOS along with returned buffers.
                // For now, when a `Flush()` completes, this saved resource will be returned as a zero-sized
                // buffer with the EOS flag.
                if stream.eos_manager.try_reserve_eos_buffer(resource_id) {
                    return Ok(VideoCmdResponseType::Async(AsyncCmdTag::Queue {
                        stream_id,
                        queue_type: QueueType::Output,
                        resource_id,
                    }));
                }

                match encoder_session.use_output_buffer(
                    dst_resource
                        .resource
                        .handle
                        .try_clone()
                        .map_err(|_| VideoError::InvalidParameter)?,
                    dst_resource.offset,
                    buffer_size,
                ) {
                    Ok(output_buffer_id) => {
                        if let Some(last_resource_id) = stream
                            .encoder_output_buffer_ids
                            .insert(output_buffer_id, resource_id)
                        {
                            error!(
                                "encoder output id {} was already mapped to resource id {}",
                                output_buffer_id, last_resource_id
                            );
                        }
                        let queue_params = QueuedOutputResourceParams { in_queue: true };
                        if let Some(last_queue_params) =
                            dst_resource.queue_params.replace(queue_params)
                        {
                            if last_queue_params.in_queue {
                                error!(
                                    "resource {} was already queued ({:?})",
                                    resource_id, last_queue_params
                                );
                            }
                        }
                    }
                    Err(e) => {
                        error!("use_output_buffer failed: {}", e);
                        return Err(VideoError::InvalidOperation);
                    }
                }
                Ok(VideoCmdResponseType::Async(AsyncCmdTag::Queue {
                    stream_id,
                    queue_type: QueueType::Output,
                    resource_id,
                }))
            }
        }
    }

    fn resource_destroy_all(&mut self, stream_id: u32) -> VideoResult<VideoCmdResponseType> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(VideoError::InvalidStreamId(stream_id))?;
        stream.src_resources.clear();
        stream.encoder_input_buffer_ids.clear();
        stream.dst_resources.clear();
        stream.encoder_output_buffer_ids.clear();
        stream.eos_manager.reset();
        Ok(VideoCmdResponseType::Sync(CmdResponse::NoData))
    }

    fn queue_clear(
        &mut self,
        stream_id: u32,
        queue_type: QueueType,
    ) -> VideoResult<VideoCmdResponseType> {
        // Unfortunately, there is no way to clear the queue with VEA.
        // VDA has Reset() which also isn't done on a per-queue basis,
        // but VEA has no such API.
        // Doing a Flush() here and waiting for the flush response is also
        // not an option, because the virtio-video driver expects a prompt
        // response (search for "timed out waiting for queue clear" in
        // virtio_video_enc.c).
        // So for now, we do a Flush(), but also mark each currently
        // queued resource as no longer `in_queue`, and skip them when they
        // are returned.
        // TODO(b/153406792): Support per-queue clearing.
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(VideoError::InvalidStreamId(stream_id))?;

        match queue_type {
            QueueType::Input => {
                for src_resource in stream.src_resources.values_mut() {
                    if let Some(ref mut queue_params) = src_resource.queue_params {
                        queue_params.in_queue = false;
                    }
                }
            }
            QueueType::Output => {
                for dst_resource in stream.dst_resources.values_mut() {
                    if let Some(ref mut queue_params) = dst_resource.queue_params {
                        queue_params.in_queue = false;
                    }
                }
                stream.eos_manager.reset();
            }
        }
        Ok(VideoCmdResponseType::Sync(CmdResponse::NoData))
    }

    fn get_params(
        &mut self,
        stream_id: u32,
        queue_type: QueueType,
        is_ext: bool,
    ) -> VideoResult<VideoCmdResponseType> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(VideoError::InvalidStreamId(stream_id))?;

        if stream.encoder_session.is_some() && !stream.received_input_buffers_event {
            // If we haven't yet received an RequireInputBuffers
            // event, we need to wait for that before replying so that
            // the G_FMT response has the correct data.
            let pending_command = match queue_type {
                QueueType::Input => PendingCommand::GetSrcParams { is_ext },
                QueueType::Output => PendingCommand::GetDstParams { is_ext },
            };

            if !stream.pending_commands.insert(pending_command) {
                // There is already a G_FMT call waiting.
                error!("Pending get params call already exists.");
                return Err(VideoError::InvalidOperation);
            }

            Ok(VideoCmdResponseType::Async(AsyncCmdTag::GetParams {
                stream_id,
                queue_type,
            }))
        } else {
            let params = match queue_type {
                QueueType::Input => stream.src_params.clone(),
                QueueType::Output => stream.dst_params.clone(),
            };
            Ok(VideoCmdResponseType::Sync(CmdResponse::GetParams {
                queue_type,
                params,
                is_ext,
            }))
        }
    }

    fn set_params(
        &mut self,
        wait_ctx: &WaitContext<Token>,
        stream_id: u32,
        queue_type: QueueType,
        format: Option<Format>,
        frame_width: u32,
        frame_height: u32,
        frame_rate: u32,
        plane_formats: Vec<PlaneFormat>,
        resource_type: Option<ResourceType>,
    ) -> VideoResult<VideoCmdResponseType> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(VideoError::InvalidStreamId(stream_id))?;

        let mut create_session = stream.encoder_session.is_none();
        // TODO(ishitatsuyuki): We should additionally check that no resources are *attached* while
        //                      a params is being set.
        let src_resources_queued = !stream.src_resources.is_empty();
        let dst_resources_queued = !stream.dst_resources.is_empty();

        // Dynamic framerate changes are allowed. The framerate can be set on either the input or
        // output queue. Changing the framerate can influence the selected H.264 level, as the
        // level might be adjusted to conform to the minimum requirements for the selected bitrate
        // and framerate. As dynamic level changes are not supported we will just recreate the
        // encoder session as long as no resources have been queued yet. If an encoder session is
        // active we will request a dynamic framerate change instead, and it's up to the encoder
        // backend to return an error on invalid requests.
        if stream.dst_params.frame_rate != frame_rate {
            stream.src_params.frame_rate = frame_rate;
            stream.dst_params.frame_rate = frame_rate;
            if let Some(ref mut encoder_session) = stream.encoder_session {
                if !(src_resources_queued || dst_resources_queued) {
                    create_session = true;
                } else if let Err(e) = encoder_session.request_encoding_params_change(
                    stream.dst_bitrate,
                    stream.dst_params.frame_rate,
                ) {
                    error!("failed to dynamically request framerate change: {}", e);
                    return Err(VideoError::InvalidOperation);
                }
            }
        }

        match queue_type {
            QueueType::Input => {
                if stream.src_params.frame_width != frame_width
                    || stream.src_params.frame_height != frame_height
                    || stream.src_params.format != format
                    || stream.src_params.plane_formats != plane_formats
                    || resource_type
                        .map(|resource_type| stream.src_params.resource_type != resource_type)
                        .unwrap_or(false)
                {
                    if src_resources_queued {
                        // Buffers have already been queued and encoding has already started.
                        return Err(VideoError::InvalidOperation);
                    }

                    let desired_format =
                        format.or(stream.src_params.format).unwrap_or(Format::NV12);
                    self.cros_capabilities.populate_src_params(
                        &mut stream.src_params,
                        desired_format,
                        frame_width,
                        frame_height,
                        plane_formats.get(0).map(|fmt| fmt.stride).unwrap_or(0),
                    )?;

                    stream.dst_params.frame_width = frame_width;
                    stream.dst_params.frame_height = frame_height;

                    if let Some(resource_type) = resource_type {
                        stream.src_params.resource_type = resource_type;
                    }

                    create_session = true
                }
            }
            QueueType::Output => {
                if stream.dst_params.format != format
                    || stream.dst_params.plane_formats != plane_formats
                    || resource_type
                        .map(|resource_type| stream.dst_params.resource_type != resource_type)
                        .unwrap_or(false)
                {
                    if dst_resources_queued {
                        // Buffers have already been queued and encoding has already started.
                        return Err(VideoError::InvalidOperation);
                    }

                    let desired_format =
                        format.or(stream.dst_params.format).unwrap_or(Format::H264);

                    // There should be exactly one output buffer.
                    if plane_formats.len() != 1 {
                        return Err(VideoError::InvalidArgument);
                    }

                    self.cros_capabilities.populate_dst_params(
                        &mut stream.dst_params,
                        desired_format,
                        plane_formats[0].plane_size,
                    )?;

                    // Format is always populated for encoder.
                    let new_format = stream
                        .dst_params
                        .format
                        .ok_or(VideoError::InvalidArgument)?;

                    // If the selected profile no longer corresponds to the selected coded format,
                    // reset it.
                    stream.dst_profile = self
                        .cros_capabilities
                        .get_default_profile(&new_format)
                        .ok_or(VideoError::InvalidArgument)?;

                    if new_format == Format::H264 {
                        stream.dst_h264_level = Some(Level::H264_1_0);
                    } else {
                        stream.dst_h264_level = None;
                    }

                    if let Some(resource_type) = resource_type {
                        stream.dst_params.resource_type = resource_type;
                    }

                    create_session = true;
                }
            }
        }

        if create_session {
            // An encoder session has to be created immediately upon a SetParams
            // (S_FMT) call, because we need to receive the RequireInputBuffers
            // callback which has output buffer size info, in order to populate
            // dst_params to have the correct size on subsequent GetParams (G_FMT) calls.
            if stream.encoder_session.is_some() {
                stream.clear_encode_session(wait_ctx)?;
                if !stream.received_input_buffers_event {
                    // This could happen if two SetParams calls are occuring at the same time.
                    // For example, the user calls SetParams for the input queue on one thread,
                    // and a new encode session is created. Then on another thread, SetParams
                    // is called for the output queue before the first SetParams call has returned.
                    // At this point, there is a new EncodeSession being created that has not
                    // yet received a RequireInputBuffers event.
                    // Even if we clear the encoder session and recreate it, this case
                    // is handled because stream.pending_commands will still contain
                    // the waiting GetParams responses, which will then receive fresh data once
                    // the new session's RequireInputBuffers event happens.
                    warn!(
                        "New encoder session being created while waiting for RequireInputBuffers."
                    )
                }
            }
            stream.set_encode_session(&mut self.encoder, wait_ctx)?;
        }
        Ok(VideoCmdResponseType::Sync(CmdResponse::NoData))
    }

    fn query_control(&self, query_ctrl_type: QueryCtrlType) -> VideoResult<VideoCmdResponseType> {
        let query_ctrl_response = match query_ctrl_type {
            QueryCtrlType::Profile(format) => match self.cros_capabilities.get_profiles(&format) {
                Some(profiles) => QueryCtrlResponse::Profile(profiles.clone()),
                None => {
                    return Err(VideoError::UnsupportedControl(CtrlType::Profile));
                }
            },
            QueryCtrlType::Level(format) => {
                match format {
                    Format::H264 => QueryCtrlResponse::Level(vec![
                        Level::H264_1_0,
                        Level::H264_1_1,
                        Level::H264_1_2,
                        Level::H264_1_3,
                        Level::H264_2_0,
                        Level::H264_2_1,
                        Level::H264_2_2,
                        Level::H264_3_0,
                        Level::H264_3_1,
                        Level::H264_3_2,
                        Level::H264_4_0,
                        Level::H264_4_1,
                        Level::H264_4_2,
                        Level::H264_5_0,
                        Level::H264_5_1,
                    ]),
                    _ => {
                        // Levels are only supported for H264.
                        return Err(VideoError::UnsupportedControl(CtrlType::Level));
                    }
                }
            }
        };

        Ok(VideoCmdResponseType::Sync(CmdResponse::QueryControl(
            query_ctrl_response,
        )))
    }

    fn get_control(
        &self,
        stream_id: u32,
        ctrl_type: CtrlType,
    ) -> VideoResult<VideoCmdResponseType> {
        let stream = self
            .streams
            .get(&stream_id)
            .ok_or(VideoError::InvalidStreamId(stream_id))?;
        let ctrl_val = match ctrl_type {
            CtrlType::BitrateMode => CtrlVal::BitrateMode(stream.dst_bitrate.mode()),
            CtrlType::Bitrate => CtrlVal::Bitrate(stream.dst_bitrate.target()),
            CtrlType::BitratePeak => CtrlVal::BitratePeak(match stream.dst_bitrate {
                Bitrate::Vbr { peak, .. } => peak,
                // For CBR there is no peak, so return the target (which is technically correct).
                Bitrate::Cbr { target } => target,
            }),
            CtrlType::Profile => CtrlVal::Profile(stream.dst_profile),
            CtrlType::Level => {
                let format = stream
                    .dst_params
                    .format
                    .ok_or(VideoError::InvalidArgument)?;
                match format {
                    Format::H264 => CtrlVal::Level(stream.dst_h264_level.ok_or_else(|| {
                        error!("H264 level not set");
                        VideoError::InvalidArgument
                    })?),
                    _ => {
                        return Err(VideoError::UnsupportedControl(ctrl_type));
                    }
                }
            }
            // Button controls should not be queried.
            CtrlType::ForceKeyframe => return Err(VideoError::UnsupportedControl(ctrl_type)),
            // Prepending SPS and PPS to IDR is always enabled in the libvda backend.
            // TODO (b/161495502): account for other backends
            CtrlType::PrependSpsPpsToIdr => CtrlVal::PrependSpsPpsToIdr(true),
        };
        Ok(VideoCmdResponseType::Sync(CmdResponse::GetControl(
            ctrl_val,
        )))
    }

    fn set_control(
        &mut self,
        wait_ctx: &WaitContext<Token>,
        stream_id: u32,
        ctrl_val: CtrlVal,
    ) -> VideoResult<VideoCmdResponseType> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(VideoError::InvalidStreamId(stream_id))?;
        let mut recreate_session = false;
        let resources_queued = !stream.src_resources.is_empty() || !stream.dst_resources.is_empty();

        match ctrl_val {
            CtrlVal::BitrateMode(bitrate_mode) => {
                if stream.dst_bitrate.mode() != bitrate_mode {
                    if resources_queued {
                        error!("set control called for bitrate mode but already encoding.");
                        return Err(VideoError::InvalidOperation);
                    }
                    stream.dst_bitrate = match bitrate_mode {
                        BitrateMode::Cbr => Bitrate::Cbr {
                            target: stream.dst_bitrate.target(),
                        },
                        BitrateMode::Vbr => Bitrate::Vbr {
                            target: stream.dst_bitrate.target(),
                            peak: stream.dst_bitrate.target(),
                        },
                    };
                    recreate_session = true;
                }
            }
            CtrlVal::Bitrate(bitrate) => {
                if stream.dst_bitrate.target() != bitrate {
                    let mut new_bitrate = stream.dst_bitrate;
                    match &mut new_bitrate {
                        Bitrate::Cbr { target } | Bitrate::Vbr { target, .. } => *target = bitrate,
                    }
                    if let Some(ref mut encoder_session) = stream.encoder_session {
                        if let Err(e) = encoder_session.request_encoding_params_change(
                            new_bitrate,
                            stream.dst_params.frame_rate,
                        ) {
                            error!("failed to dynamically request target bitrate change: {}", e);
                            return Err(VideoError::InvalidOperation);
                        }
                    }
                    stream.dst_bitrate = new_bitrate;
                }
            }
            CtrlVal::BitratePeak(bitrate) => {
                match stream.dst_bitrate {
                    Bitrate::Vbr { peak, .. } => {
                        if peak != bitrate {
                            let new_bitrate = Bitrate::Vbr {
                                target: stream.dst_bitrate.target(),
                                peak: bitrate,
                            };
                            if let Some(ref mut encoder_session) = stream.encoder_session {
                                if let Err(e) = encoder_session.request_encoding_params_change(
                                    new_bitrate,
                                    stream.dst_params.frame_rate,
                                ) {
                                    error!(
                                        "failed to dynamically request peak bitrate change: {}",
                                        e
                                    );
                                    return Err(VideoError::InvalidOperation);
                                }
                            }
                            stream.dst_bitrate = new_bitrate;
                        }
                    }
                    // Trying to set the peak bitrate while in constant mode. This is not
                    // an error, just ignored.
                    Bitrate::Cbr { .. } => {}
                }
            }
            CtrlVal::Profile(profile) => {
                if stream.dst_profile != profile {
                    if resources_queued {
                        error!("set control called for profile but already encoding.");
                        return Err(VideoError::InvalidOperation);
                    }
                    let format = stream
                        .dst_params
                        .format
                        .ok_or(VideoError::InvalidArgument)?;
                    if format != profile.to_format() {
                        error!(
                            "specified profile does not correspond to the selected format ({})",
                            format
                        );
                        return Err(VideoError::InvalidOperation);
                    }
                    stream.dst_profile = profile;
                    recreate_session = true;
                }
            }
            CtrlVal::Level(level) => {
                if stream.dst_h264_level != Some(level) {
                    if resources_queued {
                        error!("set control called for level but already encoding.");
                        return Err(VideoError::InvalidOperation);
                    }
                    let format = stream
                        .dst_params
                        .format
                        .ok_or(VideoError::InvalidArgument)?;
                    if format != Format::H264 {
                        error!(
                            "set control called for level but format is not H264 ({})",
                            format
                        );
                        return Err(VideoError::InvalidOperation);
                    }
                    stream.dst_h264_level = Some(level);
                    recreate_session = true;
                }
            }
            CtrlVal::ForceKeyframe => {
                stream.force_keyframe = true;
            }
            CtrlVal::PrependSpsPpsToIdr(prepend_sps_pps_to_idr) => {
                // Prepending SPS and PPS to IDR is always enabled in the libvda backend,
                // disabling it will always fail.
                // TODO (b/161495502): account for other backends
                if !prepend_sps_pps_to_idr {
                    return Err(VideoError::InvalidOperation);
                }
            }
        }

        // We can safely recreate the encoder session if no resources were queued yet.
        if recreate_session && stream.encoder_session.is_some() {
            stream.clear_encode_session(wait_ctx)?;
            stream.set_encode_session(&mut self.encoder, wait_ctx)?;
        }

        Ok(VideoCmdResponseType::Sync(CmdResponse::SetControl))
    }
}

impl<T: Encoder> Device for EncoderDevice<T> {
    fn process_cmd(
        &mut self,
        req: VideoCmd,
        wait_ctx: &WaitContext<Token>,
    ) -> (
        VideoCmdResponseType,
        Option<(u32, Vec<VideoEvtResponseType>)>,
    ) {
        let mut event_ret = None;
        let cmd_response = match req {
            VideoCmd::QueryCapability { queue_type } => self.query_capabilities(queue_type),
            VideoCmd::StreamCreate {
                stream_id,
                coded_format: desired_format,
                input_resource_type,
                output_resource_type,
            } => self.stream_create(
                stream_id,
                desired_format,
                input_resource_type,
                output_resource_type,
            ),
            VideoCmd::StreamDestroy { stream_id } => self.stream_destroy(stream_id),
            VideoCmd::StreamDrain { stream_id } => self.stream_drain(stream_id),
            VideoCmd::ResourceCreate {
                stream_id,
                queue_type,
                resource_id,
                plane_offsets,
                plane_entries,
            } => self.resource_create(
                wait_ctx,
                stream_id,
                queue_type,
                resource_id,
                plane_offsets,
                plane_entries,
            ),
            VideoCmd::ResourceQueue {
                stream_id,
                queue_type,
                resource_id,
                timestamp,
                data_sizes,
            } => {
                let resp =
                    self.resource_queue(stream_id, queue_type, resource_id, timestamp, data_sizes);

                if resp.is_ok() && queue_type == QueueType::Output {
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        // If we have a flush pending, add the response for dequeueing the EOS
                        // buffer.
                        if stream.eos_manager.client_awaits_eos {
                            info!(
                                "stream {}: using queued buffer as EOS for pending flush",
                                stream_id
                            );
                            event_ret = match stream.eos_manager.try_complete_eos(vec![]) {
                                Some(eos_resps) => Some((stream_id, eos_resps)),
                                None => {
                                    error!("stream {}: try_get_eos_buffer() should have returned a valid response. This is a bug.", stream_id);
                                    Some((
                                        stream_id,
                                        vec![VideoEvtResponseType::Event(VideoEvt {
                                            typ: EvtType::Error,
                                            stream_id,
                                        })],
                                    ))
                                }
                            };
                        }
                    } else {
                        error!(
                            "stream {}: the stream ID should be valid here. This is a bug.",
                            stream_id
                        );
                        event_ret = Some((
                            stream_id,
                            vec![VideoEvtResponseType::Event(VideoEvt {
                                typ: EvtType::Error,
                                stream_id,
                            })],
                        ));
                    }
                }

                resp
            }
            VideoCmd::ResourceDestroyAll { stream_id, .. } => self.resource_destroy_all(stream_id),
            VideoCmd::QueueClear {
                stream_id,
                queue_type,
            } => self.queue_clear(stream_id, queue_type),
            VideoCmd::GetParams {
                stream_id,
                queue_type,
                is_ext,
            } => self.get_params(stream_id, queue_type, is_ext),
            VideoCmd::SetParams {
                stream_id,
                queue_type,
                params:
                    Params {
                        format,
                        frame_width,
                        frame_height,
                        frame_rate,
                        plane_formats,
                        resource_type,
                        ..
                    },
                is_ext,
            } => self.set_params(
                wait_ctx,
                stream_id,
                queue_type,
                format,
                frame_width,
                frame_height,
                frame_rate,
                plane_formats,
                if is_ext { Some(resource_type) } else { None },
            ),
            VideoCmd::QueryControl { query_ctrl_type } => self.query_control(query_ctrl_type),
            VideoCmd::GetControl {
                stream_id,
                ctrl_type,
            } => self.get_control(stream_id, ctrl_type),
            VideoCmd::SetControl {
                stream_id,
                ctrl_val,
            } => self.set_control(wait_ctx, stream_id, ctrl_val),
        };
        let cmd_ret = match cmd_response {
            Ok(r) => r,
            Err(e) => {
                error!("returning error response: {}", &e);
                VideoCmdResponseType::Sync(e.into())
            }
        };
        (cmd_ret, event_ret)
    }

    fn process_event(
        &mut self,
        _desc_map: &mut AsyncCmdDescMap,
        stream_id: u32,
        _wait_ctx: &WaitContext<Token>,
    ) -> Option<Vec<VideoEvtResponseType>> {
        let stream = match self.streams.get_mut(&stream_id) {
            Some(s) => s,
            None => {
                // TODO: remove fd from poll context?
                error!("Received event for missing stream id {}", stream_id);
                return None;
            }
        };

        let encoder_session = match stream.encoder_session {
            Some(ref mut s) => s,
            None => {
                error!(
                    "Received event for missing encoder session of stream id {}",
                    stream_id
                );
                return None;
            }
        };

        let event = match encoder_session.read_event() {
            Ok(e) => e,
            Err(e) => {
                error!("Failed to read event for stream id {}: {}", stream_id, e);
                return None;
            }
        };

        match event {
            EncoderEvent::RequireInputBuffers {
                input_count,
                input_frame_width,
                input_frame_height,
                output_buffer_size,
            } => stream.require_input_buffers(
                input_count,
                input_frame_width,
                input_frame_height,
                output_buffer_size,
            ),
            EncoderEvent::ProcessedInputBuffer {
                id: input_buffer_id,
            } => stream.processed_input_buffer(input_buffer_id),
            EncoderEvent::ProcessedOutputBuffer {
                id: output_buffer_id,
                bytesused,
                keyframe,
                timestamp,
            } => stream.processed_output_buffer(output_buffer_id, bytesused, keyframe, timestamp),
            EncoderEvent::FlushResponse { flush_done } => stream.flush_response(flush_done),
            EncoderEvent::NotifyError { error } => stream.notify_error(error),
        }
    }
}

#[derive(Debug)]
pub enum EncoderEvent {
    RequireInputBuffers {
        input_count: u32,
        input_frame_width: u32,
        input_frame_height: u32,
        output_buffer_size: u32,
    },
    ProcessedInputBuffer {
        id: InputBufferId,
    },
    ProcessedOutputBuffer {
        id: OutputBufferId,
        bytesused: u32,
        keyframe: bool,
        timestamp: u64,
    },
    FlushResponse {
        flush_done: bool,
    },
    #[allow(dead_code)]
    NotifyError {
        error: VideoError,
    },
}

#[derive(Debug)]
pub struct SessionConfig {
    pub src_params: Params,
    pub dst_params: Params,
    pub dst_profile: Profile,
    pub dst_bitrate: Bitrate,
    pub dst_h264_level: Option<Level>,
    pub frame_rate: u32,
}

#[derive(Clone)]
pub struct EncoderCapabilities {
    pub input_format_descs: Vec<FormatDesc>,
    pub output_format_descs: Vec<FormatDesc>,
    pub coded_format_profiles: BTreeMap<Format, Vec<Profile>>,
}

impl EncoderCapabilities {
    pub fn populate_src_params(
        &self,
        src_params: &mut Params,
        desired_format: Format,
        desired_width: u32,
        desired_height: u32,
        mut stride: u32,
    ) -> VideoResult<()> {
        let format_desc = self
            .input_format_descs
            .iter()
            .find(|&format_desc| format_desc.format == desired_format)
            .unwrap_or(
                self.input_format_descs
                    .get(0)
                    .ok_or(VideoError::InvalidFormat)?,
            );

        let (allowed_width, allowed_height) =
            find_closest_resolution(&format_desc.frame_formats, desired_width, desired_height);

        if stride == 0 {
            stride = allowed_width;
        }

        let plane_formats =
            PlaneFormat::get_plane_layout(format_desc.format, stride, allowed_height)
                .ok_or(VideoError::InvalidFormat)?;

        src_params.frame_width = allowed_width;
        src_params.frame_height = allowed_height;
        src_params.format = Some(format_desc.format);
        src_params.plane_formats = plane_formats;
        Ok(())
    }

    pub fn populate_dst_params(
        &self,
        dst_params: &mut Params,
        desired_format: Format,
        buffer_size: u32,
    ) -> VideoResult<()> {
        // TODO(alexlau): Should the first be the default?
        let format_desc = self
            .output_format_descs
            .iter()
            .find(move |&format_desc| format_desc.format == desired_format)
            .unwrap_or(
                self.output_format_descs
                    .get(0)
                    .ok_or(VideoError::InvalidFormat)?,
            );
        dst_params.format = Some(format_desc.format);

        // The requested output buffer size might be adjusted by the encoder to match hardware
        // requirements in RequireInputBuffers.
        dst_params.plane_formats = vec![PlaneFormat {
            plane_size: buffer_size,
            stride: 0,
        }];
        Ok(())
    }

    pub fn get_profiles(&self, coded_format: &Format) -> Option<&Vec<Profile>> {
        self.coded_format_profiles.get(coded_format)
    }

    pub fn get_default_profile(&self, coded_format: &Format) -> Option<Profile> {
        let profiles = self.get_profiles(coded_format)?;
        match profiles.get(0) {
            None => {
                error!("Format {} exists but no available profiles.", coded_format);
                None
            }
            Some(profile) => Some(*profile),
        }
    }
}

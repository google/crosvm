// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implementation of a virtio video decoder backed by a device.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::VecDeque;

use backend::*;
use base::error;
use base::Tube;
use base::WaitContext;
use vm_memory::GuestMemory;

use crate::virtio::video::async_cmd_desc_map::AsyncCmdDescMap;
use crate::virtio::video::command::QueueType;
use crate::virtio::video::command::VideoCmd;
use crate::virtio::video::control::CtrlType;
use crate::virtio::video::control::CtrlVal;
use crate::virtio::video::control::QueryCtrlType;
use crate::virtio::video::device::*;
use crate::virtio::video::error::*;
use crate::virtio::video::event::*;
use crate::virtio::video::format::*;
use crate::virtio::video::params::Params;
use crate::virtio::video::protocol;
use crate::virtio::video::resource::*;
use crate::virtio::video::response::CmdResponse;

pub mod backend;
mod capability;

use capability::*;

type StreamId = u32;
type ResourceId = u32;

// ResourceId given by the driver
type InputResourceId = u32;
type OutputResourceId = u32;

// Id for a frame buffer passed to Chrome.
// We cannot use OutputResourceId as is because this ID must be between 0 and ((# of buffers) - 1).
//
// TODO(b/1518105): Once we decide to generate resource_id in the device side,
// we don't need this value and can pass OutputResourceId to Chrome directly.
type FrameBufferId = i32;

// The result of OutputResources.queue_resource().
enum QueueOutputResourceResult {
    UsingAsEos,                // The resource is kept as EOS buffer.
    Reused(FrameBufferId),     // The resource has been registered before.
    Registered(FrameBufferId), // The resource is queued first time.
}

struct InputResource {
    /// The actual underlying resource.
    resource: GuestResource,
    /// Offset from `resource` from which data starts.
    offset: u32,
}

/// Maps an input resource ID to the underlying resource and its useful information.
type InputResources = BTreeMap<InputResourceId, InputResource>;

#[derive(Default)]
struct OutputResources {
    // OutputResourceId <-> FrameBufferId
    res_id_to_frame_buf_id: BTreeMap<OutputResourceId, FrameBufferId>,
    frame_buf_id_to_res_id: BTreeMap<FrameBufferId, OutputResourceId>,

    // Store the resource id of the queued output buffers.
    queued_res_ids: BTreeSet<OutputResourceId>,

    // Reserves output resource ID that will be used to notify EOS.
    // If a guest enqueues a resource with this ID, the resource must not be sent to the host.
    // Once the value is set, it won't be changed until resolution is changed or a stream is
    // destroyed.
    eos_resource_id: Option<OutputResourceId>,

    // This is a flag that shows whether the device's set_output_parameters has called.
    // This will be set to true when ResourceQueue for OutputBuffer is called for the first time.
    //
    // TODO(b/1518105): This field is added as a hack because the current virtio-video v3 spec
    // doesn't have a way to send a number of frame buffers the guest provides.
    // Once we have the way in the virtio-video protocol, we should remove this flag.
    output_params_set: bool,

    // OutputResourceId -> ResourceHandle
    res_id_to_res_handle: BTreeMap<OutputResourceId, GuestResource>,
}

impl OutputResources {
    fn queue_resource(
        &mut self,
        resource_id: OutputResourceId,
    ) -> VideoResult<QueueOutputResourceResult> {
        if !self.queued_res_ids.insert(resource_id) {
            error!("resource_id {} is already queued", resource_id);
            return Err(VideoError::InvalidParameter);
        }

        // Stores an output buffer to notify EOS.
        // This is necessary because libvda is unable to indicate EOS along with returned buffers.
        // For now, when a `Flush()` completes, this saved resource will be returned as a zero-sized
        // buffer with the EOS flag.
        // TODO(b/149725148): Remove this when libvda supports buffer flags.
        if *self.eos_resource_id.get_or_insert(resource_id) == resource_id {
            return Ok(QueueOutputResourceResult::UsingAsEos);
        }

        Ok(match self.res_id_to_frame_buf_id.entry(resource_id) {
            Entry::Occupied(e) => QueueOutputResourceResult::Reused(*e.get()),
            Entry::Vacant(_) => {
                let buffer_id = self.res_id_to_frame_buf_id.len() as FrameBufferId;
                self.res_id_to_frame_buf_id.insert(resource_id, buffer_id);
                self.frame_buf_id_to_res_id.insert(buffer_id, resource_id);
                QueueOutputResourceResult::Registered(buffer_id)
            }
        })
    }

    fn dequeue_frame_buffer(
        &mut self,
        buffer_id: FrameBufferId,
        stream_id: StreamId,
    ) -> Option<ResourceId> {
        let resource_id = match self.frame_buf_id_to_res_id.get(&buffer_id) {
            Some(id) => *id,
            None => {
                error!(
                    "unknown frame buffer id {} for stream {}",
                    buffer_id, stream_id
                );
                return None;
            }
        };

        self.queued_res_ids.take(&resource_id).or_else(|| {
            error!(
                "resource_id {} is not enqueued for stream {}",
                resource_id, stream_id
            );
            None
        })
    }

    fn dequeue_eos_resource_id(&mut self) -> Option<OutputResourceId> {
        self.queued_res_ids.take(&self.eos_resource_id?)
    }

    fn output_params_set(&mut self) -> bool {
        if !self.output_params_set {
            self.output_params_set = true;
            return true;
        }
        false
    }
}

enum PendingResponse {
    PictureReady {
        picture_buffer_id: i32,
        timestamp: u64,
    },
    FlushCompleted,
}

// Context is associated with one `DecoderSession`, which corresponds to one stream from the
// virtio-video's point of view.
struct Context<S: DecoderSession> {
    stream_id: StreamId,

    in_params: Params,
    out_params: Params,

    in_res: InputResources,
    out_res: OutputResources,

    // Set the flag when we ask the decoder reset, and unset when the reset is done.
    is_resetting: bool,

    pending_responses: VecDeque<PendingResponse>,

    session: Option<S>,
}

impl<S: DecoderSession> Context<S> {
    fn new(
        stream_id: StreamId,
        format: Format,
        in_resource_type: ResourceType,
        out_resource_type: ResourceType,
    ) -> Self {
        const DEFAULT_WIDTH: u32 = 640;
        const DEFAULT_HEIGHT: u32 = 480;
        const DEFAULT_INPUT_BUFFER_SIZE: u32 = 1024 * 1024;

        let out_plane_formats =
            PlaneFormat::get_plane_layout(Format::NV12, DEFAULT_WIDTH, DEFAULT_HEIGHT).unwrap();

        Context {
            stream_id,
            in_params: Params {
                format: Some(format),
                frame_width: DEFAULT_WIDTH,
                frame_height: DEFAULT_HEIGHT,
                resource_type: in_resource_type,
                min_buffers: 1,
                max_buffers: 32,
                plane_formats: vec![PlaneFormat {
                    plane_size: DEFAULT_INPUT_BUFFER_SIZE,
                    ..Default::default()
                }],
                ..Default::default()
            },
            out_params: Params {
                format: Some(Format::NV12),
                frame_width: DEFAULT_WIDTH,
                frame_height: DEFAULT_HEIGHT,
                resource_type: out_resource_type,
                plane_formats: out_plane_formats,
                ..Default::default()
            },
            in_res: Default::default(),
            out_res: Default::default(),
            is_resetting: false,
            pending_responses: Default::default(),
            session: None,
        }
    }

    fn output_pending_responses(&mut self) -> Vec<VideoEvtResponseType> {
        let mut event_responses = vec![];
        while let Some(mut responses) = self.output_pending_response() {
            event_responses.append(&mut responses);
        }
        event_responses
    }

    fn output_pending_response(&mut self) -> Option<Vec<VideoEvtResponseType>> {
        let responses = match self.pending_responses.front()? {
            PendingResponse::PictureReady {
                picture_buffer_id,
                timestamp,
            } => {
                let resource_id = self
                    .out_res
                    .dequeue_frame_buffer(*picture_buffer_id, self.stream_id)?;

                vec![VideoEvtResponseType::AsyncCmd(
                    AsyncCmdResponse::from_response(
                        AsyncCmdTag::Queue {
                            stream_id: self.stream_id,
                            queue_type: QueueType::Output,
                            resource_id,
                        },
                        CmdResponse::ResourceQueue {
                            timestamp: *timestamp,
                            // TODO(b/149725148): Set buffer flags once libvda exposes them.
                            flags: 0,
                            // `size` is only used for the encoder.
                            size: 0,
                        },
                    ),
                )]
            }
            PendingResponse::FlushCompleted => {
                let eos_resource_id = self.out_res.dequeue_eos_resource_id()?;
                let eos_tag = AsyncCmdTag::Queue {
                    stream_id: self.stream_id,
                    queue_type: QueueType::Output,
                    resource_id: eos_resource_id,
                };
                let eos_response = CmdResponse::ResourceQueue {
                    timestamp: 0,
                    flags: protocol::VIRTIO_VIDEO_BUFFER_FLAG_EOS,
                    size: 0,
                };
                vec![
                    VideoEvtResponseType::AsyncCmd(AsyncCmdResponse::from_response(
                        eos_tag,
                        eos_response,
                    )),
                    VideoEvtResponseType::AsyncCmd(AsyncCmdResponse::from_response(
                        AsyncCmdTag::Drain {
                            stream_id: self.stream_id,
                        },
                        CmdResponse::NoData,
                    )),
                ]
            }
        };
        self.pending_responses.pop_front().unwrap();

        Some(responses)
    }

    fn register_resource(
        &mut self,
        queue_type: QueueType,
        resource_id: u32,
        resource: GuestResource,
        offset: u32,
    ) {
        match queue_type {
            QueueType::Input => {
                self.in_res
                    .insert(resource_id, InputResource { resource, offset });
            }
            QueueType::Output => {
                self.out_res
                    .res_id_to_res_handle
                    .insert(resource_id, resource);
            }
        };
    }

    /*
     * Functions handling decoder events.
     */

    fn handle_provide_picture_buffers(
        &mut self,
        min_num_buffers: u32,
        width: i32,
        height: i32,
        visible_rect: Rect,
    ) {
        // We only support NV12.
        let format = Some(Format::NV12);

        let plane_formats =
            PlaneFormat::get_plane_layout(Format::NV12, width as u32, height as u32).unwrap();

        self.in_params.frame_width = width as u32;
        self.in_params.frame_height = height as u32;

        self.out_params = Params {
            format,
            // The resource type is not changed by a provide picture buffers event.
            resource_type: self.out_params.resource_type,
            // Note that rect_width is sometimes smaller.
            frame_width: width as u32,
            frame_height: height as u32,
            // Adding 1 to `min_buffers` to reserve a resource for `eos_resource_id`.
            min_buffers: min_num_buffers + 1,
            max_buffers: 32,
            crop: Crop {
                left: visible_rect.left as u32,
                top: visible_rect.top as u32,
                width: (visible_rect.right - visible_rect.left) as u32,
                height: (visible_rect.bottom - visible_rect.top) as u32,
            },
            plane_formats,
            // No need to set `frame_rate`, as it's only for the encoder.
            ..Default::default()
        };
    }
}

/// A thin wrapper of a map of contexts with error handlings.
struct ContextMap<S: DecoderSession> {
    map: BTreeMap<StreamId, Context<S>>,
}

impl<S: DecoderSession> ContextMap<S> {
    fn insert(&mut self, ctx: Context<S>) -> VideoResult<()> {
        match self.map.entry(ctx.stream_id) {
            Entry::Vacant(e) => {
                e.insert(ctx);
                Ok(())
            }
            Entry::Occupied(_) => {
                error!("session {} already exists", ctx.stream_id);
                Err(VideoError::InvalidStreamId(ctx.stream_id))
            }
        }
    }

    fn get(&self, stream_id: &StreamId) -> VideoResult<&Context<S>> {
        self.map.get(stream_id).ok_or_else(|| {
            error!("failed to get context of stream {}", *stream_id);
            VideoError::InvalidStreamId(*stream_id)
        })
    }

    fn get_mut(&mut self, stream_id: &StreamId) -> VideoResult<&mut Context<S>> {
        self.map.get_mut(stream_id).ok_or_else(|| {
            error!("failed to get context of stream {}", *stream_id);
            VideoError::InvalidStreamId(*stream_id)
        })
    }
}

impl<S: DecoderSession> Default for ContextMap<S> {
    fn default() -> Self {
        Self {
            map: Default::default(),
        }
    }
}

/// Represents information of a decoder backed by a `DecoderBackend`.
pub struct Decoder<D: DecoderBackend> {
    decoder: D,
    capability: Capability,
    contexts: ContextMap<D::Session>,
    resource_bridge: Tube,
    mem: GuestMemory,
}

impl<D: DecoderBackend> Decoder<D> {
    /// Build a new decoder using the provided `backend`.
    pub fn new(backend: D, resource_bridge: Tube, mem: GuestMemory) -> Self {
        let capability = backend.get_capabilities();

        Self {
            decoder: backend,
            capability,
            contexts: Default::default(),
            resource_bridge,
            mem,
        }
    }

    /*
     * Functions processing virtio-video commands.
     */

    fn query_capabilities(&self, queue_type: QueueType) -> CmdResponse {
        let descs = match queue_type {
            QueueType::Input => self.capability.input_formats().clone(),
            QueueType::Output => self.capability.output_formats().clone(),
        };

        CmdResponse::QueryCapability(descs)
    }

    fn create_stream(
        &mut self,
        stream_id: StreamId,
        coded_format: Format,
        input_resource_type: ResourceType,
        output_resource_type: ResourceType,
    ) -> VideoResult<VideoCmdResponseType> {
        // Create an instance of `Context`.
        // Note that the `DecoderSession` will be created not here but at the first call of
        // `ResourceCreate`. This is because we need to fix a coded format for it, which
        // will be set by `SetParams`.
        self.contexts.insert(Context::new(
            stream_id,
            coded_format,
            input_resource_type,
            output_resource_type,
        ))?;
        Ok(VideoCmdResponseType::Sync(CmdResponse::NoData))
    }

    fn destroy_stream(&mut self, stream_id: StreamId) {
        if self.contexts.map.remove(&stream_id).is_none() {
            error!("Tried to destroy an invalid stream context {}", stream_id);
        }
    }

    fn create_session(
        decoder: &mut D,
        wait_ctx: &WaitContext<Token>,
        ctx: &Context<D::Session>,
        stream_id: StreamId,
    ) -> VideoResult<D::Session> {
        let format = match ctx.in_params.format {
            Some(f) => f,
            None => {
                error!("bitstream format is not specified");
                return Err(VideoError::InvalidParameter);
            }
        };

        let session = decoder.new_session(format)?;

        wait_ctx
            .add(session.event_pipe(), Token::Event { id: stream_id })
            .map_err(|e| {
                error!(
                    "failed to add FD to poll context for session {}: {}",
                    stream_id, e
                );
                VideoError::InvalidOperation
            })?;

        Ok(session)
    }

    fn create_resource(
        &mut self,
        wait_ctx: &WaitContext<Token>,
        stream_id: StreamId,
        queue_type: QueueType,
        resource_id: ResourceId,
        plane_offsets: Vec<u32>,
        plane_entries: Vec<Vec<UnresolvedResourceEntry>>,
    ) -> VideoResult<VideoCmdResponseType> {
        let ctx = self.contexts.get_mut(&stream_id)?;

        // Create a instance of `DecoderSession` at the first time `ResourceCreate` is
        // called here.
        if ctx.session.is_none() {
            ctx.session = Some(Self::create_session(
                &mut self.decoder,
                wait_ctx,
                ctx,
                stream_id,
            )?);
        }

        // We only support single-buffer resources for now.
        let entries = if plane_entries.len() != 1 {
            return Err(VideoError::InvalidArgument);
        } else {
            // unwrap() is safe because we just tested that `plane_entries` had exactly one element.
            plane_entries.get(0).unwrap()
        };

        // Now try to resolve our resource.
        let (resource_type, params) = match queue_type {
            QueueType::Input => (ctx.in_params.resource_type, &ctx.in_params),
            QueueType::Output => (ctx.out_params.resource_type, &ctx.out_params),
        };

        let resource = match resource_type {
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
                    params,
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
                params,
            )
            .map_err(|_| VideoError::InvalidArgument)?,
        };

        let offset = plane_offsets.get(0).copied().unwrap_or(0);
        ctx.register_resource(queue_type, resource_id, resource, offset);

        if queue_type == QueueType::Input {
            return Ok(VideoCmdResponseType::Sync(CmdResponse::NoData));
        };

        // We assume ResourceCreate is not called to an output resource that is already
        // imported to Chrome for now.
        // TODO(keiichiw): We need to support this case for a guest client who may use
        // arbitrary numbers of buffers. (e.g. C2V4L2Component in ARCVM)
        // Such a client is valid as long as it uses at most 32 buffers at the same time.
        if let Some(frame_buf_id) = ctx.out_res.res_id_to_frame_buf_id.get(&resource_id) {
            error!(
                "resource {} has already been imported to Chrome as a frame buffer {}",
                resource_id, frame_buf_id
            );
            return Err(VideoError::InvalidOperation);
        }

        Ok(VideoCmdResponseType::Sync(CmdResponse::NoData))
    }

    fn destroy_all_resources(
        &mut self,
        stream_id: StreamId,
        queue_type: QueueType,
    ) -> VideoResult<VideoCmdResponseType> {
        let ctx = self.contexts.get_mut(&stream_id)?;

        // Reset the associated context.
        match queue_type {
            QueueType::Input => {
                ctx.in_res = Default::default();
            }
            QueueType::Output => {
                ctx.out_res = Default::default();
            }
        }
        Ok(VideoCmdResponseType::Sync(CmdResponse::NoData))
    }

    fn queue_input_resource(
        &mut self,
        stream_id: StreamId,
        resource_id: ResourceId,
        timestamp: u64,
        data_sizes: Vec<u32>,
    ) -> VideoResult<VideoCmdResponseType> {
        let ctx = self.contexts.get_mut(&stream_id)?;

        if data_sizes.len() != 1 {
            error!("num_data_sizes must be 1 but {}", data_sizes.len());
            return Err(VideoError::InvalidOperation);
        }

        let session = ctx.session.as_mut().ok_or(VideoError::InvalidOperation)?;

        let InputResource { resource, offset } =
            ctx.in_res
                .get(&resource_id)
                .ok_or(VideoError::InvalidResourceId {
                    stream_id,
                    resource_id,
                })?;

        session.decode(
            resource_id,
            timestamp,
            resource
                .handle
                .try_clone()
                .map_err(|_| VideoError::InvalidParameter)?,
            *offset,
            data_sizes[0], // bytes_used
        )?;

        Ok(VideoCmdResponseType::Async(AsyncCmdTag::Queue {
            stream_id,
            queue_type: QueueType::Input,
            resource_id,
        }))
    }

    fn queue_output_resource(
        &mut self,
        stream_id: StreamId,
        resource_id: ResourceId,
    ) -> VideoResult<VideoCmdResponseType> {
        let ctx = self.contexts.get_mut(&stream_id)?;

        // Check if the current pixel format is set to NV12.
        match ctx.out_params.format {
            Some(Format::NV12) => (), // OK
            Some(f) => {
                error!(
                    "video decoder only supports NV12 as a frame format, got {}",
                    f
                );
                return Err(VideoError::InvalidOperation);
            }
            None => {
                error!("output format is not set");
                return Err(VideoError::InvalidOperation);
            }
        };

        match ctx.out_res.queue_resource(resource_id)? {
            QueueOutputResourceResult::UsingAsEos => {
                // Don't enqueue this resource to the host.
                Ok(())
            }
            QueueOutputResourceResult::Reused(buffer_id) => ctx
                .session
                .as_mut()
                .ok_or(VideoError::InvalidOperation)?
                .reuse_output_buffer(buffer_id),
            QueueOutputResourceResult::Registered(buffer_id) => {
                // Take full ownership of the output resource, since we will only import it once
                // into the backend.
                let resource = ctx
                    .out_res
                    .res_id_to_res_handle
                    .remove(&resource_id)
                    .ok_or(VideoError::InvalidResourceId {
                        stream_id,
                        resource_id,
                    })?;

                let session = ctx.session.as_mut().ok_or(VideoError::InvalidOperation)?;

                // Set output_buffer_count before passing the first output buffer.
                if ctx.out_res.output_params_set() {
                    const OUTPUT_BUFFER_COUNT: usize = 32;

                    // Set the buffer count to the maximum value.
                    // TODO(b/1518105): This is a hack due to the lack of way of telling a number of
                    // frame buffers explictly in virtio-video v3 RFC. Once we have the way,
                    // set_output_buffer_count should be called with a value passed by the guest.
                    session.set_output_parameters(OUTPUT_BUFFER_COUNT, Format::NV12)?;
                }

                session.use_output_buffer(buffer_id as i32, resource)
            }
        }?;
        Ok(VideoCmdResponseType::Async(AsyncCmdTag::Queue {
            stream_id,
            queue_type: QueueType::Output,
            resource_id,
        }))
    }

    fn get_params(
        &self,
        stream_id: StreamId,
        queue_type: QueueType,
        is_ext: bool,
    ) -> VideoResult<VideoCmdResponseType> {
        let ctx = self.contexts.get(&stream_id)?;
        let params = match queue_type {
            QueueType::Input => ctx.in_params.clone(),
            QueueType::Output => ctx.out_params.clone(),
        };
        Ok(VideoCmdResponseType::Sync(CmdResponse::GetParams {
            queue_type,
            params,
            is_ext,
        }))
    }

    fn set_params(
        &mut self,
        stream_id: StreamId,
        queue_type: QueueType,
        params: Params,
        is_ext: bool,
    ) -> VideoResult<VideoCmdResponseType> {
        let ctx = self.contexts.get_mut(&stream_id)?;
        match queue_type {
            QueueType::Input => {
                if ctx.session.is_some() {
                    error!("parameter for input cannot be changed once decoding started");
                    return Err(VideoError::InvalidParameter);
                }

                // Only a few parameters can be changed by the guest.
                ctx.in_params.format = params.format;
                ctx.in_params.plane_formats = params.plane_formats;
                // The resource type can only be changed through the SET_PARAMS_EXT command.
                if is_ext {
                    ctx.in_params.resource_type = params.resource_type;
                }
            }
            QueueType::Output => {
                // The guest can only change the resource type of the output queue if no resource
                // has been imported yet.
                if ctx.out_res.output_params_set {
                    error!("parameter for output cannot be changed once resources are imported");
                    return Err(VideoError::InvalidParameter);
                }
                if is_ext {
                    ctx.out_params.resource_type = params.resource_type;
                }
            }
        };
        Ok(VideoCmdResponseType::Sync(CmdResponse::NoData))
    }

    fn query_control(&self, ctrl_type: QueryCtrlType) -> VideoResult<VideoCmdResponseType> {
        match self.capability.query_control(&ctrl_type) {
            Some(resp) => Ok(VideoCmdResponseType::Sync(CmdResponse::QueryControl(resp))),
            None => {
                error!("querying an unsupported control: {:?}", ctrl_type);
                Err(VideoError::InvalidArgument)
            }
        }
    }

    fn get_control(
        &self,
        stream_id: StreamId,
        ctrl_type: CtrlType,
    ) -> VideoResult<VideoCmdResponseType> {
        let ctx = self.contexts.get(&stream_id)?;
        match ctrl_type {
            CtrlType::Profile => {
                let profile = match ctx.in_params.format {
                    Some(Format::VP8) => Profile::VP8Profile0,
                    Some(Format::VP9) => Profile::VP9Profile0,
                    Some(Format::H264) => Profile::H264Baseline,
                    Some(Format::Hevc) => Profile::HevcMain,
                    Some(f) => {
                        error!("specified format is invalid: {}", f);
                        return Err(VideoError::InvalidArgument);
                    }
                    None => {
                        error!("bitstream format is not set");
                        return Err(VideoError::InvalidArgument);
                    }
                };

                Ok(CtrlVal::Profile(profile))
            }
            CtrlType::Level => {
                let level = match ctx.in_params.format {
                    Some(Format::H264) => Level::H264_1_0,
                    Some(f) => {
                        error!("specified format has no level: {}", f);
                        return Err(VideoError::InvalidArgument);
                    }
                    None => {
                        error!("bitstream format is not set");
                        return Err(VideoError::InvalidArgument);
                    }
                };

                Ok(CtrlVal::Level(level))
            }
            t => {
                error!("cannot get a control value: {:?}", t);
                Err(VideoError::InvalidArgument)
            }
        }
        .map(|ctrl_val| VideoCmdResponseType::Sync(CmdResponse::GetControl(ctrl_val)))
    }

    fn drain_stream(&mut self, stream_id: StreamId) -> VideoResult<VideoCmdResponseType> {
        self.contexts
            .get_mut(&stream_id)?
            .session
            .as_mut()
            .ok_or(VideoError::InvalidOperation)?
            .flush()?;
        Ok(VideoCmdResponseType::Async(AsyncCmdTag::Drain {
            stream_id,
        }))
    }

    fn clear_queue(
        &mut self,
        stream_id: StreamId,
        queue_type: QueueType,
    ) -> VideoResult<VideoCmdResponseType> {
        let ctx = self.contexts.get_mut(&stream_id)?;

        // TODO(b/153406792): Though QUEUE_CLEAR is defined as a per-queue command in the
        // specification, the VDA's `Reset()` clears the input buffers and may (or may not) drop
        // output buffers. So, we call it only for input and resets only the crosvm's internal
        // context for output.
        // This code can be a problem when a guest application wants to reset only one queue by
        // REQBUFS(0). To handle this problem correctly, we need to make libvda expose
        // DismissPictureBuffer() method.
        match queue_type {
            QueueType::Input => {
                if let Some(session) = ctx.session.as_mut() {
                    session.reset()?;
                    ctx.is_resetting = true;
                    ctx.pending_responses.clear();
                    Ok(VideoCmdResponseType::Async(AsyncCmdTag::Clear {
                        stream_id,
                        queue_type: QueueType::Input,
                    }))
                } else {
                    Ok(VideoCmdResponseType::Sync(CmdResponse::NoData))
                }
            }
            QueueType::Output => {
                if let Some(session) = ctx.session.as_mut() {
                    session.clear_output_buffers()?;
                    ctx.out_res.queued_res_ids.clear();
                }
                Ok(VideoCmdResponseType::Sync(CmdResponse::NoData))
            }
        }
    }
}

impl<D: DecoderBackend> Device for Decoder<D> {
    fn process_cmd(
        &mut self,
        cmd: VideoCmd,
        wait_ctx: &WaitContext<Token>,
    ) -> (
        VideoCmdResponseType,
        Option<(u32, Vec<VideoEvtResponseType>)>,
    ) {
        use VideoCmd::*;
        use VideoCmdResponseType::Sync;

        let mut event_ret = None;
        let cmd_response = match cmd {
            QueryCapability { queue_type } => Ok(Sync(self.query_capabilities(queue_type))),
            StreamCreate {
                stream_id,
                coded_format,
                input_resource_type,
                output_resource_type,
            } => self.create_stream(
                stream_id,
                coded_format,
                input_resource_type,
                output_resource_type,
            ),
            StreamDestroy { stream_id } => {
                self.destroy_stream(stream_id);
                Ok(Sync(CmdResponse::NoData))
            }
            ResourceCreate {
                stream_id,
                queue_type,
                resource_id,
                plane_offsets,
                plane_entries,
            } => self.create_resource(
                wait_ctx,
                stream_id,
                queue_type,
                resource_id,
                plane_offsets,
                plane_entries,
            ),
            ResourceDestroyAll {
                stream_id,
                queue_type,
            } => self.destroy_all_resources(stream_id, queue_type),
            ResourceQueue {
                stream_id,
                queue_type: QueueType::Input,
                resource_id,
                timestamp,
                data_sizes,
            } => self.queue_input_resource(stream_id, resource_id, timestamp, data_sizes),
            ResourceQueue {
                stream_id,
                queue_type: QueueType::Output,
                resource_id,
                ..
            } => {
                let resp = self.queue_output_resource(stream_id, resource_id);
                if resp.is_ok() {
                    if let Ok(ctx) = self.contexts.get_mut(&stream_id) {
                        event_ret = Some((stream_id, ctx.output_pending_responses()));
                    }
                }
                resp
            }
            GetParams {
                stream_id,
                queue_type,
                is_ext,
            } => self.get_params(stream_id, queue_type, is_ext),
            SetParams {
                stream_id,
                queue_type,
                params,
                is_ext,
            } => self.set_params(stream_id, queue_type, params, is_ext),
            QueryControl { query_ctrl_type } => self.query_control(query_ctrl_type),
            GetControl {
                stream_id,
                ctrl_type,
            } => self.get_control(stream_id, ctrl_type),
            SetControl { .. } => {
                error!("SET_CONTROL is not allowed for decoder");
                Err(VideoError::InvalidOperation)
            }
            StreamDrain { stream_id } => self.drain_stream(stream_id),
            QueueClear {
                stream_id,
                queue_type,
            } => self.clear_queue(stream_id, queue_type),
        };

        let cmd_ret = match cmd_response {
            Ok(r) => r,
            Err(e) => {
                error!("returning error response: {}", &e);
                Sync(e.into())
            }
        };
        (cmd_ret, event_ret)
    }

    fn process_event(
        &mut self,
        desc_map: &mut AsyncCmdDescMap,
        stream_id: u32,
    ) -> Option<Vec<VideoEvtResponseType>> {
        // TODO(b/161774071): Switch the return value from Option to VideoResult or another
        // result that would allow us to return an error to the caller.

        use crate::virtio::video::device::VideoEvtResponseType::*;

        let ctx = match self.contexts.get_mut(&stream_id) {
            Ok(ctx) => ctx,
            Err(e) => {
                error!("failed to get a context for session {}: {}", stream_id, e);
                return None;
            }
        };

        let session = match ctx.session.as_mut() {
            Some(s) => s,
            None => {
                error!("session not yet created for context {}", stream_id);
                return None;
            }
        };

        let event = match session.read_event() {
            Ok(event) => event,
            Err(e) => {
                error!("failed to read an event from session {}: {}", stream_id, e);
                return None;
            }
        };

        let event_responses = match event {
            DecoderEvent::ProvidePictureBuffers {
                min_num_buffers,
                width,
                height,
                visible_rect,
            } => {
                ctx.handle_provide_picture_buffers(min_num_buffers, width, height, visible_rect);
                vec![Event(VideoEvt {
                    typ: EvtType::DecResChanged,
                    stream_id,
                })]
            }
            DecoderEvent::PictureReady {
                picture_buffer_id,
                timestamp,
                ..
            } => {
                if ctx.is_resetting {
                    vec![]
                } else {
                    ctx.pending_responses
                        .push_back(PendingResponse::PictureReady {
                            picture_buffer_id,
                            timestamp,
                        });
                    ctx.output_pending_responses()
                }
            }
            DecoderEvent::NotifyEndOfBitstreamBuffer(resource_id) => {
                let async_response = AsyncCmdResponse::from_response(
                    AsyncCmdTag::Queue {
                        stream_id,
                        queue_type: QueueType::Input,
                        resource_id,
                    },
                    CmdResponse::ResourceQueue {
                        timestamp: 0, // ignored for bitstream buffers.
                        flags: 0,     // no flag is raised, as it's returned successfully.
                        size: 0,      // this field is only for encoder
                    },
                );
                vec![AsyncCmd(async_response)]
            }
            DecoderEvent::FlushCompleted(flush_result) => {
                match flush_result {
                    Ok(()) => {
                        ctx.pending_responses
                            .push_back(PendingResponse::FlushCompleted);
                        ctx.output_pending_responses()
                    }
                    Err(error) => {
                        // TODO(b/151810591): If `resp` is `libvda::decode::Response::Canceled`,
                        // we should notify it to the driver in some way.
                        error!(
                            "failed to 'Flush' in VDA (stream id {}): {:?}",
                            stream_id, error
                        );
                        vec![AsyncCmd(AsyncCmdResponse::from_error(
                            AsyncCmdTag::Drain { stream_id },
                            error,
                        ))]
                    }
                }
            }
            DecoderEvent::ResetCompleted(reset_result) => {
                ctx.is_resetting = false;
                let tag = AsyncCmdTag::Clear {
                    stream_id,
                    queue_type: QueueType::Input,
                };
                match reset_result {
                    Ok(()) => {
                        let mut responses: Vec<_> = desc_map
                            .create_cancellation_responses(
                                &stream_id,
                                Some(QueueType::Input),
                                Some(tag),
                            )
                            .into_iter()
                            .map(AsyncCmd)
                            .collect();
                        responses.push(AsyncCmd(AsyncCmdResponse::from_response(
                            tag,
                            CmdResponse::NoData,
                        )));
                        responses
                    }
                    Err(error) => {
                        error!(
                            "failed to 'Reset' in VDA (stream id {}): {:?}",
                            stream_id, error
                        );
                        vec![AsyncCmd(AsyncCmdResponse::from_error(tag, error))]
                    }
                }
            }
            DecoderEvent::NotifyError(error) => {
                error!("an error is notified by VDA: {}", error);
                vec![Event(VideoEvt {
                    typ: EvtType::Error,
                    stream_id,
                })]
            }
        };

        Some(event_responses)
    }
}

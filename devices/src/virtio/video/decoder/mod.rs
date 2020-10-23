// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implementation of a virtio video decoder device backed by LibVDA.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryInto;
use std::os::unix::io::IntoRawFd;

use base::{error, PollContext};

use crate::virtio::resource_bridge::{self, ResourceInfo, ResourceRequestSocket};
use crate::virtio::video::async_cmd_desc_map::AsyncCmdDescMap;
use crate::virtio::video::command::{QueueType, VideoCmd};
use crate::virtio::video::control::{CtrlType, CtrlVal, QueryCtrlResponse, QueryCtrlType};
use crate::virtio::video::device::*;
use crate::virtio::video::error::*;
use crate::virtio::video::event::*;
use crate::virtio::video::format::*;
use crate::virtio::video::params::Params;
use crate::virtio::video::protocol;
use crate::virtio::video::response::CmdResponse;

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

type ResourceHandle = u32;
type Timestamp = u64;

// The result of OutputResources.queue_resource().
enum QueueOutputResourceResult {
    UsingAsEos,                // The resource is kept as EOS buffer.
    Reused(FrameBufferId),     // The resource has been registered before.
    Registered(FrameBufferId), // The resource is queued first time.
}

#[derive(Default)]
struct InputResources {
    // Timestamp -> InputResourceId
    timestamp_to_res_id: BTreeMap<Timestamp, InputResourceId>,

    // InputResourceId -> ResourceHandle
    res_id_to_res_handle: BTreeMap<InputResourceId, ResourceHandle>,
}

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

    // This is a flag that shows whether libvda's set_output_buffer_count is called.
    // This will be set to true when ResourceCreate for OutputBuffer is called for the first time.
    //
    // TODO(b/1518105): This field is added as a hack because the current virtio-video v3 spec
    // doesn't have a way to send a number of frame buffers the guest provides.
    // Once we have the way in the virtio-video protocol, we should remove this flag.
    is_output_buffer_count_set: bool,

    // OutputResourceId -> ResourceHandle
    res_id_to_res_handle: BTreeMap<OutputResourceId, ResourceHandle>,
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

    fn set_output_buffer_count(&mut self) -> bool {
        if !self.is_output_buffer_count_set {
            self.is_output_buffer_count_set = true;
            return true;
        }
        false
    }
}

// Context is associated with one `libvda::Session`, which corresponds to one stream from the
// virtio-video's point of view.
#[derive(Default)]
struct Context {
    stream_id: StreamId,

    in_params: Params,
    out_params: Params,

    in_res: InputResources,
    out_res: OutputResources,
}

impl Context {
    fn new(stream_id: StreamId, format: Format) -> Self {
        Context {
            stream_id,
            in_params: Params {
                format: Some(format),
                min_buffers: 2,
                max_buffers: 32,
                plane_formats: vec![Default::default()],
                ..Default::default()
            },
            out_params: Default::default(),
            ..Default::default()
        }
    }

    fn get_resource_info(
        &self,
        queue_type: QueueType,
        res_bridge: &ResourceRequestSocket,
        resource_id: u32,
    ) -> VideoResult<ResourceInfo> {
        let res_id_to_res_handle = match queue_type {
            QueueType::Input => &self.in_res.res_id_to_res_handle,
            QueueType::Output => &self.out_res.res_id_to_res_handle,
        };

        let handle = res_id_to_res_handle.get(&resource_id).copied().ok_or(
            VideoError::InvalidResourceId {
                stream_id: self.stream_id,
                resource_id,
            },
        )?;
        resource_bridge::get_resource_info(res_bridge, handle)
            .map_err(VideoError::ResourceBridgeFailure)
    }

    fn register_buffer(&mut self, queue_type: QueueType, resource_id: u32, uuid: &u128) {
        // TODO(stevensd): `Virtio3DBackend::resource_assign_uuid` is currently implemented to use
        // 32-bits resource_handles as UUIDs. Once it starts using real UUIDs, we need to update
        // this conversion.
        let handle = TryInto::<u32>::try_into(*uuid).expect("uuid is larger than 32 bits");
        let res_id_to_res_handle = match queue_type {
            QueueType::Input => &mut self.in_res.res_id_to_res_handle,
            QueueType::Output => &mut self.out_res.res_id_to_res_handle,
        };
        res_id_to_res_handle.insert(resource_id, handle);
    }

    /*
     * Functions handling libvda events.
     */

    fn handle_provide_picture_buffers(
        &mut self,
        min_num_buffers: u32,
        width: i32,
        height: i32,
        visible_rect_left: i32,
        visible_rect_top: i32,
        visible_rect_right: i32,
        visible_rect_bottom: i32,
    ) {
        // We only support NV12.
        let format = Some(Format::NV12);

        let rect_width: u32 = (visible_rect_right - visible_rect_left) as u32;
        let rect_height: u32 = (visible_rect_bottom - visible_rect_top) as u32;

        let plane_size = rect_width * rect_height;
        let stride = rect_width;
        let plane_formats = vec![
            PlaneFormat { plane_size, stride },
            PlaneFormat { plane_size, stride },
        ];

        self.out_params = Params {
            format,
            // Note that rect_width is sometimes smaller.
            frame_width: width as u32,
            frame_height: height as u32,
            // Adding 1 to `min_buffers` to reserve a resource for `eos_resource_id`.
            min_buffers: min_num_buffers + 1,
            max_buffers: 32,
            crop: Crop {
                left: visible_rect_left as u32,
                top: visible_rect_top as u32,
                width: rect_width,
                height: rect_height,
            },
            plane_formats,
            // No need to set `frame_rate`, as it's only for the encoder.
            ..Default::default()
        };
    }

    fn handle_picture_ready(
        &mut self,
        buffer_id: FrameBufferId,
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
    ) -> Option<ResourceId> {
        let plane_size = ((right - left) * (bottom - top)) as u32;
        for fmt in self.out_params.plane_formats.iter_mut() {
            fmt.plane_size = plane_size;
            // We don't need to set `plane_formats[i].stride` for the decoder.
        }

        self.out_res.dequeue_frame_buffer(buffer_id, self.stream_id)
    }

    fn handle_notify_end_of_bitstream_buffer(&mut self, bitstream_id: i32) -> Option<ResourceId> {
        // `bitstream_id` in libvda is a timestamp passed via RESOURCE_QUEUE for the input buffer
        // in second.
        let timestamp: u64 = (bitstream_id as u64) * 1_000_000_000;
        self.in_res
            .timestamp_to_res_id
            .remove(&(timestamp as u64))
            .or_else(|| {
                error!("failed to remove a timestamp {}", timestamp);
                None
            })
    }
}

/// A thin wrapper of a map of contexts with error handlings.
#[derive(Default)]
struct ContextMap {
    map: BTreeMap<StreamId, Context>,
}

impl ContextMap {
    fn insert(&mut self, ctx: Context) -> VideoResult<()> {
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

    fn get(&self, stream_id: &StreamId) -> VideoResult<&Context> {
        self.map.get(stream_id).ok_or_else(|| {
            error!("failed to get context of stream {}", *stream_id);
            VideoError::InvalidStreamId(*stream_id)
        })
    }

    fn get_mut(&mut self, stream_id: &StreamId) -> VideoResult<&mut Context> {
        self.map.get_mut(stream_id).ok_or_else(|| {
            error!("failed to get context of stream {}", *stream_id);
            VideoError::InvalidStreamId(*stream_id)
        })
    }
}

/// A thin wrapper of a map of libvda sesssions with error handlings.
#[derive(Default)]
struct SessionMap<'a> {
    map: BTreeMap<u32, libvda::decode::Session<'a>>,
}

impl<'a> SessionMap<'a> {
    fn contains_key(&self, stream_id: StreamId) -> bool {
        self.map.contains_key(&stream_id)
    }

    fn get(&self, stream_id: &StreamId) -> VideoResult<&libvda::decode::Session<'a>> {
        self.map.get(&stream_id).ok_or_else(|| {
            error!("failed to get libvda session {}", *stream_id);
            VideoError::InvalidStreamId(*stream_id)
        })
    }

    fn get_mut(&mut self, stream_id: &StreamId) -> VideoResult<&mut libvda::decode::Session<'a>> {
        self.map.get_mut(&stream_id).ok_or_else(|| {
            error!("failed to get libvda session {}", *stream_id);
            VideoError::InvalidStreamId(*stream_id)
        })
    }

    fn insert(
        &mut self,
        stream_id: StreamId,
        session: libvda::decode::Session<'a>,
    ) -> Option<libvda::decode::Session<'a>> {
        self.map.insert(stream_id, session)
    }
}

/// Represents information of a decoder backed with `libvda`.
pub struct Decoder<'a> {
    vda: &'a libvda::decode::VdaInstance,
    capability: Capability,
    contexts: ContextMap,
    sessions: SessionMap<'a>,
}

impl<'a> Decoder<'a> {
    pub fn new(vda: &'a libvda::decode::VdaInstance) -> Self {
        let capability = Capability::new(vda.get_capabilities());
        Decoder {
            vda,
            capability,
            contexts: Default::default(),
            sessions: Default::default(),
        }
    }

    /*
     * Functions processing virtio-video commands.
     */

    fn query_capabilities(&self, queue_type: QueueType) -> CmdResponse {
        let descs = match queue_type {
            QueueType::Input => self.capability.in_fmts.clone(),
            QueueType::Output => self.capability.out_fmts.clone(),
        };

        CmdResponse::QueryCapability(descs)
    }

    fn create_stream(&mut self, stream_id: StreamId, coded_format: Format) -> VideoResult<()> {
        // Create an instance of `Context`.
        // Note that `libvda::Session` will be created not here but at the first call of
        // `ResourceCreate`. This is because we need to fix a coded format for it, which
        // will be set by `SetParams`.
        self.contexts.insert(Context::new(stream_id, coded_format))
    }

    fn destroy_stream(&mut self, stream_id: StreamId) {
        if self.contexts.map.remove(&stream_id).is_none() {
            error!("Tried to destroy an invalid stream context {}", stream_id);
        }

        // Close a libVDA session, as closing will be done in `Drop` for `session`.
        // Note that `sessions` doesn't have an instance for `stream_id` if the
        // first `ResourceCreate` haven't been called yet.
        self.sessions.map.remove(&stream_id);
    }

    fn create_session(
        vda: &'a libvda::decode::VdaInstance,
        poll_ctx: &PollContext<Token>,
        ctx: &Context,
        stream_id: StreamId,
    ) -> VideoResult<libvda::decode::Session<'a>> {
        let profile = match ctx.in_params.format {
            Some(Format::VP8) => Ok(libvda::Profile::VP8),
            Some(Format::VP9) => Ok(libvda::Profile::VP9Profile0),
            Some(Format::H264) => Ok(libvda::Profile::H264ProfileBaseline),
            Some(f) => {
                error!("specified format is invalid for bitstream: {}", f);
                Err(VideoError::InvalidParameter)
            }
            None => {
                error!("bitstream format is not specified");
                Err(VideoError::InvalidParameter)
            }
        }?;

        let session = vda.open_session(profile).map_err(|e| {
            error!(
                "failed to open a session {} for {:?}: {}",
                stream_id, profile, e
            );
            VideoError::InvalidOperation
        })?;

        poll_ctx
            .add(session.pipe(), Token::Event { id: stream_id })
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
        poll_ctx: &PollContext<Token>,
        stream_id: StreamId,
        queue_type: QueueType,
        resource_id: ResourceId,
        uuid: u128,
    ) -> VideoResult<()> {
        let ctx = self.contexts.get_mut(&stream_id)?;

        // Create a instance of `libvda::Session` at the first time `ResourceCreate` is
        // called here.
        if !self.sessions.contains_key(stream_id) {
            let session = Self::create_session(self.vda, poll_ctx, ctx, stream_id)?;
            self.sessions.insert(stream_id, session);
        }

        ctx.register_buffer(queue_type, resource_id, &uuid);

        if queue_type == QueueType::Input {
            return Ok(());
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

        Ok(())
    }

    fn destroy_all_resources(
        &mut self,
        stream_id: StreamId,
        queue_type: QueueType,
    ) -> VideoResult<()> {
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
        Ok(())
    }

    fn queue_input_resource(
        &mut self,
        resource_bridge: &ResourceRequestSocket,
        stream_id: StreamId,
        resource_id: ResourceId,
        timestamp: u64,
        data_sizes: Vec<u32>,
    ) -> VideoResult<()> {
        let session = self.sessions.get(&stream_id)?;
        let ctx = self.contexts.get_mut(&stream_id)?;

        if data_sizes.len() != 1 {
            error!("num_data_sizes must be 1 but {}", data_sizes.len());
            return Err(VideoError::InvalidOperation);
        }

        // Take an ownership of this file by `into_raw_fd()` as this file will be closed by libvda.
        let fd = ctx
            .get_resource_info(QueueType::Input, resource_bridge, resource_id)?
            .file
            .into_raw_fd();

        // Register a mapping of timestamp to resource_id
        if let Some(old_resource_id) = ctx
            .in_res
            .timestamp_to_res_id
            .insert(timestamp, resource_id)
        {
            error!(
                "Mapping from timestamp {} to resource_id ({} => {}) exists!",
                timestamp, old_resource_id, resource_id
            );
        }

        // While the virtio-video driver handles timestamps as nanoseconds,
        // Chrome assumes per-second timestamps coming. So, we need a conversion from nsec
        // to sec.
        // Note that this value should not be an unix time stamp but a frame number that
        // a guest passes to a driver as a 32-bit integer in our implementation.
        // So, overflow must not happen in this conversion.
        let ts_sec: i32 = (timestamp / 1_000_000_000) as i32;
        session
            .decode(
                ts_sec,
                fd,            // fd
                0,             // offset is always 0 due to the driver implementation.
                data_sizes[0], // bytes_used
            )
            .map_err(VideoError::VdaError)?;

        Ok(())
    }

    fn queue_output_resource(
        &mut self,
        resource_bridge: &ResourceRequestSocket,
        stream_id: StreamId,
        resource_id: ResourceId,
    ) -> VideoResult<()> {
        let session = self.sessions.get(&stream_id)?;
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
            QueueOutputResourceResult::Reused(buffer_id) => session
                .reuse_output_buffer(buffer_id)
                .map_err(VideoError::VdaError),
            QueueOutputResourceResult::Registered(buffer_id) => {
                let resource_info =
                    ctx.get_resource_info(QueueType::Output, resource_bridge, resource_id)?;
                let planes = vec![
                    libvda::FramePlane {
                        offset: resource_info.planes[0].offset as i32,
                        stride: resource_info.planes[0].stride as i32,
                    },
                    libvda::FramePlane {
                        offset: resource_info.planes[1].offset as i32,
                        stride: resource_info.planes[1].stride as i32,
                    },
                ];

                // Set output_buffer_count before passing the first output buffer.
                if ctx.out_res.set_output_buffer_count() {
                    const OUTPUT_BUFFER_COUNT: usize = 32;

                    // Set the buffer count to the maximum value.
                    // TODO(b/1518105): This is a hack due to the lack of way of telling a number of
                    // frame buffers explictly in virtio-video v3 RFC. Once we have the way,
                    // set_output_buffer_count should be called with a value passed by the guest.
                    session
                        .set_output_buffer_count(OUTPUT_BUFFER_COUNT)
                        .map_err(VideoError::VdaError)?;
                }

                // Take ownership of this file by `into_raw_fd()` as this
                // file will be closed by libvda.
                let fd = resource_info.file.into_raw_fd();
                session
                    .use_output_buffer(buffer_id as i32, libvda::PixelFormat::NV12, fd, &planes)
                    .map_err(VideoError::VdaError)
            }
        }
    }

    fn get_params(&self, stream_id: StreamId, queue_type: QueueType) -> VideoResult<Params> {
        let ctx = self.contexts.get(&stream_id)?;
        Ok(match queue_type {
            QueueType::Input => ctx.in_params.clone(),
            QueueType::Output => ctx.out_params.clone(),
        })
    }

    fn set_params(
        &mut self,
        stream_id: StreamId,
        queue_type: QueueType,
        params: Params,
    ) -> VideoResult<()> {
        let ctx = self.contexts.get_mut(&stream_id)?;
        match queue_type {
            QueueType::Input => {
                if self.sessions.contains_key(stream_id) {
                    error!("parameter for input cannot be changed once decoding started");
                    return Err(VideoError::InvalidParameter);
                }

                // Only a few parameters can be changed by the guest.
                ctx.in_params.format = params.format;
                ctx.in_params.plane_formats = params.plane_formats;
            }
            QueueType::Output => {
                // The guest cannot update parameters for output queue in the decoder.
            }
        };
        Ok(())
    }

    fn query_control(&self, ctrl_type: QueryCtrlType) -> VideoResult<QueryCtrlResponse> {
        self.capability.query_control(&ctrl_type).ok_or_else(|| {
            error!("querying an unsupported control: {:?}", ctrl_type);
            VideoError::InvalidArgument
        })
    }

    fn get_control(&self, stream_id: StreamId, ctrl_type: CtrlType) -> VideoResult<CtrlVal> {
        let ctx = self.contexts.get(&stream_id)?;
        match ctrl_type {
            CtrlType::Profile => {
                let profile = match ctx.in_params.format {
                    Some(Format::VP8) => Profile::VP8Profile0,
                    Some(Format::VP9) => Profile::VP9Profile0,
                    Some(Format::H264) => Profile::H264Baseline,
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
    }

    fn drain_stream(&mut self, stream_id: StreamId) -> VideoResult<()> {
        self.sessions
            .get(&stream_id)?
            .flush()
            .map_err(VideoError::VdaError)?;
        Ok(())
    }

    fn clear_queue(&mut self, stream_id: StreamId, queue_type: QueueType) -> VideoResult<()> {
        let ctx = self.contexts.get_mut(&stream_id)?;
        let session = self.sessions.get(&stream_id)?;

        // TODO(b/153406792): Though QUEUE_CLEAR is defined as a per-queue command in the
        // specification, the VDA's `Reset()` clears the input buffers and may (or may not) drop
        // output buffers. So, we call it only for input and resets only the crosvm's internal
        // context for output.
        // This code can be a problem when a guest application wants to reset only one queue by
        // REQBUFS(0). To handle this problem correctly, we need to make libvda expose
        // DismissPictureBuffer() method.
        match queue_type {
            QueueType::Input => {
                session.reset().map_err(VideoError::VdaError)?;
            }
            QueueType::Output => {
                ctx.out_res = Default::default();
            }
        }
        Ok(())
    }
}

impl<'a> Device for Decoder<'a> {
    fn process_cmd(
        &mut self,
        cmd: VideoCmd,
        poll_ctx: &PollContext<Token>,
        resource_bridge: &ResourceRequestSocket,
    ) -> VideoResult<VideoCmdResponseType> {
        use VideoCmd::*;
        use VideoCmdResponseType::{Async, Sync};

        match cmd {
            QueryCapability { queue_type } => Ok(Sync(self.query_capabilities(queue_type))),
            StreamCreate {
                stream_id,
                coded_format,
            } => {
                self.create_stream(stream_id, coded_format)?;
                Ok(Sync(CmdResponse::NoData))
            }
            StreamDestroy { stream_id } => {
                self.destroy_stream(stream_id);
                Ok(Sync(CmdResponse::NoData))
            }
            ResourceCreate {
                stream_id,
                queue_type,
                resource_id,
                uuid,
                // ignore `plane_offsets` as we use `resource_info` given by `resource_bridge` instead.
                ..
            } => {
                self.create_resource(poll_ctx, stream_id, queue_type, resource_id, uuid)?;
                Ok(Sync(CmdResponse::NoData))
            }
            ResourceDestroyAll {
                stream_id,
                queue_type,
            } => {
                self.destroy_all_resources(stream_id, queue_type)?;
                Ok(Sync(CmdResponse::NoData))
            }
            ResourceQueue {
                stream_id,
                queue_type: QueueType::Input,
                resource_id,
                timestamp,
                data_sizes,
            } => {
                self.queue_input_resource(
                    resource_bridge,
                    stream_id,
                    resource_id,
                    timestamp,
                    data_sizes,
                )?;
                Ok(Async(AsyncCmdTag::Queue {
                    stream_id,
                    queue_type: QueueType::Input,
                    resource_id,
                }))
            }
            ResourceQueue {
                stream_id,
                queue_type: QueueType::Output,
                resource_id,
                ..
            } => {
                self.queue_output_resource(resource_bridge, stream_id, resource_id)?;
                Ok(Async(AsyncCmdTag::Queue {
                    stream_id,
                    queue_type: QueueType::Output,
                    resource_id,
                }))
            }
            GetParams {
                stream_id,
                queue_type,
            } => {
                let params = self.get_params(stream_id, queue_type)?;
                Ok(Sync(CmdResponse::GetParams { queue_type, params }))
            }
            SetParams {
                stream_id,
                queue_type,
                params,
            } => {
                self.set_params(stream_id, queue_type, params)?;
                Ok(Sync(CmdResponse::NoData))
            }
            QueryControl { query_ctrl_type } => {
                let resp = self.query_control(query_ctrl_type)?;
                Ok(Sync(CmdResponse::QueryControl(resp)))
            }
            GetControl {
                stream_id,
                ctrl_type,
            } => {
                let ctrl_val = self.get_control(stream_id, ctrl_type)?;
                Ok(Sync(CmdResponse::GetControl(ctrl_val)))
            }
            SetControl { .. } => {
                error!("SET_CONTROL is not allowed for decoder");
                Err(VideoError::InvalidOperation)
            }
            StreamDrain { stream_id } => {
                self.drain_stream(stream_id)?;
                Ok(Async(AsyncCmdTag::Drain { stream_id }))
            }
            QueueClear {
                stream_id,
                queue_type,
            } => {
                self.clear_queue(stream_id, queue_type)?;
                Ok(match queue_type {
                    QueueType::Input => Async(AsyncCmdTag::Clear {
                        stream_id,
                        queue_type: QueueType::Input,
                    }),
                    QueueType::Output => Sync(CmdResponse::NoData),
                })
            }
        }
    }

    fn process_event(
        &mut self,
        desc_map: &mut AsyncCmdDescMap,
        stream_id: u32,
    ) -> Option<Vec<VideoEvtResponseType>> {
        // TODO(b/161774071): Switch the return value from Option to VideoResult or another
        // result that would allow us to return an error to the caller.

        use crate::virtio::video::device::VideoEvtResponseType::*;
        use libvda::decode::Event::*;

        let session = match self.sessions.get_mut(&stream_id) {
            Ok(s) => s,
            Err(e) => {
                error!(
                    "an event notified for an unknown session {}: {}",
                    stream_id, e
                );
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

        let ctx = match self.contexts.get_mut(&stream_id) {
            Ok(ctx) => ctx,
            Err(_) => {
                error!(
                    "failed to get a context for session {}: {:?}",
                    stream_id, event
                );
                return None;
            }
        };

        let event_responses = match event {
            ProvidePictureBuffers {
                min_num_buffers,
                width,
                height,
                visible_rect_left,
                visible_rect_top,
                visible_rect_right,
                visible_rect_bottom,
            } => {
                ctx.handle_provide_picture_buffers(
                    min_num_buffers,
                    width,
                    height,
                    visible_rect_left,
                    visible_rect_top,
                    visible_rect_right,
                    visible_rect_bottom,
                );
                vec![Event(VideoEvt {
                    typ: EvtType::DecResChanged,
                    stream_id,
                })]
            }
            PictureReady {
                buffer_id, // FrameBufferId
                bitstream_id: ts_sec,
                left,
                top,
                right,
                bottom,
            } => {
                let resource_id = ctx.handle_picture_ready(buffer_id, left, top, right, bottom)?;
                let async_response = AsyncCmdResponse::from_response(
                    AsyncCmdTag::Queue {
                        stream_id,
                        queue_type: QueueType::Output,
                        resource_id,
                    },
                    CmdResponse::ResourceQueue {
                        // Conversion from sec to nsec.
                        timestamp: (ts_sec as u64) * 1_000_000_000,
                        // TODO(b/149725148): Set buffer flags once libvda exposes them.
                        flags: 0,
                        // `size` is only used for the encoder.
                        size: 0,
                    },
                );
                vec![AsyncCmd(async_response)]
            }
            NotifyEndOfBitstreamBuffer { bitstream_id } => {
                let resource_id = ctx.handle_notify_end_of_bitstream_buffer(bitstream_id)?;
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
            FlushResponse(flush_response) => {
                match flush_response {
                    libvda::decode::Response::Success => {
                        let eos_resource_id = match ctx.out_res.dequeue_eos_resource_id() {
                            Some(r) => r,
                            None => {
                                // TODO(b/168750131): Instead of trigger error, we should wait for
                                // the next output buffer enqueued, then dequeue the buffer with
                                // EOS flag.
                                error!(
                                    "No EOS resource available on successful flush response (stream id {})",
                                    stream_id);
                                return Some(vec![Event(VideoEvt {
                                    typ: EvtType::Error,
                                    stream_id,
                                })]);
                            }
                        };

                        let eos_tag = AsyncCmdTag::Queue {
                            stream_id,
                            queue_type: QueueType::Output,
                            resource_id: eos_resource_id,
                        };

                        let eos_response = CmdResponse::ResourceQueue {
                            timestamp: 0,
                            flags: protocol::VIRTIO_VIDEO_BUFFER_FLAG_EOS,
                            size: 0,
                        };
                        vec![
                            AsyncCmd(AsyncCmdResponse::from_response(eos_tag, eos_response)),
                            AsyncCmd(AsyncCmdResponse::from_response(
                                AsyncCmdTag::Drain { stream_id },
                                CmdResponse::NoData,
                            )),
                        ]
                    }
                    _ => {
                        // TODO(b/151810591): If `resp` is `libvda::decode::Response::Canceled`,
                        // we should notify it to the driver in some way.
                        error!(
                            "failed to 'Flush' in VDA (stream id {}): {:?}",
                            stream_id, flush_response
                        );
                        vec![AsyncCmd(AsyncCmdResponse::from_error(
                            AsyncCmdTag::Drain { stream_id },
                            VideoError::VdaFailure(flush_response),
                        ))]
                    }
                }
            }
            ResetResponse(reset_response) => {
                let tag = AsyncCmdTag::Clear {
                    stream_id,
                    queue_type: QueueType::Input,
                };
                match reset_response {
                    libvda::decode::Response::Success => {
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
                    _ => {
                        error!(
                            "failed to 'Reset' in VDA (stream id {}): {:?}",
                            stream_id, reset_response
                        );
                        vec![AsyncCmd(AsyncCmdResponse::from_error(
                            tag,
                            VideoError::VdaFailure(reset_response),
                        ))]
                    }
                }
            }
            NotifyError(resp) => {
                error!("an error is notified by VDA: {}", resp);
                vec![Event(VideoEvt {
                    typ: EvtType::Error,
                    stream_id,
                })]
            }
        };

        Some(event_responses)
    }
}

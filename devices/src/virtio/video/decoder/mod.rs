// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implementation of a virtio video decoder backed by a device.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::convert::TryInto;

use backend::*;
use base::{error, IntoRawDescriptor, Tube, WaitContext};

use crate::virtio::resource_bridge::{self, BufferInfo, ResourceInfo, ResourceRequest};
use crate::virtio::video::async_cmd_desc_map::AsyncCmdDescMap;
use crate::virtio::video::command::{QueueType, VideoCmd};
use crate::virtio::video::control::{CtrlType, CtrlVal, QueryCtrlType};
use crate::virtio::video::device::*;
use crate::virtio::video::error::*;
use crate::virtio::video::event::*;
use crate::virtio::video::format::*;
use crate::virtio::video::params::Params;
use crate::virtio::video::protocol;
use crate::virtio::video::response::CmdResponse;

mod backend;
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

    // InputResourceId -> data offset
    res_id_to_offset: BTreeMap<InputResourceId, u32>,
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

    // This is a flag that shows whether the device's set_output_buffer_count is called.
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

struct PictureReadyEvent {
    picture_buffer_id: i32,
    bitstream_id: i32,
    visible_rect: Rect,
}

// Context is associated with one `DecoderSession`, which corresponds to one stream from the
// virtio-video's point of view.
#[derive(Default)]
struct Context<S: DecoderSession> {
    stream_id: StreamId,

    in_params: Params,
    out_params: Params,

    in_res: InputResources,
    out_res: OutputResources,

    // Set the flag when we ask the decoder reset, and unset when the reset is done.
    is_resetting: bool,

    pending_ready_pictures: VecDeque<PictureReadyEvent>,

    session: Option<S>,
}

impl<S: DecoderSession> Context<S> {
    fn new(stream_id: StreamId, format: Format) -> Self {
        Context {
            stream_id,
            in_params: Params {
                format: Some(format),
                min_buffers: 1,
                max_buffers: 32,
                plane_formats: vec![Default::default()],
                ..Default::default()
            },
            out_params: Default::default(),
            in_res: Default::default(),
            out_res: Default::default(),
            is_resetting: false,
            pending_ready_pictures: Default::default(),
            session: None,
        }
    }

    fn output_pending_pictures(&mut self) -> Vec<VideoEvtResponseType> {
        let mut responses = vec![];
        while let Some(async_response) = self.output_pending_picture() {
            responses.push(VideoEvtResponseType::AsyncCmd(async_response));
        }
        responses
    }

    fn output_pending_picture(&mut self) -> Option<AsyncCmdResponse> {
        let response = {
            let PictureReadyEvent {
                picture_buffer_id,
                bitstream_id,
                visible_rect,
            } = self.pending_ready_pictures.front()?;

            let plane_size = ((visible_rect.right - visible_rect.left)
                * (visible_rect.bottom - visible_rect.top)) as u32;
            for fmt in self.out_params.plane_formats.iter_mut() {
                fmt.plane_size = plane_size;
                // We don't need to set `plane_formats[i].stride` for the decoder.
            }

            let resource_id = self
                .out_res
                .dequeue_frame_buffer(*picture_buffer_id, self.stream_id)?;

            AsyncCmdResponse::from_response(
                AsyncCmdTag::Queue {
                    stream_id: self.stream_id,
                    queue_type: QueueType::Output,
                    resource_id,
                },
                CmdResponse::ResourceQueue {
                    // Conversion from sec to nsec.
                    timestamp: (*bitstream_id as u64) * 1_000_000_000,
                    // TODO(b/149725148): Set buffer flags once libvda exposes them.
                    flags: 0,
                    // `size` is only used for the encoder.
                    size: 0,
                },
            )
        };
        self.pending_ready_pictures.pop_front().unwrap();

        Some(response)
    }

    fn get_resource_info(
        &self,
        queue_type: QueueType,
        res_bridge: &Tube,
        resource_id: u32,
    ) -> VideoResult<BufferInfo> {
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
        match resource_bridge::get_resource_info(
            res_bridge,
            ResourceRequest::GetBuffer { id: handle },
        ) {
            Ok(ResourceInfo::Buffer(buffer_info)) => Ok(buffer_info),
            Ok(_) => Err(VideoError::InvalidArgument),
            Err(e) => Err(VideoError::ResourceBridgeFailure(e)),
        }
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

        let rect_width: u32 = (visible_rect.right - visible_rect.left) as u32;
        let rect_height: u32 = (visible_rect.bottom - visible_rect.top) as u32;

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
                left: visible_rect.left as u32,
                top: visible_rect.top as u32,
                width: rect_width,
                height: rect_height,
            },
            plane_formats,
            // No need to set `frame_rate`, as it's only for the encoder.
            ..Default::default()
        };
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
struct ContextMap<S: DecoderSession> {
    map: BTreeMap<StreamId, Context<S>>,
}

impl<S: DecoderSession> ContextMap<S> {
    fn new() -> Self {
        ContextMap {
            map: Default::default(),
        }
    }

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

/// Represents information of a decoder backed by a `DecoderBackend`.
pub struct Decoder<D: DecoderBackend> {
    decoder: D,
    capability: Capability,
    contexts: ContextMap<D::Session>,
}

impl<'a, D: DecoderBackend> Decoder<D> {
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

    fn create_stream(
        &mut self,
        stream_id: StreamId,
        coded_format: Format,
    ) -> VideoResult<VideoCmdResponseType> {
        // Create an instance of `Context`.
        // Note that the `DecoderSession` will be created not here but at the first call of
        // `ResourceCreate`. This is because we need to fix a coded format for it, which
        // will be set by `SetParams`.
        self.contexts
            .insert(Context::new(stream_id, coded_format))?;
        Ok(VideoCmdResponseType::Sync(CmdResponse::NoData))
    }

    fn destroy_stream(&mut self, stream_id: StreamId) {
        if self.contexts.map.remove(&stream_id).is_none() {
            error!("Tried to destroy an invalid stream context {}", stream_id);
        }
    }

    fn create_session(
        decoder: &D,
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
        uuid: u128,
    ) -> VideoResult<VideoCmdResponseType> {
        let ctx = self.contexts.get_mut(&stream_id)?;

        // Create a instance of `DecoderSession` at the first time `ResourceCreate` is
        // called here.
        if ctx.session.is_none() {
            ctx.session = Some(Self::create_session(
                &self.decoder,
                wait_ctx,
                ctx,
                stream_id,
            )?);
        }

        ctx.register_buffer(queue_type, resource_id, &uuid);

        if queue_type == QueueType::Input {
            ctx.in_res
                .res_id_to_offset
                .insert(resource_id, plane_offsets.get(0).copied().unwrap_or(0));
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
        resource_bridge: &Tube,
        stream_id: StreamId,
        resource_id: ResourceId,
        timestamp: u64,
        data_sizes: Vec<u32>,
    ) -> VideoResult<VideoCmdResponseType> {
        let ctx = self.contexts.get_mut(&stream_id)?;
        let session = ctx.session.as_ref().ok_or(VideoError::InvalidOperation)?;

        if data_sizes.len() != 1 {
            error!("num_data_sizes must be 1 but {}", data_sizes.len());
            return Err(VideoError::InvalidOperation);
        }

        // Take an ownership of this file by `into_raw_descriptor()` as this file will be closed
        // by the `DecoderBackend`.
        let fd = ctx
            .get_resource_info(QueueType::Input, resource_bridge, resource_id)?
            .file
            .into_raw_descriptor();

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

        let offset = match ctx.in_res.res_id_to_offset.get(&resource_id) {
            Some(offset) => *offset,
            None => {
                error!("Failed to find offset for {}", resource_id);
                0
            }
        };

        // While the virtio-video driver handles timestamps as nanoseconds,
        // Chrome assumes per-second timestamps coming. So, we need a conversion from nsec
        // to sec.
        // Note that this value should not be an unix time stamp but a frame number that
        // a guest passes to a driver as a 32-bit integer in our implementation.
        // So, overflow must not happen in this conversion.
        let ts_sec: i32 = (timestamp / 1_000_000_000) as i32;
        session.decode(
            ts_sec,
            fd,
            offset,
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
        resource_bridge: &Tube,
        stream_id: StreamId,
        resource_id: ResourceId,
    ) -> VideoResult<VideoCmdResponseType> {
        let ctx = self.contexts.get_mut(&stream_id)?;
        let session = ctx.session.as_ref().ok_or(VideoError::InvalidOperation)?;

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
            QueueOutputResourceResult::Reused(buffer_id) => session.reuse_output_buffer(buffer_id),
            QueueOutputResourceResult::Registered(buffer_id) => {
                let resource_info =
                    ctx.get_resource_info(QueueType::Output, resource_bridge, resource_id)?;
                let planes = vec![
                    FramePlane {
                        offset: resource_info.planes[0].offset as i32,
                        stride: resource_info.planes[0].stride as i32,
                    },
                    FramePlane {
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
                    session.set_output_buffer_count(OUTPUT_BUFFER_COUNT)?;
                }

                // Take ownership of this file by `into_raw_descriptor()` as this
                // file will be closed by libvda.
                let fd = resource_info.file.into_raw_descriptor();
                session.use_output_buffer(
                    buffer_id as i32,
                    Format::NV12,
                    fd,
                    &planes,
                    resource_info.modifier,
                )
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
    ) -> VideoResult<VideoCmdResponseType> {
        let ctx = self.contexts.get(&stream_id)?;
        let params = match queue_type {
            QueueType::Input => ctx.in_params.clone(),
            QueueType::Output => ctx.out_params.clone(),
        };
        Ok(VideoCmdResponseType::Sync(CmdResponse::GetParams {
            queue_type,
            params,
        }))
    }

    fn set_params(
        &mut self,
        stream_id: StreamId,
        queue_type: QueueType,
        params: Params,
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
            }
            QueueType::Output => {
                // The guest cannot update parameters for output queue in the decoder.
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
            .get(&stream_id)?
            .session
            .as_ref()
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
        let session = ctx.session.as_ref().ok_or(VideoError::InvalidOperation)?;

        // TODO(b/153406792): Though QUEUE_CLEAR is defined as a per-queue command in the
        // specification, the VDA's `Reset()` clears the input buffers and may (or may not) drop
        // output buffers. So, we call it only for input and resets only the crosvm's internal
        // context for output.
        // This code can be a problem when a guest application wants to reset only one queue by
        // REQBUFS(0). To handle this problem correctly, we need to make libvda expose
        // DismissPictureBuffer() method.
        match queue_type {
            QueueType::Input => {
                session.reset()?;
                ctx.is_resetting = true;
                ctx.pending_ready_pictures.clear();
                Ok(VideoCmdResponseType::Async(AsyncCmdTag::Clear {
                    stream_id,
                    queue_type: QueueType::Input,
                }))
            }
            QueueType::Output => {
                ctx.out_res.queued_res_ids.clear();
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
        resource_bridge: &Tube,
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
            } => self.create_stream(stream_id, coded_format),
            StreamDestroy { stream_id } => {
                self.destroy_stream(stream_id);
                Ok(Sync(CmdResponse::NoData))
            }
            ResourceCreate {
                stream_id,
                queue_type,
                resource_id,
                plane_offsets,
                uuid,
            } => self.create_resource(
                wait_ctx,
                stream_id,
                queue_type,
                resource_id,
                plane_offsets,
                uuid,
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
            } => self.queue_input_resource(
                resource_bridge,
                stream_id,
                resource_id,
                timestamp,
                data_sizes,
            ),
            ResourceQueue {
                stream_id,
                queue_type: QueueType::Output,
                resource_id,
                ..
            } => {
                let resp = self.queue_output_resource(resource_bridge, stream_id, resource_id);
                if resp.is_ok() {
                    if let Ok(ctx) = self.contexts.get_mut(&stream_id) {
                        event_ret = Some((stream_id, ctx.output_pending_pictures()));
                    }
                }
                resp
            }
            GetParams {
                stream_id,
                queue_type,
            } => self.get_params(stream_id, queue_type),
            SetParams {
                stream_id,
                queue_type,
                params,
            } => self.set_params(stream_id, queue_type, params),
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
                picture_buffer_id, // FrameBufferId
                bitstream_id,      // timestamp in second
                visible_rect,
            } => {
                if ctx.is_resetting {
                    vec![]
                } else {
                    ctx.pending_ready_pictures.push_back(PictureReadyEvent {
                        picture_buffer_id,
                        bitstream_id,
                        visible_rect,
                    });
                    ctx.output_pending_pictures()
                }
            }
            DecoderEvent::NotifyEndOfBitstreamBuffer(bitstream_id) => {
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
            DecoderEvent::FlushCompleted(flush_result) => {
                match flush_result {
                    Ok(()) => {
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

/// Create a new decoder instance using a Libvda decoder instance to perform
/// the decoding.
impl<'a> Decoder<&'a libvda::decode::VdaInstance> {
    pub fn new(vda: &'a libvda::decode::VdaInstance) -> Self {
        Decoder {
            decoder: vda,
            capability: Capability::new(vda.get_capabilities()),
            contexts: ContextMap::new(),
        }
    }
}

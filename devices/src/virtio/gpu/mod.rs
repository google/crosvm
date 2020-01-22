// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod protocol;
mod virtio_2d_backend;
mod virtio_3d_backend;
mod virtio_backend;
mod virtio_gfxstream_backend;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::i64;
use std::io::Read;
use std::mem::{self, size_of};
use std::num::NonZeroU8;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::rc::Rc;
use std::thread;
use std::time::Duration;

use data_model::*;

use sys_util::{debug, error, warn, EventFd, GuestAddress, GuestMemory, PollContext, PollToken};

pub use gpu_display::EventDevice;
use gpu_display::*;
use gpu_renderer::RendererFlags;
use msg_socket::{MsgReceiver, MsgSender};
use resources::Alloc;

use super::{
    copy_config, resource_bridge::*, DescriptorChain, Interrupt, Queue, Reader, VirtioDevice,
    Writer, TYPE_GPU, VIRTIO_F_VERSION_1,
};

use super::{PciCapabilityType, VirtioPciShmCap, VirtioPciShmCapID};

use self::protocol::*;
use self::virtio_2d_backend::Virtio2DBackend;
use self::virtio_3d_backend::Virtio3DBackend;
#[cfg(feature = "gfxstream")]
use self::virtio_gfxstream_backend::VirtioGfxStreamBackend;
use crate::pci::{PciBarConfiguration, PciBarPrefetchable, PciBarRegionType, PciCapability};

use vm_control::VmMemoryControlRequestSocket;

pub const DEFAULT_DISPLAY_WIDTH: u32 = 1280;
pub const DEFAULT_DISPLAY_HEIGHT: u32 = 1024;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum GpuMode {
    Mode2D,
    Mode3D,
    #[cfg(feature = "gfxstream")]
    ModeGfxStream,
}

#[derive(Debug)]
pub struct GpuParameters {
    pub display_width: u32,
    pub display_height: u32,
    pub renderer_use_egl: bool,
    pub renderer_use_gles: bool,
    pub renderer_use_glx: bool,
    pub renderer_use_surfaceless: bool,
    pub mode: GpuMode,
}

// First queue is for virtio gpu commands. Second queue is for cursor commands, which we expect
// there to be fewer of.
const QUEUE_SIZES: &[u16] = &[256, 16];
const FENCE_POLL_MS: u64 = 1;

const GPU_BAR_NUM: u8 = 4;
const GPU_BAR_OFFSET: u64 = 0;
const GPU_BAR_SIZE: u64 = 1 << 33;

impl Default for GpuParameters {
    fn default() -> Self {
        GpuParameters {
            display_width: DEFAULT_DISPLAY_WIDTH,
            display_height: DEFAULT_DISPLAY_HEIGHT,
            renderer_use_egl: true,
            renderer_use_gles: true,
            renderer_use_glx: false,
            renderer_use_surfaceless: true,
            mode: GpuMode::Mode3D,
        }
    }
}

/// A virtio-gpu backend state tracker which supports display and potentially accelerated rendering.
///
/// Commands from the virtio-gpu protocol can be submitted here using the methods, and they will be
/// realized on the hardware. Most methods return a `GpuResponse` that indicate the success,
/// failure, or requested data for the given command.
trait Backend {
    /// Returns the number of capsets provided by the Backend.
    fn capsets() -> u32
    where
        Self: Sized;

    /// Returns the bitset of virtio features provided by the Backend.
    fn features() -> u64
    where
        Self: Sized;

    /// Constructs a backend.
    fn build(
        possible_displays: &[DisplayBackend],
        display_width: u32,
        display_height: u32,
        renderer_flags: RendererFlags,
        event_devices: Vec<EventDevice>,
        gpu_device_socket: VmMemoryControlRequestSocket,
        pci_bar: Alloc,
    ) -> Option<Box<dyn Backend>>
    where
        Self: Sized;

    fn display(&self) -> &Rc<RefCell<GpuDisplay>>;

    /// Processes the internal `display` events and returns `true` if the main display was closed.
    fn process_display(&mut self) -> bool;

    /// Creates a fence with the given id that can be used to determine when the previous command
    /// completed.
    fn create_fence(&mut self, ctx_id: u32, fence_id: u32) -> GpuResponse;

    /// Returns the id of the latest fence to complete.
    fn fence_poll(&mut self) -> u32;

    /// For accelerated rendering capable backends, switch to the default rendering context.
    fn force_ctx_0(&mut self) {}

    /// Attaches the given input device to the given surface of the display (to allow for input
    /// from a X11 window for example).
    fn import_event_device(&mut self, event_device: EventDevice, scanout: u32);

    /// If supported, export the resource with the given id to a file.
    fn export_resource(&mut self, id: u32) -> ResourceResponse;

    /// Gets the list of supported display resolutions as a slice of `(width, height)` tuples.
    fn display_info(&self) -> [(u32, u32); 1];

    /// Creates a 2D resource with the given properties and associates it with the given id.
    fn create_resource_2d(&mut self, id: u32, width: u32, height: u32, format: u32) -> GpuResponse;

    /// Removes the guest's reference count for the given resource id.
    fn unref_resource(&mut self, id: u32) -> GpuResponse;

    /// Sets the given resource id as the source of scanout to the display.
    fn set_scanout(&mut self, _scanout_id: u32, resource_id: u32) -> GpuResponse;

    /// Flushes the given rectangle of pixels of the given resource to the display.
    fn flush_resource(&mut self, id: u32, x: u32, y: u32, width: u32, height: u32) -> GpuResponse;

    /// Copes the given rectangle of pixels of the given resource's backing memory to the host side
    /// resource.
    fn transfer_to_resource_2d(
        &mut self,
        id: u32,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        src_offset: u64,
        mem: &GuestMemory,
    ) -> GpuResponse;

    /// Attaches backing memory to the given resource, represented by a `Vec` of `(address, size)`
    /// tuples in the guest's physical address space.
    fn attach_backing(
        &mut self,
        id: u32,
        mem: &GuestMemory,
        vecs: Vec<(GuestAddress, usize)>,
    ) -> GpuResponse;

    /// Detaches any backing memory from the given resource, if there is any.
    fn detach_backing(&mut self, id: u32) -> GpuResponse;

    fn resource_assign_uuid(&mut self, _id: u32) -> GpuResponse {
        GpuResponse::ErrUnspec
    }

    /// Updates the cursor's memory to the given id, and sets its position to the given coordinates.
    fn update_cursor(&mut self, id: u32, x: u32, y: u32) -> GpuResponse;

    /// Moves the cursor's position to the given coordinates.
    fn move_cursor(&mut self, x: u32, y: u32) -> GpuResponse;

    /// Gets the renderer's capset information associated with `index`.
    fn get_capset_info(&self, index: u32) -> GpuResponse;

    /// Gets the capset of `version` associated with `id`.
    fn get_capset(&self, id: u32, version: u32) -> GpuResponse;

    /// Creates a fresh renderer context with the given `id`.
    fn create_renderer_context(&mut self, _id: u32) -> GpuResponse {
        GpuResponse::ErrUnspec
    }

    /// Destorys the renderer context associated with `id`.
    fn destroy_renderer_context(&mut self, _id: u32) -> GpuResponse {
        GpuResponse::ErrUnspec
    }

    /// Attaches the indicated resource to the given context.
    fn context_attach_resource(&mut self, _ctx_id: u32, _res_id: u32) -> GpuResponse {
        GpuResponse::ErrUnspec
    }

    /// detaches the indicated resource to the given context.
    fn context_detach_resource(&mut self, _ctx_id: u32, _res_id: u32) -> GpuResponse {
        GpuResponse::ErrUnspec
    }

    /// Creates a 3D resource with the given properties and associates it with the given id.
    fn resource_create_3d(
        &mut self,
        _id: u32,
        _target: u32,
        _format: u32,
        _bind: u32,
        _width: u32,
        _height: u32,
        _depth: u32,
        _array_size: u32,
        _last_level: u32,
        _nr_samples: u32,
        _flags: u32,
    ) -> GpuResponse {
        GpuResponse::ErrUnspec
    }

    /// Copes the given 3D rectangle of pixels of the given resource's backing memory to the host
    /// side resource.
    fn transfer_to_resource_3d(
        &mut self,
        _ctx_id: u32,
        _res_id: u32,
        _x: u32,
        _y: u32,
        _z: u32,
        _width: u32,
        _height: u32,
        _depth: u32,
        _level: u32,
        _stride: u32,
        _layer_stride: u32,
        _offset: u64,
    ) -> GpuResponse {
        GpuResponse::ErrUnspec
    }

    /// Copes the given rectangle of pixels from the resource to the given resource's backing
    /// memory.
    fn transfer_from_resource_3d(
        &mut self,
        _ctx_id: u32,
        _res_id: u32,
        _x: u32,
        _y: u32,
        _z: u32,
        _width: u32,
        _height: u32,
        _depth: u32,
        _level: u32,
        _stride: u32,
        _layer_stride: u32,
        _offset: u64,
    ) -> GpuResponse {
        GpuResponse::ErrUnspec
    }

    /// Submits a command buffer to the given rendering context.
    fn submit_command(&mut self, _ctx_id: u32, _commands: &mut [u8]) -> GpuResponse {
        GpuResponse::ErrUnspec
    }

    fn resource_create_v2(
        &mut self,
        _resource_id: u32,
        _ctx_id: u32,
        _flags: u32,
        _size: u64,
        _memory_id: u64,
        _vecs: Vec<(GuestAddress, usize)>,
        _mem: &GuestMemory,
    ) -> GpuResponse {
        GpuResponse::ErrUnspec
    }

    fn resource_map(&mut self, _resource_id: u32, _pci_addr: u64) -> GpuResponse {
        GpuResponse::ErrUnspec
    }

    fn resource_unmap(&mut self, _resource_id: u32) -> GpuResponse {
        GpuResponse::ErrUnspec
    }
}

#[derive(Clone)]
enum BackendKind {
    Virtio2D,
    Virtio3D,
    #[cfg(feature = "gfxstream")]
    VirtioGfxStream,
}

impl BackendKind {
    /// Returns the number of capsets provided by the Backend.
    fn capsets(&self) -> u32 {
        match self {
            BackendKind::Virtio2D => Virtio2DBackend::capsets(),
            BackendKind::Virtio3D => Virtio3DBackend::capsets(),
            #[cfg(feature = "gfxstream")]
            BackendKind::VirtioGfxStream => VirtioGfxStreamBackend::capsets(),
        }
    }

    /// Returns the bitset of virtio features provided by the Backend.
    fn features(&self) -> u64 {
        match self {
            BackendKind::Virtio2D => Virtio2DBackend::features(),
            BackendKind::Virtio3D => Virtio3DBackend::features(),
            #[cfg(feature = "gfxstream")]
            BackendKind::VirtioGfxStream => VirtioGfxStreamBackend::features(),
        }
    }

    /// Initializes the backend.
    fn build(
        &self,
        possible_displays: &[DisplayBackend],
        display_width: u32,
        display_height: u32,
        renderer_flags: RendererFlags,
        event_devices: Vec<EventDevice>,
        gpu_device_socket: VmMemoryControlRequestSocket,
        pci_bar: Alloc,
    ) -> Option<Box<dyn Backend>> {
        match self {
            BackendKind::Virtio2D => Virtio2DBackend::build(
                possible_displays,
                display_width,
                display_height,
                renderer_flags,
                event_devices,
                gpu_device_socket,
                pci_bar,
            ),
            BackendKind::Virtio3D => Virtio3DBackend::build(
                possible_displays,
                display_width,
                display_height,
                renderer_flags,
                event_devices,
                gpu_device_socket,
                pci_bar,
            ),
            #[cfg(feature = "gfxstream")]
            BackendKind::VirtioGfxStream => VirtioGfxStreamBackend::build(
                possible_displays,
                display_width,
                display_height,
                renderer_flags,
                event_devices,
                gpu_device_socket,
                pci_bar,
            ),
        }
    }
}

struct ReturnDescriptor {
    index: u16,
    len: u32,
}

struct FenceDescriptor {
    fence_id: u32,
    index: u16,
    len: u32,
}

struct Frontend {
    return_ctrl_descriptors: VecDeque<ReturnDescriptor>,
    return_cursor_descriptors: VecDeque<ReturnDescriptor>,
    fence_descriptors: Vec<FenceDescriptor>,
    backend: Box<dyn Backend>,
}

impl Frontend {
    fn new(backend: Box<dyn Backend>) -> Frontend {
        Frontend {
            return_ctrl_descriptors: Default::default(),
            return_cursor_descriptors: Default::default(),
            fence_descriptors: Default::default(),
            backend,
        }
    }

    fn display(&mut self) -> &Rc<RefCell<GpuDisplay>> {
        self.backend.display()
    }

    fn process_display(&mut self) -> bool {
        self.backend.process_display()
    }

    fn process_resource_bridge(&mut self, resource_bridge: &ResourceResponseSocket) {
        let ResourceRequest::GetResource { id } = match resource_bridge.recv() {
            Ok(msg) => msg,
            Err(e) => {
                error!("error receiving resource bridge request: {}", e);
                return;
            }
        };

        let response = self.backend.export_resource(id);

        if let Err(e) = resource_bridge.send(&response) {
            error!("error sending resource bridge request: {}", e);
        }
    }

    fn process_gpu_command(
        &mut self,
        mem: &GuestMemory,
        cmd: GpuCommand,
        reader: &mut Reader,
    ) -> GpuResponse {
        self.backend.force_ctx_0();

        match cmd {
            GpuCommand::GetDisplayInfo(_) => {
                GpuResponse::OkDisplayInfo(self.backend.display_info().to_vec())
            }
            GpuCommand::ResourceCreate2d(info) => self.backend.create_resource_2d(
                info.resource_id.to_native(),
                info.width.to_native(),
                info.height.to_native(),
                info.format.to_native(),
            ),
            GpuCommand::ResourceUnref(info) => {
                self.backend.unref_resource(info.resource_id.to_native())
            }
            GpuCommand::SetScanout(info) => self
                .backend
                .set_scanout(info.scanout_id.to_native(), info.resource_id.to_native()),
            GpuCommand::ResourceFlush(info) => self.backend.flush_resource(
                info.resource_id.to_native(),
                info.r.x.to_native(),
                info.r.y.to_native(),
                info.r.width.to_native(),
                info.r.height.to_native(),
            ),
            GpuCommand::TransferToHost2d(info) => self.backend.transfer_to_resource_2d(
                info.resource_id.to_native(),
                info.r.x.to_native(),
                info.r.y.to_native(),
                info.r.width.to_native(),
                info.r.height.to_native(),
                info.offset.to_native(),
                mem,
            ),
            GpuCommand::ResourceAttachBacking(info) => {
                let available_bytes = reader.available_bytes();
                if available_bytes != 0 {
                    let entry_count = info.nr_entries.to_native() as usize;
                    let mut vecs = Vec::with_capacity(entry_count);
                    for _ in 0..entry_count {
                        match reader.read_obj::<virtio_gpu_mem_entry>() {
                            Ok(entry) => {
                                let addr = GuestAddress(entry.addr.to_native());
                                let len = entry.length.to_native() as usize;
                                vecs.push((addr, len))
                            }
                            Err(_) => return GpuResponse::ErrUnspec,
                        }
                    }
                    self.backend
                        .attach_backing(info.resource_id.to_native(), mem, vecs)
                } else {
                    error!("missing data for command {:?}", cmd);
                    GpuResponse::ErrUnspec
                }
            }
            GpuCommand::ResourceDetachBacking(info) => {
                self.backend.detach_backing(info.resource_id.to_native())
            }
            GpuCommand::UpdateCursor(info) => self.backend.update_cursor(
                info.resource_id.to_native(),
                info.pos.x.into(),
                info.pos.y.into(),
            ),
            GpuCommand::MoveCursor(info) => self
                .backend
                .move_cursor(info.pos.x.into(), info.pos.y.into()),
            GpuCommand::ResourceAssignUuid(info) => {
                let resource_id = info.resource_id.to_native();
                self.backend.resource_assign_uuid(resource_id)
            }
            GpuCommand::GetCapsetInfo(info) => {
                self.backend.get_capset_info(info.capset_index.to_native())
            }
            GpuCommand::GetCapset(info) => self
                .backend
                .get_capset(info.capset_id.to_native(), info.capset_version.to_native()),
            GpuCommand::CtxCreate(info) => self
                .backend
                .create_renderer_context(info.hdr.ctx_id.to_native()),
            GpuCommand::CtxDestroy(info) => self
                .backend
                .destroy_renderer_context(info.hdr.ctx_id.to_native()),
            GpuCommand::CtxAttachResource(info) => self
                .backend
                .context_attach_resource(info.hdr.ctx_id.to_native(), info.resource_id.to_native()),
            GpuCommand::CtxDetachResource(info) => self
                .backend
                .context_detach_resource(info.hdr.ctx_id.to_native(), info.resource_id.to_native()),
            GpuCommand::ResourceCreate3d(info) => {
                let id = info.resource_id.to_native();
                let target = info.target.to_native();
                let format = info.format.to_native();
                let bind = info.bind.to_native();
                let width = info.width.to_native();
                let height = info.height.to_native();
                let depth = info.depth.to_native();
                let array_size = info.array_size.to_native();
                let last_level = info.last_level.to_native();
                let nr_samples = info.nr_samples.to_native();
                let flags = info.flags.to_native();
                self.backend.resource_create_3d(
                    id, target, format, bind, width, height, depth, array_size, last_level,
                    nr_samples, flags,
                )
            }
            GpuCommand::TransferToHost3d(info) => {
                let ctx_id = info.hdr.ctx_id.to_native();
                let res_id = info.resource_id.to_native();
                let x = info.box_.x.to_native();
                let y = info.box_.y.to_native();
                let z = info.box_.z.to_native();
                let width = info.box_.w.to_native();
                let height = info.box_.h.to_native();
                let depth = info.box_.d.to_native();
                let level = info.level.to_native();
                let stride = info.stride.to_native();
                let layer_stride = info.layer_stride.to_native();
                let offset = info.offset.to_native();
                self.backend.transfer_to_resource_3d(
                    ctx_id,
                    res_id,
                    x,
                    y,
                    z,
                    width,
                    height,
                    depth,
                    level,
                    stride,
                    layer_stride,
                    offset,
                )
            }
            GpuCommand::TransferFromHost3d(info) => {
                let ctx_id = info.hdr.ctx_id.to_native();
                let res_id = info.resource_id.to_native();
                let x = info.box_.x.to_native();
                let y = info.box_.y.to_native();
                let z = info.box_.z.to_native();
                let width = info.box_.w.to_native();
                let height = info.box_.h.to_native();
                let depth = info.box_.d.to_native();
                let level = info.level.to_native();
                let stride = info.stride.to_native();
                let layer_stride = info.layer_stride.to_native();
                let offset = info.offset.to_native();
                self.backend.transfer_from_resource_3d(
                    ctx_id,
                    res_id,
                    x,
                    y,
                    z,
                    width,
                    height,
                    depth,
                    level,
                    stride,
                    layer_stride,
                    offset,
                )
            }
            GpuCommand::CmdSubmit3d(info) => {
                if reader.available_bytes() != 0 {
                    let cmd_size = info.size.to_native() as usize;
                    let mut cmd_buf = vec![0; cmd_size];
                    if reader.read_exact(&mut cmd_buf[..]).is_ok() {
                        self.backend
                            .submit_command(info.hdr.ctx_id.to_native(), &mut cmd_buf[..])
                    } else {
                        GpuResponse::ErrInvalidParameter
                    }
                } else {
                    // Silently accept empty command buffers to allow for
                    // benchmarking.
                    GpuResponse::OkNoData
                }
            }
            GpuCommand::ResourceCreateV2(info) => {
                let resource_id = info.resource_id.to_native();
                let ctx_id = info.hdr.ctx_id.to_native();
                let flags = info.flags.to_native();
                let size = info.size.to_native();
                let memory_id = info.memory_id.to_native();
                let entry_count = info.nr_entries.to_native();
                if entry_count > VIRTIO_GPU_MAX_IOVEC_ENTRIES
                    || (reader.available_bytes() == 0 && entry_count > 0)
                {
                    return GpuResponse::ErrUnspec;
                }

                let mut vecs = Vec::with_capacity(entry_count as usize);
                for _ in 0..entry_count {
                    match reader.read_obj::<virtio_gpu_mem_entry>() {
                        Ok(entry) => {
                            let addr = GuestAddress(entry.addr.to_native());
                            let len = entry.length.to_native() as usize;
                            vecs.push((addr, len))
                        }
                        Err(_) => return GpuResponse::ErrUnspec,
                    }
                }

                self.backend.resource_create_v2(
                    resource_id,
                    ctx_id,
                    flags,
                    size,
                    memory_id,
                    vecs,
                    mem,
                )
            }
            GpuCommand::ResourceMap(info) => {
                let resource_id = info.resource_id.to_native();
                let offset = info.offset.to_native();
                self.backend.resource_map(resource_id, offset)
            }
            GpuCommand::ResourceUnmap(info) => {
                let resource_id = info.resource_id.to_native();
                self.backend.resource_unmap(resource_id)
            }
        }
    }

    fn validate_desc(desc: &DescriptorChain) -> bool {
        desc.len as usize >= size_of::<virtio_gpu_ctrl_hdr>() && !desc.is_write_only()
    }

    fn process_queue(&mut self, mem: &GuestMemory, queue: &mut Queue) -> bool {
        let mut signal_used = false;
        while let Some(desc) = queue.pop(mem) {
            if Frontend::validate_desc(&desc) {
                match (
                    Reader::new(mem, desc.clone()),
                    Writer::new(mem, desc.clone()),
                ) {
                    (Ok(mut reader), Ok(mut writer)) => {
                        if let Some(ret_desc) =
                            self.process_descriptor(mem, desc.index, &mut reader, &mut writer)
                        {
                            queue.add_used(&mem, ret_desc.index, ret_desc.len);
                            signal_used = true;
                        }
                    }
                    (_, Err(e)) | (Err(e), _) => {
                        debug!("invalid descriptor: {}", e);
                        queue.add_used(&mem, desc.index, 0);
                        signal_used = true;
                    }
                }
            } else {
                let likely_type = mem.read_obj_from_addr(desc.addr).unwrap_or(Le32::from(0));
                debug!(
                    "queue bad descriptor index = {} len = {} write = {} type = {}",
                    desc.index,
                    desc.len,
                    desc.is_write_only(),
                    virtio_gpu_cmd_str(likely_type.to_native())
                );
                queue.add_used(&mem, desc.index, 0);
                signal_used = true;
            }
        }

        signal_used
    }

    fn process_descriptor(
        &mut self,
        mem: &GuestMemory,
        desc_index: u16,
        reader: &mut Reader,
        writer: &mut Writer,
    ) -> Option<ReturnDescriptor> {
        let mut resp = GpuResponse::ErrUnspec;
        let mut gpu_cmd = None;
        let mut len = 0;
        match GpuCommand::decode(reader) {
            Ok(cmd) => {
                resp = self.process_gpu_command(mem, cmd, reader);
                gpu_cmd = Some(cmd);
            }
            Err(e) => debug!("descriptor decode error: {}", e),
        }
        if resp.is_err() {
            debug!("{:?} -> {:?}", gpu_cmd, resp);
        }

        if writer.available_bytes() != 0 {
            let mut fence_id = 0;
            let mut ctx_id = 0;
            let mut flags = 0;
            if let Some(cmd) = gpu_cmd {
                let ctrl_hdr = cmd.ctrl_hdr();
                if ctrl_hdr.flags.to_native() & VIRTIO_GPU_FLAG_FENCE != 0 {
                    fence_id = ctrl_hdr.fence_id.to_native();
                    ctx_id = ctrl_hdr.ctx_id.to_native();
                    flags = VIRTIO_GPU_FLAG_FENCE;

                    let fence_resp = self.backend.create_fence(ctx_id, fence_id as u32);
                    if fence_resp.is_err() {
                        warn!("create_fence {} -> {:?}", fence_id, fence_resp);
                        resp = fence_resp;
                    }
                }
            }

            // Prepare the response now, even if it is going to wait until
            // fence is complete.
            match resp.encode(flags, fence_id, ctx_id, writer) {
                Ok(l) => len = l,
                Err(e) => debug!("ctrl queue response encode error: {}", e),
            }

            if flags & VIRTIO_GPU_FLAG_FENCE != 0 {
                self.fence_descriptors.push(FenceDescriptor {
                    fence_id: fence_id as u32,
                    index: desc_index,
                    len,
                });

                return None;
            }

            // No fence, respond now.
        }
        Some(ReturnDescriptor {
            index: desc_index,
            len,
        })
    }

    fn return_cursor(&mut self) -> Option<ReturnDescriptor> {
        self.return_cursor_descriptors.pop_front()
    }

    fn return_ctrl(&mut self) -> Option<ReturnDescriptor> {
        self.return_ctrl_descriptors.pop_front()
    }

    fn fence_poll(&mut self) {
        let fence_id = self.backend.fence_poll();
        let return_descs = &mut self.return_ctrl_descriptors;
        self.fence_descriptors.retain(|f_desc| {
            if f_desc.fence_id > fence_id {
                true
            } else {
                return_descs.push_back(ReturnDescriptor {
                    index: f_desc.index,
                    len: f_desc.len,
                });
                false
            }
        })
    }
}

struct Worker {
    interrupt: Interrupt,
    exit_evt: EventFd,
    mem: GuestMemory,
    ctrl_queue: Queue,
    ctrl_evt: EventFd,
    cursor_queue: Queue,
    cursor_evt: EventFd,
    resource_bridges: Vec<ResourceResponseSocket>,
    kill_evt: EventFd,
    state: Frontend,
}

impl Worker {
    fn run(&mut self) {
        #[derive(PollToken)]
        enum Token {
            CtrlQueue,
            CursorQueue,
            Display,
            InterruptResample,
            Kill,
            ResourceBridge { index: usize },
        }

        let poll_ctx: PollContext<Token> = match PollContext::build_with(&[
            (&self.ctrl_evt, Token::CtrlQueue),
            (&self.cursor_evt, Token::CursorQueue),
            (&*self.state.display().borrow(), Token::Display),
            (self.interrupt.get_resample_evt(), Token::InterruptResample),
            (&self.kill_evt, Token::Kill),
        ]) {
            Ok(pc) => pc,
            Err(e) => {
                error!("failed creating PollContext: {}", e);
                return;
            }
        };

        for (index, bridge) in self.resource_bridges.iter().enumerate() {
            if let Err(e) = poll_ctx.add(bridge, Token::ResourceBridge { index }) {
                error!("failed to add resource bridge to PollContext: {}", e);
            }
        }

        // TODO(davidriley): The entire main loop processing is somewhat racey and incorrect with
        // respect to cursor vs control queue processing.  As both currently and originally
        // written, while the control queue is only processed/read from after the the cursor queue
        // is finished, the entire queue will be processed at that time.  The end effect of this
        // racyiness is that control queue descriptors that are issued after cursors descriptors
        // might be handled first instead of the other way around.  In practice, the cursor queue
        // isn't used so this isn't a huge issue.

        // Declare this outside the loop so we don't keep allocating and freeing the vector.
        let mut process_resource_bridge = Vec::with_capacity(self.resource_bridges.len());
        'poll: loop {
            // If there are outstanding fences, wake up early to poll them.
            let duration = if !self.state.fence_descriptors.is_empty() {
                Duration::from_millis(FENCE_POLL_MS)
            } else {
                Duration::new(i64::MAX as u64, 0)
            };

            let events = match poll_ctx.wait_timeout(duration) {
                Ok(v) => v,
                Err(e) => {
                    error!("failed polling for events: {}", e);
                    break;
                }
            };
            let mut signal_used_cursor = false;
            let mut signal_used_ctrl = false;
            let mut ctrl_available = false;

            // Clear the old values and re-initialize with false.
            process_resource_bridge.clear();
            process_resource_bridge.resize(self.resource_bridges.len(), false);

            // This display isn't typically used when the virt-wl device is available and it can
            // lead to hung fds (crbug.com/1027379). Disable if it's hung.
            for event in events.iter_hungup() {
                if let Token::Display = event.token() {
                    error!("default display hang-up detected");
                    let _ = poll_ctx.delete(&*self.state.display().borrow());
                }
            }

            for event in events.iter_readable() {
                match event.token() {
                    Token::CtrlQueue => {
                        let _ = self.ctrl_evt.read();
                        // Set flag that control queue is available to be read, but defer reading
                        // until rest of the events are processed.
                        ctrl_available = true;
                    }
                    Token::CursorQueue => {
                        let _ = self.cursor_evt.read();
                        if self.state.process_queue(&self.mem, &mut self.cursor_queue) {
                            signal_used_cursor = true;
                        }
                    }
                    Token::Display => {
                        let close_requested = self.state.process_display();
                        if close_requested {
                            let _ = self.exit_evt.write(1);
                        }
                    }
                    Token::ResourceBridge { index } => {
                        process_resource_bridge[index] = true;
                    }
                    Token::InterruptResample => {
                        self.interrupt.interrupt_resample();
                    }
                    Token::Kill => {
                        break 'poll;
                    }
                }
            }

            // All cursor commands go first because they have higher priority.
            while let Some(desc) = self.state.return_cursor() {
                self.cursor_queue.add_used(&self.mem, desc.index, desc.len);
                signal_used_cursor = true;
            }

            if ctrl_available && self.state.process_queue(&self.mem, &mut self.ctrl_queue) {
                signal_used_ctrl = true;
            }

            self.state.fence_poll();

            while let Some(desc) = self.state.return_ctrl() {
                self.ctrl_queue.add_used(&self.mem, desc.index, desc.len);
                signal_used_ctrl = true;
            }

            // Process the entire control queue before the resource bridge in case a resource is
            // created or destroyed by the control queue. Processing the resource bridge first may
            // lead to a race condition.
            // TODO(davidriley): This is still inherently racey if both the control queue request
            // and the resource bridge request come in at the same time after the control queue is
            // processed above and before the corresponding bridge is processed below.
            for (bridge, &should_process) in
                self.resource_bridges.iter().zip(&process_resource_bridge)
            {
                if should_process {
                    self.state.process_resource_bridge(bridge);
                }
            }

            if signal_used_ctrl {
                self.interrupt.signal_used_queue(self.ctrl_queue.vector);
            }

            if signal_used_cursor {
                self.interrupt.signal_used_queue(self.cursor_queue.vector);
            }
        }
    }
}

/// Indicates a backend that should be tried for the gpu to use for display.
///
/// Several instances of this enum are used in an ordered list to give the gpu device many backends
/// to use as fallbacks in case some do not work.
#[derive(Clone)]
pub enum DisplayBackend {
    /// Use the wayland backend with the given socket path if given.
    Wayland(Option<PathBuf>),
    /// Open a connection to the X server at the given display if given.
    X(Option<String>),
    /// Emulate a display without actually displaying it.
    Stub,
}

impl DisplayBackend {
    fn build(&self) -> std::result::Result<GpuDisplay, GpuDisplayError> {
        match self {
            DisplayBackend::Wayland(path) => GpuDisplay::open_wayland(path.as_ref()),
            DisplayBackend::X(display) => GpuDisplay::open_x(display.as_ref()),
            DisplayBackend::Stub => GpuDisplay::open_stub(),
        }
    }

    fn is_x(&self) -> bool {
        match self {
            DisplayBackend::X(_) => true,
            _ => false,
        }
    }
}

pub struct Gpu {
    exit_evt: EventFd,
    gpu_device_socket: Option<VmMemoryControlRequestSocket>,
    resource_bridges: Vec<ResourceResponseSocket>,
    event_devices: Vec<EventDevice>,
    kill_evt: Option<EventFd>,
    config_event: bool,
    worker_thread: Option<thread::JoinHandle<()>>,
    num_scanouts: NonZeroU8,
    display_backends: Vec<DisplayBackend>,
    display_width: u32,
    display_height: u32,
    renderer_flags: RendererFlags,
    pci_bar: Option<Alloc>,
    backend_kind: BackendKind,
}

impl Gpu {
    pub fn new(
        exit_evt: EventFd,
        gpu_device_socket: Option<VmMemoryControlRequestSocket>,
        num_scanouts: NonZeroU8,
        resource_bridges: Vec<ResourceResponseSocket>,
        display_backends: Vec<DisplayBackend>,
        gpu_parameters: &GpuParameters,
        event_devices: Vec<EventDevice>,
    ) -> Gpu {
        let renderer_flags = RendererFlags::new()
            .use_egl(gpu_parameters.renderer_use_egl)
            .use_gles(gpu_parameters.renderer_use_gles)
            .use_glx(gpu_parameters.renderer_use_glx)
            .use_surfaceless(gpu_parameters.renderer_use_surfaceless);

        let backend_kind = match gpu_parameters.mode {
            GpuMode::Mode2D => BackendKind::Virtio2D,
            GpuMode::Mode3D => BackendKind::Virtio3D,
            #[cfg(feature = "gfxstream")]
            GpuMode::ModeGfxStream => BackendKind::VirtioGfxStream,
        };

        Gpu {
            exit_evt,
            gpu_device_socket,
            num_scanouts,
            resource_bridges,
            event_devices,
            config_event: false,
            kill_evt: None,
            worker_thread: None,
            display_backends,
            display_width: gpu_parameters.display_width,
            display_height: gpu_parameters.display_height,
            renderer_flags,
            pci_bar: None,
            backend_kind,
        }
    }

    fn get_config(&self) -> virtio_gpu_config {
        let mut events_read = 0;
        if self.config_event {
            events_read |= VIRTIO_GPU_EVENT_DISPLAY;
        }
        virtio_gpu_config {
            events_read: Le32::from(events_read),
            events_clear: Le32::from(0),
            num_scanouts: Le32::from(self.num_scanouts.get() as u32),
            num_capsets: Le32::from(self.backend_kind.capsets()),
        }
    }
}

impl Drop for Gpu {
    fn drop(&mut self) {
        if let Some(kill_evt) = self.kill_evt.take() {
            // Ignore the result because there is nothing we can do about it.
            let _ = kill_evt.write(1);
        }

        if let Some(worker_thread) = self.worker_thread.take() {
            let _ = worker_thread.join();
        }
    }
}

impl VirtioDevice for Gpu {
    fn keep_fds(&self) -> Vec<RawFd> {
        let mut keep_fds = Vec::new();
        // TODO(davidriley): Remove once virgl has another path to include
        // debugging logs.
        if cfg!(debug_assertions) {
            keep_fds.push(libc::STDOUT_FILENO);
            keep_fds.push(libc::STDERR_FILENO);
        }

        if let Some(ref gpu_device_socket) = self.gpu_device_socket {
            keep_fds.push(gpu_device_socket.as_raw_fd());
        }

        keep_fds.push(self.exit_evt.as_raw_fd());
        for bridge in &self.resource_bridges {
            keep_fds.push(bridge.as_raw_fd());
        }
        keep_fds
    }

    fn device_type(&self) -> u32 {
        TYPE_GPU
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self) -> u64 {
        self.backend_kind.features()
    }

    fn ack_features(&mut self, value: u64) {
        let _ = value;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        copy_config(data, 0, self.get_config().as_slice(), offset);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let mut cfg = self.get_config();
        copy_config(cfg.as_mut_slice(), offset, data, 0);
        if (cfg.events_clear.to_native() & VIRTIO_GPU_EVENT_DISPLAY) != 0 {
            self.config_event = false;
        }
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) {
        if queues.len() != QUEUE_SIZES.len() || queue_evts.len() != QUEUE_SIZES.len() {
            return;
        }

        let exit_evt = match self.exit_evt.try_clone() {
            Ok(e) => e,
            Err(e) => {
                error!("error cloning exit eventfd: {}", e);
                return;
            }
        };

        let (self_kill_evt, kill_evt) = match EventFd::new().and_then(|e| Ok((e.try_clone()?, e))) {
            Ok(v) => v,
            Err(e) => {
                error!("error creating kill EventFd pair: {}", e);
                return;
            }
        };
        self.kill_evt = Some(self_kill_evt);

        let resource_bridges = mem::replace(&mut self.resource_bridges, Vec::new());

        let backend_kind = self.backend_kind.clone();
        let ctrl_queue = queues.remove(0);
        let ctrl_evt = queue_evts.remove(0);
        let cursor_queue = queues.remove(0);
        let cursor_evt = queue_evts.remove(0);
        let display_backends = self.display_backends.clone();
        let display_width = self.display_width;
        let display_height = self.display_height;
        let renderer_flags = self.renderer_flags;
        let event_devices = self.event_devices.split_off(0);
        if let (Some(gpu_device_socket), Some(pci_bar)) =
            (self.gpu_device_socket.take(), self.pci_bar.take())
        {
            let worker_result =
                thread::Builder::new()
                    .name("virtio_gpu".to_string())
                    .spawn(move || {
                        let backend = match backend_kind.build(
                            &display_backends,
                            display_width,
                            display_height,
                            renderer_flags,
                            event_devices,
                            gpu_device_socket,
                            pci_bar,
                        ) {
                            Some(backend) => backend,
                            None => return,
                        };

                        Worker {
                            interrupt,
                            exit_evt,
                            mem,
                            ctrl_queue,
                            ctrl_evt,
                            cursor_queue,
                            cursor_evt,
                            resource_bridges,
                            kill_evt,
                            state: Frontend::new(backend),
                        }
                        .run()
                    });

            match worker_result {
                Err(e) => {
                    error!("failed to spawn virtio_gpu worker: {}", e);
                    return;
                }
                Ok(join_handle) => {
                    self.worker_thread = Some(join_handle);
                }
            }
        }
    }

    // Require 1 BAR for mapping 3D buffers
    fn get_device_bars(&mut self, bus: u8, dev: u8) -> Vec<PciBarConfiguration> {
        self.pci_bar = Some(Alloc::PciBar {
            bus,
            dev,
            bar: GPU_BAR_NUM,
        });
        vec![PciBarConfiguration::new(
            GPU_BAR_NUM as usize,
            GPU_BAR_SIZE,
            PciBarRegionType::Memory64BitRegion,
            PciBarPrefetchable::NotPrefetchable,
        )]
    }

    fn get_device_caps(&self) -> Vec<Box<dyn PciCapability>> {
        vec![Box::new(VirtioPciShmCap::new(
            PciCapabilityType::SharedMemoryConfig,
            GPU_BAR_NUM,
            GPU_BAR_OFFSET,
            GPU_BAR_SIZE,
            VirtioPciShmCapID::Cache,
        ))]
    }
}

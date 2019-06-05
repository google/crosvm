// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implementation for the transport agnostic virtio-gpu protocol, including display and rendering.

use std::cell::RefCell;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap as Map;
use std::os::unix::io::AsRawFd;
use std::rc::Rc;
use std::usize;

use data_model::*;

use msg_socket::{MsgReceiver, MsgSender};
use sys_util::{error, warn, GuestAddress, GuestMemory};

use gpu_buffer::{Buffer, Device, Flags, Format};
use gpu_display::*;
use gpu_renderer::{
    format_fourcc as renderer_fourcc, Box3, Context as RendererContext, Image as RendererImage,
    Renderer, Resource as GpuRendererResource, ResourceCreateArgs, VIRGL_RES_BIND_SCANOUT,
};

use super::protocol::{
    GpuResponse, GpuResponsePlaneInfo, VIRTIO_GPU_CAPSET_VIRGL, VIRTIO_GPU_CAPSET_VIRGL2,
};
use crate::virtio::resource_bridge::*;
use vm_control::VmMemoryControlRequestSocket;

const DEFAULT_WIDTH: u32 = 1280;
const DEFAULT_HEIGHT: u32 = 1024;

/// Trait for virtio-gpu resources allocated by the guest.
trait VirglResource {
    /// The width in pixels of this resource.
    fn width(&self) -> u32;

    /// The height in pixels of this resource.
    fn height(&self) -> u32;

    /// Associates the backing for this resource with the given guest memory.
    fn attach_guest_backing(&mut self, mem: &GuestMemory, vecs: Vec<(GuestAddress, usize)>);

    /// Removes associated memory for this resource previously made with `attach_guest_backing`.
    fn detach_guest_backing(&mut self);

    /// Returns the GPU `Buffer` for this resource, if it has one.
    fn buffer(&self) -> Option<&Buffer> {
        None
    }

    /// Returns the renderer's concrete `GpuRendererResource` for this resource, if it has one.
    fn gpu_renderer_resource(&mut self) -> Option<&mut GpuRendererResource> {
        None
    }

    /// Returns an import ID for this resource onto the given display, if successful.
    fn import_to_display(&mut self, _display: &Rc<RefCell<GpuDisplay>>) -> Option<u32> {
        None
    }

    /// Copies the given rectangle of pixels from guest memory, using the backing specified from a
    /// call to `attach_guest_backing`.
    fn write_from_guest_memory(
        &mut self,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        src_offset: u64,
        mem: &GuestMemory,
    );

    /// Reads from the given rectangle of pixels in the resource to the `dst` slice of memory.
    fn read_to_volatile(&mut self, x: u32, y: u32, width: u32, height: u32, dst: VolatileSlice);
}

impl VirglResource for GpuRendererResource {
    fn width(&self) -> u32 {
        match self.get_info() {
            Ok(info) => info.width,
            Err(_) => 0,
        }
    }
    fn height(&self) -> u32 {
        match self.get_info() {
            Ok(info) => info.height,
            Err(_) => 0,
        }
    }

    fn attach_guest_backing(&mut self, mem: &GuestMemory, vecs: Vec<(GuestAddress, usize)>) {
        if let Err(e) = self.attach_backing(&vecs[..], mem) {
            error!("failed to attach backing to resource: {}", e);
        }
    }

    fn detach_guest_backing(&mut self) {
        self.detach_backing();
    }

    fn gpu_renderer_resource(&mut self) -> Option<&mut GpuRendererResource> {
        Some(self)
    }

    fn write_from_guest_memory(
        &mut self,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        src_offset: u64,
        _mem: &GuestMemory,
    ) {
        let res = self.transfer_write(
            None,
            0,
            0,
            0,
            Box3 {
                x,
                y,
                z: 0,
                w: width,
                h: height,
                d: 0,
            },
            src_offset,
        );
        if let Err(e) = res {
            error!(
                "failed to write to resource (x={} y={} w={} h={}, src_offset={}): {}",
                x, y, width, height, src_offset, e
            );
        }
    }

    fn read_to_volatile(&mut self, x: u32, y: u32, width: u32, height: u32, dst: VolatileSlice) {
        let res = GpuRendererResource::read_to_volatile(
            self,
            None,
            0,
            0,
            0,
            Box3 {
                x,
                y,
                z: 0,
                w: width,
                h: height,
                d: 0,
            },
            0,
            dst,
        );
        if let Err(e) = res {
            error!("failed to read from resource: {}", e);
        }
    }
}

/// A buffer backed with a `gpu_buffer::Buffer`.
struct BackedBuffer {
    display_import: Option<(Rc<RefCell<GpuDisplay>>, u32)>,
    backing: Vec<(GuestAddress, usize)>,
    buffer: Buffer,
    gpu_renderer_resource: Option<GpuRendererResource>,
    _image: Option<RendererImage>,
}

impl BackedBuffer {
    fn new_renderer_registered(
        buffer: Buffer,
        gpu_renderer_resource: GpuRendererResource,
        image: RendererImage,
    ) -> BackedBuffer {
        BackedBuffer {
            display_import: None,
            backing: Vec::new(),
            buffer,
            gpu_renderer_resource: Some(gpu_renderer_resource),
            _image: Some(image),
        }
    }
}

impl From<Buffer> for BackedBuffer {
    fn from(buffer: Buffer) -> BackedBuffer {
        BackedBuffer {
            display_import: None,
            backing: Vec::new(),
            buffer,
            gpu_renderer_resource: None,
            _image: None,
        }
    }
}

impl VirglResource for BackedBuffer {
    fn width(&self) -> u32 {
        self.buffer.width()
    }

    fn height(&self) -> u32 {
        self.buffer.height()
    }

    fn attach_guest_backing(&mut self, mem: &GuestMemory, vecs: Vec<(GuestAddress, usize)>) {
        self.backing = vecs.clone();
        if let Some(resource) = &mut self.gpu_renderer_resource {
            if let Err(e) = resource.attach_backing(&vecs[..], mem) {
                error!("failed to attach backing to BackBuffer resource: {}", e);
            }
        }
    }

    fn detach_guest_backing(&mut self) {
        if let Some(resource) = &mut self.gpu_renderer_resource {
            resource.detach_backing();
        }
        self.backing.clear();
    }

    fn gpu_renderer_resource(&mut self) -> Option<&mut GpuRendererResource> {
        self.gpu_renderer_resource.as_mut()
    }

    fn buffer(&self) -> Option<&Buffer> {
        Some(&self.buffer)
    }

    fn import_to_display(&mut self, display: &Rc<RefCell<GpuDisplay>>) -> Option<u32> {
        if let Some((self_display, import)) = &self.display_import {
            if Rc::ptr_eq(self_display, display) {
                return Some(*import);
            }
        }
        let dmabuf = match self.buffer.export_plane_fd(0) {
            Ok(dmabuf) => dmabuf,
            Err(e) => {
                error!("failed to get dmabuf for scanout: {}", e);
                return None;
            }
        };

        match display.borrow_mut().import_dmabuf(
            dmabuf.as_raw_fd(),
            0, /* offset */
            self.buffer.stride(),
            self.buffer.format_modifier(),
            self.buffer.width(),
            self.buffer.height(),
            self.buffer.format().into(),
        ) {
            Ok(import_id) => {
                self.display_import = Some((display.clone(), import_id));
                Some(import_id)
            }
            Err(e) => {
                error!("failed to import dmabuf for display: {}", e);
                None
            }
        }
    }

    fn write_from_guest_memory(
        &mut self,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        src_offset: u64,
        mem: &GuestMemory,
    ) {
        if src_offset >= usize::MAX as u64 {
            error!(
                "failed to write to resource with given offset: {}",
                src_offset
            );
            return;
        }
        let res = self.buffer.write_from_sg(
            x,
            y,
            width,
            height,
            0, // plane
            src_offset as usize,
            self.backing
                .iter()
                .map(|&(addr, len)| mem.get_slice(addr.offset(), len as u64).unwrap_or_default()),
        );
        if let Err(e) = res {
            error!("failed to write to resource from guest memory: {}", e)
        }
    }

    fn read_to_volatile(&mut self, x: u32, y: u32, width: u32, height: u32, dst: VolatileSlice) {
        if let Err(e) = self.buffer.read_to_volatile(x, y, width, height, 0, dst) {
            error!("failed to copy resource: {}", e);
        }
    }
}

/// The virtio-gpu backend state tracker.
///
/// Commands from the virtio-gpu protocol can be submitted here using the methods, and they will be
/// realized on the hardware. Most methods return a `GpuResponse` that indicate the success,
/// failure, or requested data for the given command.
pub struct Backend {
    display: Rc<RefCell<GpuDisplay>>,
    device: Device,
    renderer: Renderer,
    resources: Map<u32, Box<dyn VirglResource>>,
    contexts: Map<u32, RendererContext>,
    #[allow(dead_code)]
    gpu_device_socket: VmMemoryControlRequestSocket,
    scanout_surface: Option<u32>,
    cursor_surface: Option<u32>,
    scanout_resource: u32,
    cursor_resource: u32,
}

impl Backend {
    /// Creates a new backend for virtio-gpu that realizes all commands using the given `device` for
    /// allocating buffers, `display` for showing the results, and `renderer` for submitting
    /// rendering commands.
    pub fn new(
        device: Device,
        display: GpuDisplay,
        renderer: Renderer,
        gpu_device_socket: VmMemoryControlRequestSocket,
    ) -> Backend {
        Backend {
            display: Rc::new(RefCell::new(display)),
            device,
            renderer,
            gpu_device_socket,
            resources: Default::default(),
            contexts: Default::default(),
            scanout_surface: None,
            cursor_surface: None,
            scanout_resource: 0,
            cursor_resource: 0,
        }
    }

    /// Gets a reference to the display passed into `new`.
    pub fn display(&self) -> &Rc<RefCell<GpuDisplay>> {
        &self.display
    }

    /// Processes the internal `display` events and returns `true` if the main display was closed.
    pub fn process_display(&mut self) -> bool {
        let mut display = self.display.borrow_mut();
        display.dispatch_events();
        self.scanout_surface
            .map(|s| display.close_requested(s))
            .unwrap_or(false)
    }

    pub fn process_resource_bridge(&self, resource_bridge: &ResourceResponseSocket) {
        let request = match resource_bridge.recv() {
            Ok(msg) => msg,
            Err(e) => {
                error!("error receiving resource bridge request: {}", e);
                return;
            }
        };

        let response = match request {
            ResourceRequest::GetResource { id } => self
                .resources
                .get(&id)
                .and_then(|resource| resource.buffer())
                .and_then(|buffer| buffer.export_plane_fd(0).ok())
                .map(ResourceResponse::Resource)
                .unwrap_or(ResourceResponse::Invalid),
        };

        if let Err(e) = resource_bridge.send(&response) {
            error!("error sending resource bridge request: {}", e);
        }
    }

    /// Gets the list of supported display resolutions as a slice of `(width, height)` tuples.
    pub fn display_info(&self) -> &[(u32, u32)] {
        &[(DEFAULT_WIDTH, DEFAULT_HEIGHT)]
    }

    /// Creates a 2D resource with the given properties and associated it with the given id.
    pub fn create_resource_2d(
        &mut self,
        id: u32,
        width: u32,
        height: u32,
        fourcc: u32,
    ) -> GpuResponse {
        if id == 0 {
            return GpuResponse::ErrInvalidResourceId;
        }
        match self.resources.entry(id) {
            Entry::Vacant(slot) => {
                let res = self.device.create_buffer(
                    width,
                    height,
                    Format::from(fourcc),
                    Flags::empty().use_scanout(true).use_linear(true),
                );
                match res {
                    Ok(res) => {
                        slot.insert(Box::from(BackedBuffer::from(res)));
                        GpuResponse::OkNoData
                    }
                    Err(_) => {
                        error!("failed to create renderer resource {}", fourcc);
                        GpuResponse::ErrUnspec
                    }
                }
            }
            Entry::Occupied(_) => GpuResponse::ErrInvalidResourceId,
        }
    }

    /// Removes the guest's reference count for the given resource id.
    pub fn unref_resource(&mut self, id: u32) -> GpuResponse {
        match self.resources.remove(&id) {
            Some(_) => GpuResponse::OkNoData,
            None => GpuResponse::ErrInvalidResourceId,
        }
    }

    /// Sets the given resource id as the source of scanout to the display.
    pub fn set_scanout(&mut self, id: u32) -> GpuResponse {
        let mut display = self.display.borrow_mut();
        if id == 0 {
            if let Some(surface) = self.scanout_surface.take() {
                display.release_surface(surface);
            }
            self.scanout_resource = 0;
            if let Some(surface) = self.cursor_surface.take() {
                display.release_surface(surface);
            }
            self.cursor_resource = 0;
            GpuResponse::OkNoData
        } else if self.resources.get_mut(&id).is_some() {
            self.scanout_resource = id;

            if self.scanout_surface.is_none() {
                match display.create_surface(None, DEFAULT_WIDTH, DEFAULT_HEIGHT) {
                    Ok(surface) => self.scanout_surface = Some(surface),
                    Err(e) => error!("failed to create display surface: {}", e),
                }
            }
            GpuResponse::OkNoData
        } else {
            GpuResponse::ErrInvalidResourceId
        }
    }

    fn flush_resource_to_surface(
        &mut self,
        resource_id: u32,
        surface_id: u32,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
    ) -> GpuResponse {
        let resource = match self.resources.get_mut(&resource_id) {
            Some(r) => r,
            None => return GpuResponse::ErrInvalidResourceId,
        };

        if let Some(import_id) = resource.import_to_display(&self.display) {
            self.display.borrow_mut().flip_to(surface_id, import_id);
            return GpuResponse::OkNoData;
        }

        // Import failed, fall back to a copy.
        let display = self.display.borrow_mut();
        // Prevent overwriting a buffer that is currently being used by the compositor.
        if display.next_buffer_in_use(surface_id) {
            return GpuResponse::OkNoData;
        }
        let fb = match display.framebuffer_memory(surface_id) {
            Some(fb) => fb,
            None => {
                error!("failed to access framebuffer for surface {}", surface_id);
                return GpuResponse::ErrUnspec;
            }
        };

        resource.read_to_volatile(x, y, width, height, fb);
        display.flip(surface_id);

        GpuResponse::OkNoData
    }

    /// Flushes the given rectangle of pixels of the given resource to the display.
    pub fn flush_resource(
        &mut self,
        id: u32,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
    ) -> GpuResponse {
        if id == 0 {
            return GpuResponse::OkNoData;
        }

        let mut response = GpuResponse::OkNoData;

        if id == self.scanout_resource {
            if let Some(surface_id) = self.scanout_surface {
                response = self.flush_resource_to_surface(id, surface_id, x, y, width, height);
            }
        }

        if response != GpuResponse::OkNoData {
            return response;
        }

        if id == self.cursor_resource {
            if let Some(surface_id) = self.cursor_surface {
                response = self.flush_resource_to_surface(id, surface_id, x, y, width, height);
            }
        }

        response
    }

    /// Copes the given rectangle of pixels of the given resource's backing memory to the host side
    /// resource.
    pub fn transfer_to_resource_2d(
        &mut self,
        id: u32,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        src_offset: u64,
        mem: &GuestMemory,
    ) -> GpuResponse {
        match self.resources.get_mut(&id) {
            Some(res) => {
                res.write_from_guest_memory(x, y, width, height, src_offset, mem);
                GpuResponse::OkNoData
            }
            None => GpuResponse::ErrInvalidResourceId,
        }
    }

    /// Attaches backing memory to the given resource, represented by a `Vec` of `(address, size)`
    /// tuples in the guest's physical address space.
    pub fn attach_backing(
        &mut self,
        id: u32,
        mem: &GuestMemory,
        vecs: Vec<(GuestAddress, usize)>,
    ) -> GpuResponse {
        match self.resources.get_mut(&id) {
            Some(resource) => {
                resource.attach_guest_backing(mem, vecs);
                GpuResponse::OkNoData
            }
            None => GpuResponse::ErrInvalidResourceId,
        }
    }

    /// Detaches any backing memory from the given resource, if there is any.
    pub fn detach_backing(&mut self, id: u32) -> GpuResponse {
        match self.resources.get_mut(&id) {
            Some(resource) => {
                resource.detach_guest_backing();
                GpuResponse::OkNoData
            }
            None => GpuResponse::ErrInvalidResourceId,
        }
    }

    /// Updates the cursor's memory to the given id, and sets its position to the given coordinates.
    pub fn update_cursor(&mut self, id: u32, x: u32, y: u32) -> GpuResponse {
        if id == 0 {
            if let Some(surface) = self.cursor_surface.take() {
                self.display.borrow_mut().release_surface(surface);
            }
            self.cursor_resource = 0;
            GpuResponse::OkNoData
        } else if let Some(resource) = self.resources.get_mut(&id) {
            self.cursor_resource = id;
            if self.cursor_surface.is_none() {
                match self.display.borrow_mut().create_surface(
                    self.scanout_surface,
                    resource.width(),
                    resource.height(),
                ) {
                    Ok(surface) => self.cursor_surface = Some(surface),
                    Err(e) => {
                        error!("failed to create cursor surface: {}", e);
                        return GpuResponse::ErrUnspec;
                    }
                }
            }

            let cursor_surface = self.cursor_surface.unwrap();
            self.display.borrow_mut().set_position(cursor_surface, x, y);

            // Gets the resource's pixels into the display by importing the buffer.
            if let Some(import_id) = resource.import_to_display(&self.display) {
                self.display.borrow_mut().flip_to(cursor_surface, import_id);
                return GpuResponse::OkNoData;
            }

            // Importing failed, so try copying the pixels into the surface's slower shared memory
            // framebuffer.
            if let Some(buffer) = resource.buffer() {
                if let Some(fb) = self.display.borrow_mut().framebuffer_memory(cursor_surface) {
                    if let Err(e) =
                        buffer.read_to_volatile(0, 0, buffer.width(), buffer.height(), 0, fb)
                    {
                        error!("failed to copy resource to cursor: {}", e);
                        return GpuResponse::ErrInvalidParameter;
                    }
                }
                self.display.borrow_mut().flip(cursor_surface);
            }
            GpuResponse::OkNoData
        } else {
            GpuResponse::ErrInvalidResourceId
        }
    }

    /// Moves the cursor's position to the given coordinates.
    pub fn move_cursor(&mut self, x: u32, y: u32) -> GpuResponse {
        if let Some(cursor_surface) = self.cursor_surface {
            if let Some(scanout_surface) = self.scanout_surface {
                let display = self.display.borrow_mut();
                display.set_position(cursor_surface, x, y);
                display.commit(scanout_surface);
            }
        }
        GpuResponse::OkNoData
    }

    /// Gets the renderer's capset information associated with `index`.
    pub fn get_capset_info(&self, index: u32) -> GpuResponse {
        let id = match index {
            0 => VIRTIO_GPU_CAPSET_VIRGL,
            1 => VIRTIO_GPU_CAPSET_VIRGL2,
            _ => return GpuResponse::ErrInvalidParameter,
        };
        let (version, size) = self.renderer.get_cap_set_info(id);
        GpuResponse::OkCapsetInfo { id, version, size }
    }

    /// Gets the capset of `version` associated with `id`.
    pub fn get_capset(&self, id: u32, version: u32) -> GpuResponse {
        GpuResponse::OkCapset(self.renderer.get_cap_set(id, version))
    }

    /// Creates a fresh renderer context with the given `id`.
    pub fn create_renderer_context(&mut self, id: u32) -> GpuResponse {
        if id == 0 {
            return GpuResponse::ErrInvalidContextId;
        }
        match self.contexts.entry(id) {
            Entry::Occupied(_) => GpuResponse::ErrInvalidContextId,
            Entry::Vacant(slot) => match self.renderer.create_context(id) {
                Ok(ctx) => {
                    slot.insert(ctx);
                    GpuResponse::OkNoData
                }
                Err(e) => {
                    error!("failed to create renderer ctx: {}", e);
                    GpuResponse::ErrUnspec
                }
            },
        }
    }

    /// Destorys the renderer context associated with `id`.
    pub fn destroy_renderer_context(&mut self, id: u32) -> GpuResponse {
        match self.contexts.remove(&id) {
            Some(_) => GpuResponse::OkNoData,
            None => GpuResponse::ErrInvalidContextId,
        }
    }

    /// Attaches the indicated resource to the given context.
    pub fn context_attach_resource(&mut self, ctx_id: u32, res_id: u32) -> GpuResponse {
        match (
            self.contexts.get_mut(&ctx_id),
            self.resources
                .get_mut(&res_id)
                .and_then(|res| res.gpu_renderer_resource()),
        ) {
            (Some(ctx), Some(res)) => {
                ctx.attach(res);
                GpuResponse::OkNoData
            }
            (None, _) => GpuResponse::ErrInvalidContextId,
            (_, None) => GpuResponse::ErrInvalidResourceId,
        }
    }

    /// detaches the indicated resource to the given context.
    pub fn context_detach_resource(&mut self, ctx_id: u32, res_id: u32) -> GpuResponse {
        match (
            self.contexts.get_mut(&ctx_id),
            self.resources
                .get_mut(&res_id)
                .and_then(|res| res.gpu_renderer_resource()),
        ) {
            (Some(ctx), Some(res)) => {
                ctx.detach(res);
                GpuResponse::OkNoData
            }
            (None, _) => GpuResponse::ErrInvalidContextId,
            (_, None) => GpuResponse::ErrInvalidResourceId,
        }
    }

    pub fn allocate_using_minigbm(args: ResourceCreateArgs) -> bool {
        args.bind & VIRGL_RES_BIND_SCANOUT != 0
            && args.depth == 1
            && args.array_size == 1
            && args.last_level == 0
            && args.nr_samples == 0
    }

    /// Creates a 3D resource with the given properties and associated it with the given id.
    pub fn resource_create_3d(
        &mut self,
        id: u32,
        target: u32,
        format: u32,
        bind: u32,
        width: u32,
        height: u32,
        depth: u32,
        array_size: u32,
        last_level: u32,
        nr_samples: u32,
        flags: u32,
    ) -> GpuResponse {
        if id == 0 {
            return GpuResponse::ErrInvalidResourceId;
        }

        let create_args = ResourceCreateArgs {
            handle: id,
            target,
            format,
            bind,
            width,
            height,
            depth,
            array_size,
            last_level,
            nr_samples,
            flags,
        };

        match self.resources.entry(id) {
            Entry::Occupied(_) => GpuResponse::ErrInvalidResourceId,
            Entry::Vacant(slot) => {
                if Backend::allocate_using_minigbm(create_args) {
                    match renderer_fourcc(create_args.format) {
                        Some(fourcc) => {
                            let buffer = match self.device.create_buffer(
                                width,
                                height,
                                Format::from(fourcc),
                                Flags::empty().use_scanout(true).use_rendering(true),
                            ) {
                                Ok(buffer) => buffer,
                                Err(_) => {
                                    // Attempt to allocate the buffer without scanout flag.
                                    match self.device.create_buffer(
                                        width,
                                        height,
                                        Format::from(fourcc),
                                        Flags::empty().use_rendering(true),
                                    ) {
                                        Ok(buffer) => buffer,
                                        Err(e) => {
                                            error!(
                                                "failed to create buffer for 3d resource {}: {}",
                                                format, e
                                            );
                                            return GpuResponse::ErrUnspec;
                                        }
                                    }
                                }
                            };

                            let dma_buf_fd = match buffer.export_plane_fd(0) {
                                Ok(dma_buf_fd) => dma_buf_fd,
                                Err(e) => {
                                    error!("failed to export plane fd: {}", e);
                                    return GpuResponse::ErrUnspec;
                                }
                            };

                            let image = match self.renderer.image_from_dmabuf(
                                fourcc,
                                width,
                                height,
                                dma_buf_fd.as_raw_fd(),
                                buffer.plane_offset(0),
                                buffer.plane_stride(0),
                            ) {
                                Ok(image) => image,
                                Err(e) => {
                                    error!("failed to create egl image: {}", e);
                                    return GpuResponse::ErrUnspec;
                                }
                            };

                            let res = self.renderer.import_resource(create_args, &image);
                            match res {
                                Ok(res) => {
                                    let format_modifier = buffer.format_modifier();
                                    let mut plane_info = Vec::with_capacity(buffer.num_planes());
                                    for plane_index in 0..buffer.num_planes() {
                                        plane_info.push(GpuResponsePlaneInfo {
                                            stride: buffer.plane_stride(plane_index),
                                            offset: buffer.plane_offset(plane_index),
                                        });
                                    }
                                    let backed =
                                        BackedBuffer::new_renderer_registered(buffer, res, image);
                                    slot.insert(Box::new(backed));
                                    GpuResponse::OkResourcePlaneInfo {
                                        format_modifier,
                                        plane_info,
                                    }
                                }
                                Err(e) => {
                                    error!("failed to import renderer resource: {}", e);
                                    GpuResponse::ErrUnspec
                                }
                            }
                        }
                        None => {
                            warn!(
                                "failed to get fourcc for minigbm 3d resource {}, falling back",
                                format
                            );
                            let res = self.renderer.create_resource(create_args);
                            match res {
                                Ok(res) => {
                                    slot.insert(Box::new(res));
                                    GpuResponse::OkNoData
                                }
                                Err(e) => {
                                    error!("failed to create renderer resource: {}", e);
                                    GpuResponse::ErrUnspec
                                }
                            }
                        }
                    }
                } else {
                    let res = self.renderer.create_resource(create_args);
                    match res {
                        Ok(res) => {
                            slot.insert(Box::new(res));
                            GpuResponse::OkNoData
                        }
                        Err(e) => {
                            error!("failed to create renderer resource: {}", e);
                            GpuResponse::ErrUnspec
                        }
                    }
                }
            }
        }
    }

    /// Copes the given 3D rectangle of pixels of the given resource's backing memory to the host
    /// side resource.
    pub fn transfer_to_resource_3d(
        &mut self,
        ctx_id: u32,
        res_id: u32,
        x: u32,
        y: u32,
        z: u32,
        width: u32,
        height: u32,
        depth: u32,
        level: u32,
        stride: u32,
        layer_stride: u32,
        offset: u64,
    ) -> GpuResponse {
        let ctx = match ctx_id {
            0 => None,
            id => match self.contexts.get(&id) {
                None => return GpuResponse::ErrInvalidContextId,
                ctx => ctx,
            },
        };
        match self.resources.get_mut(&res_id) {
            Some(res) => match res.gpu_renderer_resource() {
                Some(res) => {
                    let transfer_box = Box3 {
                        x,
                        y,
                        z,
                        w: width,
                        h: height,
                        d: depth,
                    };
                    let res =
                        res.transfer_write(ctx, level, stride, layer_stride, transfer_box, offset);
                    match res {
                        Ok(_) => GpuResponse::OkNoData,
                        Err(e) => {
                            error!("failed to transfer to host: {}", e);
                            GpuResponse::ErrUnspec
                        }
                    }
                }
                None => GpuResponse::ErrInvalidResourceId,
            },
            None => GpuResponse::ErrInvalidResourceId,
        }
    }

    /// Copes the given rectangle of pixels from the resource to the given resource's backing
    /// memory.
    pub fn transfer_from_resource_3d(
        &mut self,
        ctx_id: u32,
        res_id: u32,
        x: u32,
        y: u32,
        z: u32,
        width: u32,
        height: u32,
        depth: u32,
        level: u32,
        stride: u32,
        layer_stride: u32,
        offset: u64,
    ) -> GpuResponse {
        let ctx = match ctx_id {
            0 => None,
            id => match self.contexts.get(&id) {
                None => return GpuResponse::ErrInvalidContextId,
                ctx => ctx,
            },
        };
        match self.resources.get_mut(&res_id) {
            Some(res) => match res.gpu_renderer_resource() {
                Some(res) => {
                    let transfer_box = Box3 {
                        x,
                        y,
                        z,
                        w: width,
                        h: height,
                        d: depth,
                    };
                    let res =
                        res.transfer_read(ctx, level, stride, layer_stride, transfer_box, offset);
                    match res {
                        Ok(_) => GpuResponse::OkNoData,
                        Err(e) => {
                            error!("failed to transfer from host: {}", e);
                            GpuResponse::ErrUnspec
                        }
                    }
                }
                None => GpuResponse::ErrInvalidResourceId,
            },
            None => GpuResponse::ErrInvalidResourceId,
        }
    }

    /// Submits a command buffer to the given rendering context.
    pub fn submit_command(&mut self, ctx_id: u32, commands: &mut [u8]) -> GpuResponse {
        match self.contexts.get_mut(&ctx_id) {
            Some(ctx) => match ctx.submit(&mut commands[..]) {
                Ok(_) => GpuResponse::OkNoData,
                Err(e) => {
                    error!("failed to submit command buffer: {}", e);
                    GpuResponse::ErrUnspec
                }
            },
            None => GpuResponse::ErrInvalidContextId,
        }
    }

    pub fn create_fence(&mut self, ctx_id: u32, fence_id: u32) -> GpuResponse {
        // There is a mismatch of ordering that is intentional.
        // This create_fence matches the other functions in Backend, yet
        // the renderer matches the virgl interface.
        match self.renderer.create_fence(fence_id, ctx_id) {
            Ok(_) => GpuResponse::OkNoData,
            Err(e) => {
                error!("failed to create fence: {}", e);
                GpuResponse::ErrUnspec
            }
        }
    }

    pub fn fence_poll(&mut self) -> u32 {
        self.renderer.poll()
    }

    pub fn force_ctx_0(&mut self) {
        self.renderer.force_ctx_0();
    }
}

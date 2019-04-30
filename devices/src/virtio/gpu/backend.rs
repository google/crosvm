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
use resources::Alloc;
use sys_util::{error, GuestAddress, GuestMemory};

use gpu_display::*;
use gpu_renderer::{
    Box3, Context as RendererContext, Renderer, Resource as GpuRendererResource, ResourceCreateArgs,
};

use super::protocol::{
    AllocationMetadataResponse, GpuResponse, GpuResponsePlaneInfo, VIRTIO_GPU_CAPSET3,
    VIRTIO_GPU_CAPSET_VIRGL, VIRTIO_GPU_CAPSET_VIRGL2, VIRTIO_GPU_MEMORY_HOST_COHERENT,
};
use crate::virtio::resource_bridge::*;

use vm_control::{MaybeOwnedFd, VmMemoryControlRequestSocket, VmMemoryRequest, VmMemoryResponse};

const DEFAULT_WIDTH: u32 = 1280;
const DEFAULT_HEIGHT: u32 = 1024;

struct VirtioGpuResource {
    width: u32,
    height: u32,
    gpu_resource: GpuRendererResource,
    display_import: Option<(Rc<RefCell<GpuDisplay>>, u32)>,
    kvm_slot: Option<u32>,
}

impl VirtioGpuResource {
    pub fn new(width: u32, height: u32, gpu_resource: GpuRendererResource) -> VirtioGpuResource {
        VirtioGpuResource {
            width,
            height,
            gpu_resource,
            display_import: None,
            kvm_slot: None,
        }
    }

    pub fn v2_new(kvm_slot: u32, gpu_resource: GpuRendererResource) -> VirtioGpuResource {
        // Choose DEFAULT_WIDTH and DEFAULT_HEIGHT, since that matches the default modes
        // for virtgpu-kms.
        VirtioGpuResource {
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            gpu_resource,
            display_import: None,
            kvm_slot: Some(kvm_slot),
        }
    }

    pub fn import_to_display(&mut self, display: &Rc<RefCell<GpuDisplay>>) -> Option<u32> {
        if let Some((self_display, import)) = &self.display_import {
            if Rc::ptr_eq(self_display, display) {
                return Some(*import);
            }
        }

        let (query, dmabuf) = match self.gpu_resource.export() {
            Ok(export) => (export.0, export.1),
            Err(e) => {
                error!("failed to query resource: {}", e);
                return None;
            }
        };

        match display.borrow_mut().import_dmabuf(
            dmabuf.as_raw_fd(),
            query.out_offsets[0],
            query.out_strides[0],
            query.out_modifier,
            self.width,
            self.height,
            query.out_fourcc,
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

    pub fn write_from_guest_memory(
        &mut self,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        src_offset: u64,
        _mem: &GuestMemory,
    ) {
        let res = self.gpu_resource.transfer_write(
            None,
            0,
            0,
            0,
            Box3::new_2d(x, y, width, height),
            src_offset,
        );
        if let Err(e) = res {
            error!(
                "failed to write to resource (x={} y={} w={} h={}, src_offset={}): {}",
                x, y, width, height, src_offset, e
            );
        }
    }

    pub fn read_to_volatile(
        &mut self,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        dst: VolatileSlice,
        dst_stride: u32,
    ) {
        let res = self.gpu_resource.read_to_volatile(
            None,
            0,
            dst_stride,
            0, /* layer_stride */
            Box3::new_2d(x, y, width, height),
            0, /* offset */
            dst,
        );
        if let Err(e) = res {
            error!("failed to read from resource: {}", e);
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
    renderer: Renderer,
    resources: Map<u32, VirtioGpuResource>,
    contexts: Map<u32, RendererContext>,
    gpu_device_socket: VmMemoryControlRequestSocket,
    scanout_surface: Option<u32>,
    cursor_surface: Option<u32>,
    scanout_resource: u32,
    cursor_resource: u32,
    pci_bar: Alloc,
}

impl Backend {
    /// Creates a new backend for virtio-gpu that realizes all commands using the given `display`
    /// for showing the results, and `renderer` for submitting rendering commands.
    ///
    /// All buffer allocations will be done internally by the renderer or the display and buffer
    /// data is copied as needed.
    pub fn new(
        display: GpuDisplay,
        renderer: Renderer,
        gpu_device_socket: VmMemoryControlRequestSocket,
        pci_bar: Alloc,
    ) -> Backend {
        Backend {
            display: Rc::new(RefCell::new(display)),
            renderer,
            gpu_device_socket,
            resources: Default::default(),
            contexts: Default::default(),
            scanout_surface: None,
            cursor_surface: None,
            scanout_resource: 0,
            cursor_resource: 0,
            pci_bar,
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
                .and_then(|resource| resource.gpu_resource.export().ok())
                .and_then(|export| Some(export.1))
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
        format: u32,
    ) -> GpuResponse {
        if id == 0 {
            return GpuResponse::ErrInvalidResourceId;
        }
        match self.resources.entry(id) {
            Entry::Vacant(slot) => {
                let gpu_resource = self.renderer.create_resource_2d(id, width, height, format);
                match gpu_resource {
                    Ok(gpu_resource) => {
                        let virtio_gpu_resource =
                            VirtioGpuResource::new(width, height, gpu_resource);
                        slot.insert(virtio_gpu_resource);
                        GpuResponse::OkNoData
                    }
                    Err(e) => {
                        error!("failed to create renderer resource: {}", e);
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
        _x: u32,
        _y: u32,
        _width: u32,
        _height: u32,
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
        let mut display = self.display.borrow_mut();
        // Prevent overwriting a buffer that is currently being used by the compositor.
        if display.next_buffer_in_use(surface_id) {
            return GpuResponse::OkNoData;
        }

        let fb = match display.framebuffer_region(surface_id, 0, 0, DEFAULT_WIDTH, DEFAULT_HEIGHT) {
            Some(fb) => fb,
            None => {
                error!("failed to access framebuffer for surface {}", surface_id);
                return GpuResponse::ErrUnspec;
            }
        };

        resource.read_to_volatile(
            0,
            0,
            DEFAULT_WIDTH,
            DEFAULT_HEIGHT,
            fb.as_volatile_slice(),
            fb.stride(),
        );
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
            Some(resource) => match resource.gpu_resource.attach_backing(&vecs[..], mem) {
                Ok(_) => GpuResponse::OkNoData,
                Err(_) => GpuResponse::ErrUnspec,
            },
            None => GpuResponse::ErrInvalidResourceId,
        }
    }

    /// Detaches any backing memory from the given resource, if there is any.
    pub fn detach_backing(&mut self, id: u32) -> GpuResponse {
        match self.resources.get_mut(&id) {
            Some(resource) => {
                resource.gpu_resource.detach_backing();
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
                    resource.width,
                    resource.height,
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
            if let Some(fb) = self.display.borrow_mut().framebuffer(cursor_surface) {
                resource.read_to_volatile(
                    0,
                    0,
                    resource.width,
                    resource.height,
                    fb.as_volatile_slice(),
                    fb.stride(),
                )
            }
            self.display.borrow_mut().flip(cursor_surface);
            GpuResponse::OkNoData
        } else {
            GpuResponse::ErrInvalidResourceId
        }
    }

    /// Moves the cursor's position to the given coordinates.
    pub fn move_cursor(&mut self, x: u32, y: u32) -> GpuResponse {
        if let Some(cursor_surface) = self.cursor_surface {
            if let Some(scanout_surface) = self.scanout_surface {
                let mut display = self.display.borrow_mut();
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
            2 => VIRTIO_GPU_CAPSET3,
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
            self.resources.get_mut(&res_id),
        ) {
            (Some(ctx), Some(res)) => {
                ctx.attach(&res.gpu_resource);
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
            self.resources.get_mut(&res_id),
        ) {
            (Some(ctx), Some(res)) => {
                ctx.detach(&res.gpu_resource);
                GpuResponse::OkNoData
            }
            (None, _) => GpuResponse::ErrInvalidContextId,
            (_, None) => GpuResponse::ErrInvalidResourceId,
        }
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
                let gpu_resource = self.renderer.create_resource(create_args);
                match gpu_resource {
                    Ok(gpu_resource) => {
                        let query = match gpu_resource.query() {
                            Ok(query) => query,
                            Err(_) => return GpuResponse::ErrUnspec,
                        };

                        let response = match query.out_num_fds {
                            0 => GpuResponse::OkNoData,
                            1 => {
                                let mut plane_info = Vec::with_capacity(4);
                                for plane_index in 0..4 {
                                    plane_info.push(GpuResponsePlaneInfo {
                                        stride: query.out_strides[plane_index],
                                        offset: query.out_offsets[plane_index],
                                    });
                                }

                                let format_modifier = query.out_modifier;
                                GpuResponse::OkResourcePlaneInfo {
                                    format_modifier,
                                    plane_info,
                                }
                            }
                            _ => return GpuResponse::ErrUnspec,
                        };

                        let virtio_gpu_resource =
                            VirtioGpuResource::new(width, height, gpu_resource);
                        slot.insert(virtio_gpu_resource);
                        response
                    }
                    Err(e) => {
                        error!("failed to create renderer resource: {}", e);
                        GpuResponse::ErrUnspec
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
            Some(res) => {
                let transfer_box = Box3 {
                    x,
                    y,
                    z,
                    w: width,
                    h: height,
                    d: depth,
                };
                let res = res.gpu_resource.transfer_write(
                    ctx,
                    level,
                    stride,
                    layer_stride,
                    transfer_box,
                    offset,
                );
                match res {
                    Ok(_) => GpuResponse::OkNoData,
                    Err(e) => {
                        error!("failed to transfer to host: {}", e);
                        GpuResponse::ErrUnspec
                    }
                }
            }
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
            Some(res) => {
                let transfer_box = Box3 {
                    x,
                    y,
                    z,
                    w: width,
                    h: height,
                    d: depth,
                };
                let res = res.gpu_resource.transfer_read(
                    ctx,
                    level,
                    stride,
                    layer_stride,
                    transfer_box,
                    offset,
                );
                match res {
                    Ok(_) => GpuResponse::OkNoData,
                    Err(e) => {
                        error!("failed to transfer from host: {}", e);
                        GpuResponse::ErrUnspec
                    }
                }
            }
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

    pub fn allocation_metadata(
        &mut self,
        request_id: u32,
        request: Vec<u8>,
        mut response: Vec<u8>,
    ) -> GpuResponse {
        let res = self.renderer.allocation_metadata(&request, &mut response);

        match res {
            Ok(_) => {
                let res_info = AllocationMetadataResponse {
                    request_id,
                    response,
                };

                GpuResponse::OkAllocationMetadata { res_info }
            }
            Err(_) => {
                error!("failed to get metadata");
                GpuResponse::ErrUnspec
            }
        }
    }

    pub fn resource_create_v2(
        &mut self,
        resource_id: u32,
        guest_memory_type: u32,
        guest_caching_type: u32,
        size: u64,
        pci_addr: u64,
        mem: &GuestMemory,
        vecs: Vec<(GuestAddress, usize)>,
        args: Vec<u8>,
    ) -> GpuResponse {
        match self.resources.entry(resource_id) {
            Entry::Vacant(entry) => {
                let resource = match self.renderer.resource_create_v2(
                    resource_id,
                    guest_memory_type,
                    guest_caching_type,
                    size,
                    mem,
                    &vecs,
                    &args,
                ) {
                    Ok(resource) => resource,
                    Err(e) => {
                        error!("failed to create resource: {}", e);
                        return GpuResponse::ErrUnspec;
                    }
                };

                match guest_memory_type {
                    VIRTIO_GPU_MEMORY_HOST_COHERENT => {
                        let dma_buf_fd = match resource.export() {
                            Ok(export) => export.1,
                            Err(e) => {
                                error!("failed to export plane fd: {}", e);
                                return GpuResponse::ErrUnspec;
                            }
                        };

                        let request = VmMemoryRequest::RegisterMemoryAtAddress(
                            self.pci_bar,
                            MaybeOwnedFd::Borrowed(dma_buf_fd.as_raw_fd()),
                            size as usize,
                            pci_addr,
                        );

                        match self.gpu_device_socket.send(&request) {
                            Ok(_resq) => match self.gpu_device_socket.recv() {
                                Ok(response) => match response {
                                    VmMemoryResponse::RegisterMemory { pfn: _, slot } => {
                                        entry.insert(VirtioGpuResource::v2_new(slot, resource));
                                        GpuResponse::OkNoData
                                    }
                                    VmMemoryResponse::Err(e) => {
                                        error!("received an error: {}", e);
                                        GpuResponse::ErrUnspec
                                    }
                                    _ => {
                                        error!("recieved an unexpected response");
                                        GpuResponse::ErrUnspec
                                    }
                                },
                                Err(e) => {
                                    error!("failed to receive data: {}", e);
                                    GpuResponse::ErrUnspec
                                }
                            },
                            Err(e) => {
                                error!("failed to send request: {}", e);
                                GpuResponse::ErrUnspec
                            }
                        }
                    }
                    _ => {
                        entry.insert(VirtioGpuResource::new(
                            DEFAULT_WIDTH,
                            DEFAULT_HEIGHT,
                            resource,
                        ));

                        GpuResponse::OkNoData
                    }
                }
            }
            Entry::Occupied(_) => GpuResponse::ErrInvalidResourceId,
        }
    }

    pub fn resource_v2_unref(&mut self, resource_id: u32) -> GpuResponse {
        match self.resources.remove(&resource_id) {
            Some(entry) => match entry.kvm_slot {
                Some(kvm_slot) => {
                    let request = VmMemoryRequest::UnregisterMemory(kvm_slot);
                    match self.gpu_device_socket.send(&request) {
                        Ok(_resq) => match self.gpu_device_socket.recv() {
                            Ok(response) => match response {
                                VmMemoryResponse::Ok => GpuResponse::OkNoData,
                                VmMemoryResponse::Err(e) => {
                                    error!("received an error: {}", e);
                                    GpuResponse::ErrUnspec
                                }
                                _ => {
                                    error!("recieved an unexpected response");
                                    GpuResponse::ErrUnspec
                                }
                            },
                            Err(e) => {
                                error!("failed to receive data: {}", e);
                                GpuResponse::ErrUnspec
                            }
                        },
                        Err(e) => {
                            error!("failed to send request: {}", e);
                            GpuResponse::ErrUnspec
                        }
                    }
                }
                None => GpuResponse::OkNoData,
            },
            None => GpuResponse::ErrInvalidResourceId,
        }
    }
}

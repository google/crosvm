// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implementation of a virtio-gpu protocol command processor which supports display and accelerated
//! rendering.

use std::cell::RefCell;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap as Map;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::rc::Rc;
use std::usize;

use libc::EINVAL;

use data_model::*;
use msg_socket::{MsgReceiver, MsgSender};
use resources::Alloc;
use sys_util::{error, warn, Error, GuestAddress, GuestMemory};

use gpu_display::*;
use gpu_renderer::{
    Box3, Context as RendererContext, Error as GpuRendererError, Renderer, RendererFlags,
    Resource as GpuRendererResource, ResourceCreateArgs,
};

use super::protocol::{
    AllocationMetadataResponse, GpuResponse, GpuResponsePlaneInfo, VIRTIO_GPU_CAPSET3,
    VIRTIO_GPU_CAPSET_VIRGL, VIRTIO_GPU_CAPSET_VIRGL2, VIRTIO_GPU_MEMORY_HOST_COHERENT,
};
pub use crate::virtio::gpu::virtio_backend::{VirtioBackend, VirtioResource};
use crate::virtio::gpu::{
    Backend, DisplayBackend, VIRTIO_F_VERSION_1, VIRTIO_GPU_F_HOST_COHERENT, VIRTIO_GPU_F_MEMORY,
    VIRTIO_GPU_F_VIRGL,
};

use vm_control::{MaybeOwnedFd, VmMemoryControlRequestSocket, VmMemoryRequest, VmMemoryResponse};

struct Virtio3DResource {
    width: u32,
    height: u32,
    gpu_resource: GpuRendererResource,
    display_import: Option<(Rc<RefCell<GpuDisplay>>, u32)>,
    kvm_slot: Option<u32>,
}

impl Virtio3DResource {
    pub fn new(width: u32, height: u32, gpu_resource: GpuRendererResource) -> Virtio3DResource {
        Virtio3DResource {
            width,
            height,
            gpu_resource,
            display_import: None,
            kvm_slot: None,
        }
    }

    pub fn v2_new(
        width: u32,
        height: u32,
        kvm_slot: u32,
        gpu_resource: GpuRendererResource,
    ) -> Virtio3DResource {
        Virtio3DResource {
            width,
            height,
            gpu_resource,
            display_import: None,
            kvm_slot: Some(kvm_slot),
        }
    }

    fn as_mut(&mut self) -> &mut dyn VirtioResource {
        self
    }
}

impl VirtioResource for Virtio3DResource {
    fn width(&self) -> u32 {
        self.width
    }

    fn height(&self) -> u32 {
        self.height
    }

    fn import_to_display(&mut self, display: &Rc<RefCell<GpuDisplay>>) -> Option<u32> {
        if let Some((self_display, import)) = &self.display_import {
            if Rc::ptr_eq(self_display, display) {
                return Some(*import);
            }
        }

        let (query, dmabuf) = match self.gpu_resource.export() {
            Ok(export) => (export.0, export.1),
            Err(GpuRendererError::Virglrenderer(e)) if e == -EINVAL => return None,
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

    fn write_from_guest_memory(
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

    fn read_to_volatile(
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

/// The virtio-gpu backend state tracker which supports accelerated rendering.
pub struct Virtio3DBackend {
    base: VirtioBackend,
    renderer: Renderer,
    resources: Map<u32, Virtio3DResource>,
    contexts: Map<u32, RendererContext>,
    gpu_device_socket: VmMemoryControlRequestSocket,
    pci_bar: Alloc,
}

impl Virtio3DBackend {
    /// Creates a new backend for virtio-gpu that realizes all commands using the given `display`
    /// for showing the results, and `renderer` for submitting rendering commands.
    ///
    /// All buffer allocations will be done internally by the renderer or the display and buffer
    /// data is copied as needed.
    pub fn new(
        display: GpuDisplay,
        display_width: u32,
        display_height: u32,
        renderer: Renderer,
        gpu_device_socket: VmMemoryControlRequestSocket,
        pci_bar: Alloc,
    ) -> Virtio3DBackend {
        Virtio3DBackend {
            base: VirtioBackend {
                display: Rc::new(RefCell::new(display)),
                display_width,
                display_height,
                event_devices: Default::default(),
                scanout_resource_id: None,
                scanout_surface_id: None,
                cursor_resource_id: None,
                cursor_surface_id: None,
            },
            renderer,
            resources: Default::default(),
            contexts: Default::default(),
            gpu_device_socket,
            pci_bar,
        }
    }
}

impl Backend for Virtio3DBackend {
    /// Returns the number of capsets provided by the Backend.
    fn capsets() -> u32 {
        3
    }

    /// Returns the bitset of virtio features provided by the Backend.
    fn features() -> u64 {
        1 << VIRTIO_GPU_F_VIRGL
            | 1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_GPU_F_MEMORY
            | 1 << VIRTIO_GPU_F_HOST_COHERENT
    }

    /// Returns the underlying Backend.
    fn build(
        possible_displays: &[DisplayBackend],
        display_width: u32,
        display_height: u32,
        renderer_flags: RendererFlags,
        event_devices: Vec<EventDevice>,
        gpu_device_socket: VmMemoryControlRequestSocket,
        pci_bar: Alloc,
    ) -> Option<Box<dyn Backend>> {
        let mut renderer_flags = renderer_flags;
        let mut display_opt = None;
        for display in possible_displays {
            match display.build() {
                Ok(c) => {
                    // If X11 is being used, that's an indication that the renderer should also be
                    // using glx. Otherwise, we are likely in an enviroment in which GBM will work
                    // for doing allocations of buffers we wish to display. TODO(zachr): this is a
                    // heuristic (or terrible hack depending on your POV). We should do something
                    // either smarter or more configurable.
                    if display.is_x() {
                        renderer_flags = RendererFlags::new().use_glx(true);
                    }
                    display_opt = Some(c);
                    break;
                }
                Err(e) => error!("failed to open display: {}", e),
            };
        }
        let display = match display_opt {
            Some(d) => d,
            None => {
                error!("failed to open any displays");
                return None;
            }
        };

        if cfg!(debug_assertions) {
            let ret = unsafe { libc::dup2(libc::STDOUT_FILENO, libc::STDERR_FILENO) };
            if ret == -1 {
                warn!("unable to dup2 stdout to stderr: {}", Error::last());
            }
        }

        let renderer = match Renderer::init(renderer_flags) {
            Ok(r) => r,
            Err(e) => {
                error!("failed to initialize gpu renderer: {}", e);
                return None;
            }
        };

        let mut backend_3d = Virtio3DBackend::new(
            display,
            display_width,
            display_height,
            renderer,
            gpu_device_socket,
            pci_bar,
        );

        for event_device in event_devices {
            backend_3d.import_event_device(event_device, 0);
        }

        Some(Box::new(backend_3d))
    }

    /// Gets a reference to the display passed into `new`.
    fn display(&self) -> &Rc<RefCell<GpuDisplay>> {
        &self.base.display
    }

    /// Processes the internal `display` events and returns `true` if the main display was closed.
    fn process_display(&mut self) -> bool {
        self.base.process_display()
    }

    /// Gets the list of supported display resolutions as a slice of `(width, height)` tuples.
    fn display_info(&self) -> [(u32, u32); 1] {
        self.base.display_info()
    }

    /// Attaches the given input device to the given surface of the display (to allow for input
    /// from an X11 window for example).
    fn import_event_device(&mut self, event_device: EventDevice, scanout: u32) {
        self.base.import_event_device(event_device, scanout);
    }

    /// If supported, export the resource with the given id to a file.
    fn export_resource(&mut self, id: u32) -> Option<File> {
        let test: Option<File> = self
            .resources
            .get(&id) // Option<resource>
            .and_then(|resource| resource.gpu_resource.export().ok()) // Option<(Query, File)>
            .and_then(|t| Some(t.1)); // Option<File>
        return test;
    }

    /// Creates a fence with the given id that can be used to determine when the previous command
    /// completed.
    fn create_fence(&mut self, ctx_id: u32, fence_id: u32) -> GpuResponse {
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

    /// Returns the id of the latest fence to complete.
    fn fence_poll(&mut self) -> u32 {
        self.renderer.poll()
    }

    fn force_ctx_0(&mut self) {
        self.renderer.force_ctx_0();
    }

    /// Creates a 2D resource with the given properties and associated it with the given id.
    fn create_resource_2d(&mut self, id: u32, width: u32, height: u32, format: u32) -> GpuResponse {
        if id == 0 {
            return GpuResponse::ErrInvalidResourceId;
        }
        match self.resources.entry(id) {
            Entry::Vacant(slot) => {
                let gpu_resource = self.renderer.create_resource_2d(id, width, height, format);
                match gpu_resource {
                    Ok(gpu_resource) => {
                        let virtio_gpu_resource =
                            Virtio3DResource::new(width, height, gpu_resource);
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
    fn unref_resource(&mut self, id: u32) -> GpuResponse {
        match self.resources.remove(&id) {
            Some(_) => GpuResponse::OkNoData,
            None => GpuResponse::ErrInvalidResourceId,
        }
    }

    /// Sets the given resource id as the source of scanout to the display.
    fn set_scanout(&mut self, _scanout_id: u32, resource_id: u32) -> GpuResponse {
        if resource_id == 0 || self.resources.get_mut(&resource_id).is_some() {
            self.base.set_scanout(resource_id)
        } else {
            GpuResponse::ErrInvalidResourceId
        }
    }

    /// Flushes the given rectangle of pixels of the given resource to the display.
    fn flush_resource(
        &mut self,
        id: u32,
        _x: u32,
        _y: u32,
        _width: u32,
        _height: u32,
    ) -> GpuResponse {
        if id == 0 {
            return GpuResponse::OkNoData;
        }

        let resource = match self.resources.get_mut(&id) {
            Some(r) => r,
            None => return GpuResponse::ErrInvalidResourceId,
        };

        self.base.flush_resource(resource, id)
    }

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
    fn attach_backing(
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
    fn detach_backing(&mut self, id: u32) -> GpuResponse {
        match self.resources.get_mut(&id) {
            Some(resource) => {
                resource.gpu_resource.detach_backing();
                GpuResponse::OkNoData
            }
            None => GpuResponse::ErrInvalidResourceId,
        }
    }

    /// Updates the cursor's memory to the given id, and sets its position to the given coordinates.
    fn update_cursor(&mut self, id: u32, x: u32, y: u32) -> GpuResponse {
        let resource = self.resources.get_mut(&id).map(|r| r.as_mut());

        self.base.update_cursor(id, x, y, resource)
    }

    /// Moves the cursor's position to the given coordinates.
    fn move_cursor(&mut self, x: u32, y: u32) -> GpuResponse {
        self.base.move_cursor(x, y)
    }

    /// Gets the renderer's capset information associated with `index`.
    fn get_capset_info(&self, index: u32) -> GpuResponse {
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
    fn get_capset(&self, id: u32, version: u32) -> GpuResponse {
        GpuResponse::OkCapset(self.renderer.get_cap_set(id, version))
    }

    /// Creates a fresh renderer context with the given `id`.
    fn create_renderer_context(&mut self, id: u32) -> GpuResponse {
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
    fn destroy_renderer_context(&mut self, id: u32) -> GpuResponse {
        match self.contexts.remove(&id) {
            Some(_) => GpuResponse::OkNoData,
            None => GpuResponse::ErrInvalidContextId,
        }
    }

    /// Attaches the indicated resource to the given context.
    fn context_attach_resource(&mut self, ctx_id: u32, res_id: u32) -> GpuResponse {
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
    fn context_detach_resource(&mut self, ctx_id: u32, res_id: u32) -> GpuResponse {
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
    fn resource_create_3d(
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
                            Virtio3DResource::new(width, height, gpu_resource);
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
    fn transfer_to_resource_3d(
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
    fn transfer_from_resource_3d(
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
    fn submit_command(&mut self, ctx_id: u32, commands: &mut [u8]) -> GpuResponse {
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

    fn allocation_metadata(
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

    fn resource_create_v2(
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
                                        entry.insert(Virtio3DResource::v2_new(
                                            self.base.display_width,
                                            self.base.display_height,
                                            slot,
                                            resource,
                                        ));
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
                        entry.insert(Virtio3DResource::new(
                            self.base.display_width,
                            self.base.display_height,
                            resource,
                        ));

                        GpuResponse::OkNoData
                    }
                }
            }
            Entry::Occupied(_) => GpuResponse::ErrInvalidResourceId,
        }
    }

    fn resource_v2_unref(&mut self, resource_id: u32) -> GpuResponse {
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

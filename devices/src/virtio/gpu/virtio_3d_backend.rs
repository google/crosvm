// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implementation of a virtio-gpu protocol command processor which supports display and accelerated
//! rendering.

use std::cell::RefCell;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap as Map;
use std::os::unix::io::AsRawFd;
use std::rc::Rc;
use std::sync::Arc;
use std::usize;

use base::{error, warn, Error, ExternalMapping};
use data_model::*;
use msg_socket::{MsgReceiver, MsgSender};
use resources::Alloc;
use sync::Mutex;
use vm_memory::{GuestAddress, GuestMemory};

use gpu_display::*;
use gpu_renderer::{
    Box3, Context as RendererContext, Renderer, RendererFlags, Resource as GpuRendererResource,
    ResourceCreateArgs,
};

use super::protocol::{
    GpuResponse::*, GpuResponsePlaneInfo, VirtioGpuResult, VIRTIO_GPU_BLOB_FLAG_USE_MAPPABLE,
    VIRTIO_GPU_CAPSET3, VIRTIO_GPU_CAPSET_VIRGL, VIRTIO_GPU_CAPSET_VIRGL2,
};
pub use crate::virtio::gpu::virtio_backend::{VirtioBackend, VirtioResource};
use crate::virtio::gpu::{
    Backend, VirtioScanoutBlobData, VIRTIO_GPU_F_RESOURCE_BLOB, VIRTIO_GPU_F_RESOURCE_UUID,
    VIRTIO_GPU_F_VIRGL, VIRTIO_GPU_F_VULKAN,
};
use crate::virtio::resource_bridge::{PlaneInfo, ResourceInfo, ResourceResponse};

use vm_control::{
    MaybeOwnedFd, MemSlot, VmMemoryControlRequestSocket, VmMemoryRequest, VmMemoryResponse,
};

struct Virtio3DResource {
    width: u32,
    height: u32,
    gpu_resource: GpuRendererResource,
    display_import: Option<(Rc<RefCell<GpuDisplay>>, u32)>,
    slot: Option<MemSlot>,
    size: u64,
    blob_flags: u32,
    scanout_data: Option<VirtioScanoutBlobData>,
}

impl Virtio3DResource {
    pub fn new(width: u32, height: u32, gpu_resource: GpuRendererResource) -> Virtio3DResource {
        Virtio3DResource {
            width,
            height,
            gpu_resource,
            display_import: None,
            slot: None,
            blob_flags: 0,
            // The size of the host resource isn't really zero, but it's undefined by
            // virtio_gpu_resource_create_3d
            size: 0,
            scanout_data: None,
        }
    }

    pub fn blob_new(
        width: u32,
        height: u32,
        gpu_resource: GpuRendererResource,
        blob_flags: u32,
        size: u64,
    ) -> Virtio3DResource {
        Virtio3DResource {
            width,
            height,
            gpu_resource,
            display_import: None,
            slot: None,
            blob_flags,
            size,
            scanout_data: None,
        }
    }

    fn as_mut(&mut self) -> &mut dyn VirtioResource {
        self
    }

    fn response_from_query(&self) -> VirtioGpuResult {
        let query = self.gpu_resource.query()?;
        match query.out_num_fds {
            0 => Ok(OkNoData),
            1 => {
                let mut plane_info = Vec::with_capacity(4);
                for plane_index in 0..4 {
                    plane_info.push(GpuResponsePlaneInfo {
                        stride: query.out_strides[plane_index],
                        offset: query.out_offsets[plane_index],
                    });
                }

                let format_modifier = query.out_modifier;
                Ok(OkResourcePlaneInfo {
                    format_modifier,
                    plane_info,
                })
            }
            _ => Err(ErrUnspec),
        }
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

        let dmabuf = self.gpu_resource.export().ok()?;
        let query = self.gpu_resource.query().ok()?;

        let (width, height, format, stride, offset) = match self.scanout_data {
            Some(data) => (
                data.width,
                data.height,
                data.drm_format.into(),
                data.strides[0],
                data.offsets[0],
            ),
            None => (
                self.width,
                self.height,
                query.out_fourcc,
                query.out_strides[0],
                query.out_offsets[0],
            ),
        };

        match display.borrow_mut().import_dmabuf(
            dmabuf.as_raw_fd(),
            offset,
            stride,
            query.out_modifier,
            width,
            height,
            format,
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
    map_request: Arc<Mutex<Option<ExternalMapping>>>,
    external_blob: bool,
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
        map_request: Arc<Mutex<Option<ExternalMapping>>>,
        external_blob: bool,
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
            map_request,
            external_blob,
        }
    }
}

impl Backend for Virtio3DBackend {
    /// Returns the number of capsets provided by the Backend.
    fn capsets() -> u32 {
        3
    }

    fn features() -> u64 {
        1 << VIRTIO_GPU_F_VIRGL
            | 1 << VIRTIO_GPU_F_RESOURCE_UUID
            | 1 << VIRTIO_GPU_F_RESOURCE_BLOB
            | 1 << VIRTIO_GPU_F_VULKAN
    }

    /// Returns the underlying Backend.
    fn build(
        display: GpuDisplay,
        display_width: u32,
        display_height: u32,
        renderer_flags: RendererFlags,
        event_devices: Vec<EventDevice>,
        gpu_device_socket: VmMemoryControlRequestSocket,
        pci_bar: Alloc,
        map_request: Arc<Mutex<Option<ExternalMapping>>>,
        external_blob: bool,
    ) -> Option<Box<dyn Backend>> {
        let mut renderer_flags = renderer_flags;
        if display.is_x() {
            // If X11 is being used, that's an indication that the renderer should also be
            // using glx. Otherwise, we are likely in an enviroment in which GBM will work
            // for doing allocations of buffers we wish to display. TODO(zachr): this is a
            // heuristic (or terrible hack depending on your POV). We should do something
            // either smarter or more configurable.
            renderer_flags = RendererFlags::new().use_glx(true);
        }

        if cfg!(debug_assertions) {
            let ret = unsafe { libc::dup2(libc::STDOUT_FILENO, libc::STDERR_FILENO) };
            if ret == -1 {
                warn!("unable to dup2 stdout to stderr: {}", Error::last());
            }
        }

        renderer_flags.use_external_blob(external_blob);
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
            map_request,
            external_blob,
        );

        for event_device in event_devices {
            backend_3d
                .import_event_device(event_device, 0)
                .map_err(|e| error!("failed to import event device {}", e))
                .ok()?;
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
    fn import_event_device(&mut self, event_device: EventDevice, scanout: u32) -> VirtioGpuResult {
        self.base.import_event_device(event_device, scanout)
    }

    /// If supported, export the resource with the given id to a file.
    fn export_resource(&mut self, id: u32) -> ResourceResponse {
        let resource = match self.resources.get_mut(&id) {
            Some(r) => r,
            None => return ResourceResponse::Invalid,
        };

        let q = match resource.gpu_resource.query() {
            Ok(query) => query,
            Err(_) => return ResourceResponse::Invalid,
        };

        let file = match resource.gpu_resource.export() {
            Ok(file) => file,
            Err(_) => return ResourceResponse::Invalid,
        };

        ResourceResponse::Resource(ResourceInfo {
            file,
            planes: [
                PlaneInfo {
                    offset: q.out_offsets[0],
                    stride: q.out_strides[0],
                },
                PlaneInfo {
                    offset: q.out_offsets[1],
                    stride: q.out_strides[1],
                },
                PlaneInfo {
                    offset: q.out_offsets[2],
                    stride: q.out_strides[2],
                },
                PlaneInfo {
                    offset: q.out_offsets[3],
                    stride: q.out_strides[3],
                },
            ],
        })
    }

    /// Creates a fence with the given id that can be used to determine when the previous command
    /// completed.
    fn create_fence(&mut self, ctx_id: u32, fence_id: u32) -> VirtioGpuResult {
        // There is a mismatch of ordering that is intentional.
        // This create_fence matches the other functions in Backend, yet
        // the renderer matches the virgl interface.
        self.renderer.create_fence(fence_id, ctx_id)?;
        Ok(OkNoData)
    }

    /// Returns the id of the latest fence to complete.
    fn fence_poll(&mut self) -> u32 {
        self.renderer.poll()
    }

    fn force_ctx_0(&mut self) {
        self.renderer.force_ctx_0();
    }

    /// Creates a 2D resource with the given properties and associated it with the given id.
    fn create_resource_2d(
        &mut self,
        id: u32,
        width: u32,
        height: u32,
        format: u32,
    ) -> VirtioGpuResult {
        if id == 0 {
            return Err(ErrInvalidResourceId);
        }
        match self.resources.entry(id) {
            Entry::Vacant(slot) => {
                let gpu_resource = self
                    .renderer
                    .create_resource_2d(id, width, height, format)?;
                let virtio_gpu_resource = Virtio3DResource::new(width, height, gpu_resource);
                slot.insert(virtio_gpu_resource);
                Ok(OkNoData)
            }
            Entry::Occupied(_) => Err(ErrInvalidResourceId),
        }
    }

    /// Removes the guest's reference count for the given resource id.
    fn unref_resource(&mut self, id: u32) -> VirtioGpuResult {
        match self.resources.remove(&id) {
            Some(_) => Ok(OkNoData),
            None => Err(ErrInvalidResourceId),
        }
    }

    /// Sets the given resource id as the source of scanout to the display.
    fn set_scanout(
        &mut self,
        _scanout_id: u32,
        resource_id: u32,
        scanout_data: Option<VirtioScanoutBlobData>,
    ) -> VirtioGpuResult {
        if resource_id == 0 || self.resources.get_mut(&resource_id).is_some() {
            match self.resources.get_mut(&resource_id) {
                Some(resource) => resource.scanout_data = scanout_data,
                None => (),
            }
            self.base.set_scanout(resource_id)
        } else {
            Err(ErrInvalidResourceId)
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
    ) -> VirtioGpuResult {
        if id == 0 {
            return Ok(OkNoData);
        }

        let resource = self.resources.get_mut(&id).ok_or(ErrInvalidResourceId)?;
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
    ) -> VirtioGpuResult {
        let resource = self.resources.get_mut(&id).ok_or(ErrInvalidResourceId)?;
        resource.write_from_guest_memory(x, y, width, height, src_offset, mem);
        Ok(OkNoData)
    }

    /// Attaches backing memory to the given resource, represented by a `Vec` of `(address, size)`
    /// tuples in the guest's physical address space.
    fn attach_backing(
        &mut self,
        id: u32,
        mem: &GuestMemory,
        vecs: Vec<(GuestAddress, usize)>,
    ) -> VirtioGpuResult {
        let resource = self.resources.get_mut(&id).ok_or(ErrInvalidResourceId)?;
        resource.gpu_resource.attach_backing(&vecs[..], mem)?;
        Ok(OkNoData)
    }

    /// Detaches any backing memory from the given resource, if there is any.
    fn detach_backing(&mut self, id: u32) -> VirtioGpuResult {
        let resource = self.resources.get_mut(&id).ok_or(ErrInvalidResourceId)?;
        resource.gpu_resource.detach_backing();
        Ok(OkNoData)
    }

    /// Updates the cursor's memory to the given id, and sets its position to the given coordinates.
    fn update_cursor(&mut self, id: u32, x: u32, y: u32) -> VirtioGpuResult {
        let resource = self.resources.get_mut(&id).map(|r| r.as_mut());
        self.base.update_cursor(id, x, y, resource)
    }

    /// Moves the cursor's position to the given coordinates.
    fn move_cursor(&mut self, x: u32, y: u32) -> VirtioGpuResult {
        self.base.move_cursor(x, y)
    }

    /// Returns a uuid for the resource.
    fn resource_assign_uuid(&mut self, id: u32) -> VirtioGpuResult {
        match self.resources.entry(id) {
            Entry::Vacant(_) => Err(ErrInvalidResourceId),
            Entry::Occupied(_) => {
                // TODO(stevensd): use real uuids once the virtio wayland protocol is updated to
                // handle more than 32 bits. For now, the virtwl driver knows that the uuid is
                // actually just the resource id.
                let mut uuid: [u8; 16] = [0; 16];
                for (idx, byte) in id.to_be_bytes().iter().enumerate() {
                    uuid[12 + idx] = *byte;
                }
                Ok(OkResourceUuid { uuid })
            }
        }
    }

    /// Gets the renderer's capset information associated with `index`.
    fn get_capset_info(&self, index: u32) -> VirtioGpuResult {
        let id = match index {
            0 => VIRTIO_GPU_CAPSET_VIRGL,
            1 => VIRTIO_GPU_CAPSET_VIRGL2,
            2 => VIRTIO_GPU_CAPSET3,
            _ => return Err(ErrInvalidParameter),
        };

        let (version, size) = self.renderer.get_cap_set_info(id);
        Ok(OkCapsetInfo { id, version, size })
    }

    /// Gets the capset of `version` associated with `id`.
    fn get_capset(&self, id: u32, version: u32) -> VirtioGpuResult {
        Ok(OkCapset(self.renderer.get_cap_set(id, version)))
    }

    /// Creates a fresh renderer context with the given `id`.
    fn create_renderer_context(&mut self, id: u32) -> VirtioGpuResult {
        if id == 0 {
            return Err(ErrInvalidContextId);
        }
        match self.contexts.entry(id) {
            Entry::Occupied(_) => Err(ErrInvalidContextId),
            Entry::Vacant(slot) => {
                let ctx = self.renderer.create_context(id)?;
                slot.insert(ctx);
                Ok(OkNoData)
            }
        }
    }

    /// Destorys the renderer context associated with `id`.
    fn destroy_renderer_context(&mut self, id: u32) -> VirtioGpuResult {
        match self.contexts.remove(&id) {
            Some(_) => Ok(OkNoData),
            None => Err(ErrInvalidContextId),
        }
    }

    /// Attaches the indicated resource to the given context.
    fn context_attach_resource(&mut self, ctx_id: u32, res_id: u32) -> VirtioGpuResult {
        match (
            self.contexts.get_mut(&ctx_id),
            self.resources.get_mut(&res_id),
        ) {
            (Some(ctx), Some(res)) => {
                ctx.attach(&res.gpu_resource);
                Ok(OkNoData)
            }
            (None, _) => Err(ErrInvalidContextId),
            (_, None) => Err(ErrInvalidResourceId),
        }
    }

    /// detaches the indicated resource to the given context.
    fn context_detach_resource(&mut self, ctx_id: u32, res_id: u32) -> VirtioGpuResult {
        match (
            self.contexts.get_mut(&ctx_id),
            self.resources.get_mut(&res_id),
        ) {
            (Some(ctx), Some(res)) => {
                ctx.detach(&res.gpu_resource);
                Ok(OkNoData)
            }
            (None, _) => Err(ErrInvalidContextId),
            (_, None) => Err(ErrInvalidResourceId),
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
    ) -> VirtioGpuResult {
        if id == 0 {
            return Err(ErrInvalidResourceId);
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
            Entry::Occupied(_) => Err(ErrInvalidResourceId),
            Entry::Vacant(slot) => {
                let gpu_resource = self.renderer.create_resource(create_args)?;
                let virtio_gpu_resource = Virtio3DResource::new(width, height, gpu_resource);
                let response = virtio_gpu_resource.response_from_query()?;
                slot.insert(virtio_gpu_resource);
                Ok(response)
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
    ) -> VirtioGpuResult {
        let ctx = match ctx_id {
            0 => None,
            id => Some(self.contexts.get(&id).ok_or(ErrInvalidContextId)?),
        };

        let resource = self
            .resources
            .get_mut(&res_id)
            .ok_or(ErrInvalidResourceId)?;

        let transfer_box = Box3 {
            x,
            y,
            z,
            w: width,
            h: height,
            d: depth,
        };

        resource.gpu_resource.transfer_write(
            ctx,
            level,
            stride,
            layer_stride,
            transfer_box,
            offset,
        )?;

        Ok(OkNoData)
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
    ) -> VirtioGpuResult {
        let ctx = match ctx_id {
            0 => None,
            id => Some(self.contexts.get(&id).ok_or(ErrInvalidContextId)?),
        };

        let resource = self
            .resources
            .get_mut(&res_id)
            .ok_or(ErrInvalidResourceId)?;

        let transfer_box = Box3 {
            x,
            y,
            z,
            w: width,
            h: height,
            d: depth,
        };

        resource.gpu_resource.transfer_read(
            ctx,
            level,
            stride,
            layer_stride,
            transfer_box,
            offset,
        )?;

        Ok(OkNoData)
    }

    /// Submits a command buffer to the given rendering context.
    fn submit_command(&mut self, ctx_id: u32, commands: &mut [u8]) -> VirtioGpuResult {
        let ctx = self.contexts.get_mut(&ctx_id).ok_or(ErrInvalidContextId)?;
        ctx.submit(&mut commands[..])?;
        Ok(OkNoData)
    }

    fn resource_create_blob(
        &mut self,
        resource_id: u32,
        ctx_id: u32,
        blob_mem: u32,
        blob_flags: u32,
        blob_id: u64,
        size: u64,
        vecs: Vec<(GuestAddress, usize)>,
        mem: &GuestMemory,
    ) -> VirtioGpuResult {
        match self.resources.entry(resource_id) {
            Entry::Vacant(entry) => {
                let resource = self.renderer.resource_create_blob(
                    resource_id,
                    ctx_id,
                    blob_mem,
                    blob_flags,
                    blob_id,
                    size,
                    &vecs,
                    mem,
                )?;

                let virtio_gpu_resource = Virtio3DResource::blob_new(
                    self.base.display_width,
                    self.base.display_height,
                    resource,
                    blob_flags,
                    size,
                );

                let response = virtio_gpu_resource.response_from_query()?;
                entry.insert(virtio_gpu_resource);
                Ok(response)
            }
            Entry::Occupied(_) => Err(ErrInvalidResourceId),
        }
    }

    fn resource_map_blob(&mut self, resource_id: u32, offset: u64) -> VirtioGpuResult {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        if resource.blob_flags & VIRTIO_GPU_BLOB_FLAG_USE_MAPPABLE == 0 {
            error!("resource not mappable");
            return Err(ErrUnspec);
        }

        let map_info = resource.gpu_resource.map_info()?;
        let export = resource.gpu_resource.export();

        let request = match export {
            Ok(ref export) => VmMemoryRequest::RegisterFdAtPciBarOffset(
                self.pci_bar,
                MaybeOwnedFd::Borrowed(export.as_raw_fd()),
                resource.size as usize,
                offset,
            ),
            Err(_) => {
                if self.external_blob {
                    return Err(ErrUnspec);
                }

                let mapping = resource.gpu_resource.map()?;
                {
                    let mut map_req = self.map_request.lock();
                    if map_req.is_some() {
                        return Err(ErrUnspec);
                    }
                    *map_req = Some(mapping);
                }
                VmMemoryRequest::RegisterHostPointerAtPciBarOffset(self.pci_bar, offset)
            }
        };

        self.gpu_device_socket.send(&request)?;
        let response = self.gpu_device_socket.recv()?;

        match response {
            VmMemoryResponse::RegisterMemory { pfn: _, slot } => {
                resource.slot = Some(slot);
                Ok(OkMapInfo { map_info })
            }
            VmMemoryResponse::Err(e) => Err(ErrSys(e)),
            _ => Err(ErrUnspec),
        }
    }

    fn resource_unmap_blob(&mut self, resource_id: u32) -> VirtioGpuResult {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        let slot = resource.slot.ok_or(ErrUnspec)?;
        let request = VmMemoryRequest::UnregisterMemory(slot);
        self.gpu_device_socket.send(&request)?;
        let response = self.gpu_device_socket.recv()?;

        match response {
            VmMemoryResponse::Ok => {
                resource.slot = None;
                Ok(OkNoData)
            }
            VmMemoryResponse::Err(e) => Err(ErrSys(e)),
            _ => Err(ErrUnspec),
        }
    }
}

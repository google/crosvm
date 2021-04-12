// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::BTreeMap as Map;
use std::num::NonZeroU32;
use std::rc::Rc;
use std::result::Result;
use std::sync::Arc;

use crate::virtio::resource_bridge::{BufferInfo, PlaneInfo, ResourceInfo, ResourceResponse};
use base::{error, AsRawDescriptor, ExternalMapping, Tube};

use data_model::VolatileSlice;

use gpu_display::*;
use rutabaga_gfx::{
    ResourceCreate3D, ResourceCreateBlob, Rutabaga, RutabagaBuilder, RutabagaFenceData,
    RutabagaIovec, Transfer3D,
};

use libc::c_void;

use resources::Alloc;

use super::protocol::{
    GpuResponse::{self, *},
    GpuResponsePlaneInfo, VirtioGpuResult, VIRTIO_GPU_BLOB_FLAG_CREATE_GUEST_HANDLE,
    VIRTIO_GPU_BLOB_MEM_HOST3D,
};
use super::udmabuf::UdmabufDriver;
use super::VirtioScanoutBlobData;
use sync::Mutex;

use vm_memory::{GuestAddress, GuestMemory};

use vm_control::{MemSlot, VmMemoryRequest, VmMemoryResponse};

struct VirtioGpuResource {
    resource_id: u32,
    width: u32,
    height: u32,
    size: u64,
    slot: Option<MemSlot>,
    scanout_data: Option<VirtioScanoutBlobData>,
    display_import: Option<(Rc<RefCell<GpuDisplay>>, u32)>,
}

impl VirtioGpuResource {
    /// Creates a new VirtioGpuResource with the given metadata.  Width and height are used by the
    /// display, while size is useful for hypervisor mapping.
    pub fn new(resource_id: u32, width: u32, height: u32, size: u64) -> VirtioGpuResource {
        VirtioGpuResource {
            resource_id,
            width,
            height,
            size,
            slot: None,
            scanout_data: None,
            display_import: None,
        }
    }

    /// Returns the dimensions of the VirtioGpuResource.
    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }
}

/// Handles functionality related to displays, input events and hypervisor memory management.
pub struct VirtioGpu {
    display: Rc<RefCell<GpuDisplay>>,
    display_width: u32,
    display_height: u32,
    scanout_resource_id: Option<NonZeroU32>,
    scanout_surface_id: Option<u32>,
    cursor_resource_id: Option<NonZeroU32>,
    cursor_surface_id: Option<u32>,
    // Maps event devices to scanout number.
    event_devices: Map<u32, u32>,
    gpu_device_tube: Tube,
    pci_bar: Alloc,
    map_request: Arc<Mutex<Option<ExternalMapping>>>,
    rutabaga: Rutabaga,
    resources: Map<u32, VirtioGpuResource>,
    external_blob: bool,
    udmabuf_driver: Option<UdmabufDriver>,
}

fn sglist_to_rutabaga_iovecs(
    vecs: &[(GuestAddress, usize)],
    mem: &GuestMemory,
) -> Result<Vec<RutabagaIovec>, ()> {
    if vecs
        .iter()
        .any(|&(addr, len)| mem.get_slice_at_addr(addr, len).is_err())
    {
        return Err(());
    }

    let mut rutabaga_iovecs: Vec<RutabagaIovec> = Vec::new();
    for &(addr, len) in vecs {
        let slice = mem.get_slice_at_addr(addr, len).unwrap();
        rutabaga_iovecs.push(RutabagaIovec {
            base: slice.as_mut_ptr() as *mut c_void,
            len,
        });
    }
    Ok(rutabaga_iovecs)
}

impl VirtioGpu {
    /// Creates a new instance of the VirtioGpu state tracker.
    pub fn new(
        display: GpuDisplay,
        display_width: u32,
        display_height: u32,
        rutabaga_builder: RutabagaBuilder,
        event_devices: Vec<EventDevice>,
        gpu_device_tube: Tube,
        pci_bar: Alloc,
        map_request: Arc<Mutex<Option<ExternalMapping>>>,
        external_blob: bool,
        udmabuf: bool,
    ) -> Option<VirtioGpu> {
        let rutabaga = rutabaga_builder
            .build()
            .map_err(|e| error!("failed to build rutabaga {}", e))
            .ok()?;

        let mut udmabuf_driver = None;
        if udmabuf {
            udmabuf_driver = Some(
                UdmabufDriver::new()
                    .map_err(|e| error!("failed to initialize udmabuf: {}", e))
                    .ok()?,
            );
        }

        let mut virtio_gpu = VirtioGpu {
            display: Rc::new(RefCell::new(display)),
            display_width,
            display_height,
            event_devices: Default::default(),
            scanout_resource_id: None,
            scanout_surface_id: None,
            cursor_resource_id: None,
            cursor_surface_id: None,
            gpu_device_tube,
            pci_bar,
            map_request,
            rutabaga,
            resources: Default::default(),
            external_blob,
            udmabuf_driver,
        };

        for event_device in event_devices {
            virtio_gpu
                .import_event_device(event_device, 0)
                .map_err(|e| error!("failed to import event device {}", e))
                .ok()?;
        }

        Some(virtio_gpu)
    }

    /// Imports the event device
    pub fn import_event_device(
        &mut self,
        event_device: EventDevice,
        scanout: u32,
    ) -> VirtioGpuResult {
        // TODO(zachr): support more than one scanout.
        if scanout != 0 {
            return Err(ErrScanout {
                num_scanouts: scanout,
            });
        }

        let mut display = self.display.borrow_mut();
        let event_device_id = display.import_event_device(event_device)?;
        if let Some(s) = self.scanout_surface_id {
            display.attach_event_device(s, event_device_id)
        }
        self.event_devices.insert(event_device_id, scanout);
        Ok(OkNoData)
    }

    /// Gets a reference to the display passed into `new`.
    pub fn display(&mut self) -> &Rc<RefCell<GpuDisplay>> {
        &self.display
    }

    /// Gets the list of supported display resolutions as a slice of `(width, height)` tuples.
    pub fn display_info(&self) -> [(u32, u32); 1] {
        [(self.display_width, self.display_height)]
    }

    /// Processes the internal `display` events and returns `true` if the main display was closed.
    pub fn process_display(&mut self) -> bool {
        let mut display = self.display.borrow_mut();
        display.dispatch_events();
        self.scanout_surface_id
            .map(|s| display.close_requested(s))
            .unwrap_or(false)
    }

    /// Sets the given resource id as the source of scanout to the display.
    pub fn set_scanout(
        &mut self,
        _scanout_id: u32,
        resource_id: u32,
        scanout_data: Option<VirtioScanoutBlobData>,
    ) -> VirtioGpuResult {
        let mut display = self.display.borrow_mut();
        if resource_id == 0 {
            if let Some(surface_id) = self.scanout_surface_id.take() {
                display.release_surface(surface_id);
            }
            self.scanout_resource_id = None;
            return Ok(OkNoData);
        }

        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        resource.scanout_data = scanout_data;
        self.scanout_resource_id = NonZeroU32::new(resource_id);
        if self.scanout_surface_id.is_none() {
            let surface_id =
                display.create_surface(None, self.display_width, self.display_height)?;
            self.scanout_surface_id = Some(surface_id);
            for event_device_id in self.event_devices.keys() {
                display.attach_event_device(surface_id, *event_device_id);
            }
        }
        Ok(OkNoData)
    }

    /// If the resource is the scanout resource, flush it to the display.
    pub fn flush_resource(&mut self, resource_id: u32) -> VirtioGpuResult {
        if resource_id == 0 {
            return Ok(OkNoData);
        }

        if let (Some(scanout_resource_id), Some(scanout_surface_id)) =
            (self.scanout_resource_id, self.scanout_surface_id)
        {
            if scanout_resource_id.get() == resource_id {
                self.flush_resource_to_surface(resource_id, scanout_surface_id)?;
            }
        }

        if let (Some(cursor_resource_id), Some(cursor_surface_id)) =
            (self.cursor_resource_id, self.cursor_surface_id)
        {
            if cursor_resource_id.get() == resource_id {
                self.flush_resource_to_surface(resource_id, cursor_surface_id)?;
            }
        }

        Ok(OkNoData)
    }

    /// Attempts to import the given resource into the display.  Only works with Wayland displays.
    pub fn import_to_display(&mut self, resource_id: u32) -> Option<u32> {
        let resource = match self.resources.get_mut(&resource_id) {
            Some(resource) => resource,
            _ => return None,
        };

        if let Some((self_display, import)) = &resource.display_import {
            if Rc::ptr_eq(self_display, &self.display) {
                return Some(*import);
            }
        }

        let dmabuf = self.rutabaga.export_blob(resource.resource_id).ok()?;
        let query = self.rutabaga.query(resource.resource_id).ok()?;

        let (width, height, format, stride, offset) = match resource.scanout_data {
            Some(data) => (
                data.width,
                data.height,
                data.drm_format.into(),
                data.strides[0],
                data.offsets[0],
            ),
            None => (
                resource.width,
                resource.height,
                query.drm_fourcc,
                query.strides[0],
                query.offsets[0],
            ),
        };

        match self.display.borrow_mut().import_dmabuf(
            dmabuf.os_handle.as_raw_descriptor(),
            offset,
            stride,
            query.modifier,
            width,
            height,
            format,
        ) {
            Ok(import_id) => {
                resource.display_import = Some((self.display.clone(), import_id));
                Some(import_id)
            }
            Err(e) => {
                error!("failed to import dmabuf for display: {}", e);
                None
            }
        }
    }

    /// Attempts to import the given resource into the display, otherwise falls back to rutabaga
    /// copies.
    pub fn flush_resource_to_surface(
        &mut self,
        resource_id: u32,
        surface_id: u32,
    ) -> VirtioGpuResult {
        if let Some(import_id) = self.import_to_display(resource_id) {
            self.display.borrow_mut().flip_to(surface_id, import_id);
            return Ok(OkNoData);
        }

        if !self.resources.contains_key(&resource_id) {
            return Err(ErrInvalidResourceId);
        }

        // Import failed, fall back to a copy.
        let mut display = self.display.borrow_mut();
        // Prevent overwriting a buffer that is currently being used by the compositor.
        if display.next_buffer_in_use(surface_id) {
            return Ok(OkNoData);
        }

        let fb = display
            .framebuffer_region(surface_id, 0, 0, self.display_width, self.display_height)
            .ok_or(ErrUnspec)?;

        let mut transfer = Transfer3D::new_2d(0, 0, self.display_width, self.display_height);
        transfer.stride = fb.stride();
        self.rutabaga
            .transfer_read(0, resource_id, transfer, Some(fb.as_volatile_slice()))?;
        display.flip(surface_id);

        Ok(OkNoData)
    }

    /// Updates the cursor's memory to the given resource_id, and sets its position to the given
    /// coordinates.
    pub fn update_cursor(&mut self, resource_id: u32, x: u32, y: u32) -> VirtioGpuResult {
        if resource_id == 0 {
            if let Some(surface_id) = self.cursor_surface_id.take() {
                self.display.borrow_mut().release_surface(surface_id);
            }
            self.cursor_resource_id = None;
            return Ok(OkNoData);
        }

        let (resource_width, resource_height) = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?
            .dimensions();

        self.cursor_resource_id = NonZeroU32::new(resource_id);

        if self.cursor_surface_id.is_none() {
            self.cursor_surface_id = Some(self.display.borrow_mut().create_surface(
                self.scanout_surface_id,
                resource_width,
                resource_height,
            )?);
        }

        let cursor_surface_id = self.cursor_surface_id.unwrap();
        self.display
            .borrow_mut()
            .set_position(cursor_surface_id, x, y);

        // Gets the resource's pixels into the display by importing the buffer.
        if let Some(import_id) = self.import_to_display(resource_id) {
            self.display
                .borrow_mut()
                .flip_to(cursor_surface_id, import_id);
            return Ok(OkNoData);
        }

        // Importing failed, so try copying the pixels into the surface's slower shared memory
        // framebuffer.
        if let Some(fb) = self.display.borrow_mut().framebuffer(cursor_surface_id) {
            let mut transfer = Transfer3D::new_2d(0, 0, resource_width, resource_height);
            transfer.stride = fb.stride();
            self.rutabaga
                .transfer_read(0, resource_id, transfer, Some(fb.as_volatile_slice()))?;
        }
        self.display.borrow_mut().flip(cursor_surface_id);
        Ok(OkNoData)
    }

    /// Moves the cursor's position to the given coordinates.
    pub fn move_cursor(&mut self, x: u32, y: u32) -> VirtioGpuResult {
        if let Some(cursor_surface_id) = self.cursor_surface_id {
            if let Some(scanout_surface_id) = self.scanout_surface_id {
                let mut display = self.display.borrow_mut();
                display.set_position(cursor_surface_id, x, y);
                display.commit(scanout_surface_id);
            }
        }
        Ok(OkNoData)
    }

    /// Returns a uuid for the resource.
    pub fn resource_assign_uuid(&self, resource_id: u32) -> VirtioGpuResult {
        if !self.resources.contains_key(&resource_id) {
            return Err(ErrInvalidResourceId);
        }

        // TODO(stevensd): use real uuids once the virtio wayland protocol is updated to
        // handle more than 32 bits. For now, the virtwl driver knows that the uuid is
        // actually just the resource id.
        let mut uuid: [u8; 16] = [0; 16];
        for (idx, byte) in resource_id.to_be_bytes().iter().enumerate() {
            uuid[12 + idx] = *byte;
        }
        Ok(OkResourceUuid { uuid })
    }

    /// If supported, export the resource with the given `resource_id` to a file.
    pub fn export_resource(&mut self, resource_id: u32) -> ResourceResponse {
        let file = match self.rutabaga.export_blob(resource_id) {
            Ok(handle) => handle.os_handle.into(),
            Err(_) => return ResourceResponse::Invalid,
        };

        let q = match self.rutabaga.query(resource_id) {
            Ok(query) => query,
            Err(_) => return ResourceResponse::Invalid,
        };

        ResourceResponse::Resource(ResourceInfo::Buffer(BufferInfo {
            file,
            planes: [
                PlaneInfo {
                    offset: q.offsets[0],
                    stride: q.strides[0],
                },
                PlaneInfo {
                    offset: q.offsets[1],
                    stride: q.strides[1],
                },
                PlaneInfo {
                    offset: q.offsets[2],
                    stride: q.strides[2],
                },
                PlaneInfo {
                    offset: q.offsets[3],
                    stride: q.strides[3],
                },
            ],
            modifier: q.modifier,
        }))
    }

    /// If supported, export the fence with the given `fence_id` to a file.
    pub fn export_fence(&self, fence_id: u32) -> ResourceResponse {
        match self.rutabaga.export_fence(fence_id) {
            Ok(handle) => ResourceResponse::Resource(ResourceInfo::Fence {
                file: handle.os_handle.into(),
            }),
            Err(_) => ResourceResponse::Invalid,
        }
    }

    /// Gets rutabaga's capset information associated with `index`.
    pub fn get_capset_info(&self, index: u32) -> VirtioGpuResult {
        let (capset_id, version, size) = self.rutabaga.get_capset_info(index)?;
        Ok(OkCapsetInfo {
            capset_id,
            version,
            size,
        })
    }

    /// Gets a capset from rutabaga.
    pub fn get_capset(&self, capset_id: u32, version: u32) -> VirtioGpuResult {
        let capset = self.rutabaga.get_capset(capset_id, version)?;
        Ok(OkCapset(capset))
    }

    /// Forces rutabaga to use it's default context.
    pub fn force_ctx_0(&self) {
        self.rutabaga.force_ctx_0()
    }

    /// Creates a fence with the RutabagaFenceData that can be used to determine when the previous
    /// command completed.
    pub fn create_fence(&mut self, rutabaga_fence_data: RutabagaFenceData) -> VirtioGpuResult {
        self.rutabaga.create_fence(rutabaga_fence_data)?;
        Ok(OkNoData)
    }

    /// Returns an array of RutabagaFenceData, describing completed fences.
    pub fn fence_poll(&mut self) -> Vec<RutabagaFenceData> {
        self.rutabaga.poll()
    }

    /// Creates a 3D resource with the given properties and resource_id.
    pub fn resource_create_3d(
        &mut self,
        resource_id: u32,
        resource_create_3d: ResourceCreate3D,
    ) -> VirtioGpuResult {
        self.rutabaga
            .resource_create_3d(resource_id, resource_create_3d)?;

        let resource = VirtioGpuResource::new(
            resource_id,
            resource_create_3d.width,
            resource_create_3d.height,
            0,
        );

        // Rely on rutabaga to check for duplicate resource ids.
        self.resources.insert(resource_id, resource);
        Ok(self.result_from_query(resource_id))
    }

    /// Attaches backing memory to the given resource, represented by a `Vec` of `(address, size)`
    /// tuples in the guest's physical address space. Converts to RutabageIovec from the memory
    /// mapping.
    pub fn attach_backing(
        &mut self,
        resource_id: u32,
        mem: &GuestMemory,
        vecs: Vec<(GuestAddress, usize)>,
    ) -> VirtioGpuResult {
        let rutabaga_iovecs = sglist_to_rutabaga_iovecs(&vecs[..], mem).map_err(|_| ErrUnspec)?;
        self.rutabaga.attach_backing(resource_id, rutabaga_iovecs)?;
        Ok(OkNoData)
    }

    /// Detaches any previously attached iovecs from the resource.
    pub fn detach_backing(&mut self, resource_id: u32) -> VirtioGpuResult {
        self.rutabaga.detach_backing(resource_id)?;
        Ok(OkNoData)
    }

    /// Releases guest kernel reference on the resource.
    pub fn unref_resource(&mut self, resource_id: u32) -> VirtioGpuResult {
        self.resources
            .remove(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        self.rutabaga.unref_resource(resource_id)?;
        Ok(OkNoData)
    }

    /// Copies data to host resource from the attached iovecs. Can also be used to flush caches.
    pub fn transfer_write(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        transfer: Transfer3D,
    ) -> VirtioGpuResult {
        self.rutabaga
            .transfer_write(ctx_id, resource_id, transfer)?;
        Ok(OkNoData)
    }

    /// Copies data from the host resource to:
    ///    1) To the optional volatile slice
    ///    2) To the host resource's attached iovecs
    ///
    /// Can also be used to invalidate caches.
    pub fn transfer_read(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        transfer: Transfer3D,
        buf: Option<VolatileSlice>,
    ) -> VirtioGpuResult {
        self.rutabaga
            .transfer_read(ctx_id, resource_id, transfer, buf)?;
        Ok(OkNoData)
    }

    /// Creates a blob resource using rutabaga.
    pub fn resource_create_blob(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        resource_create_blob: ResourceCreateBlob,
        vecs: Vec<(GuestAddress, usize)>,
        mem: &GuestMemory,
    ) -> VirtioGpuResult {
        let mut rutabaga_handle = None;
        let mut rutabaga_iovecs = None;

        if resource_create_blob.blob_flags & VIRTIO_GPU_BLOB_FLAG_CREATE_GUEST_HANDLE != 0 {
            rutabaga_handle = match self.udmabuf_driver {
                Some(ref driver) => Some(driver.create_udmabuf(mem, &vecs[..])?),
                None => return Err(ErrUnspec),
            }
        } else if resource_create_blob.blob_mem != VIRTIO_GPU_BLOB_MEM_HOST3D {
            rutabaga_iovecs =
                Some(sglist_to_rutabaga_iovecs(&vecs[..], mem).map_err(|_| ErrUnspec)?);
        }

        self.rutabaga.resource_create_blob(
            ctx_id,
            resource_id,
            resource_create_blob,
            rutabaga_iovecs,
            rutabaga_handle,
        )?;

        let resource = VirtioGpuResource::new(resource_id, 0, 0, resource_create_blob.size);

        // Rely on rutabaga to check for duplicate resource ids.
        self.resources.insert(resource_id, resource);
        Ok(self.result_from_query(resource_id))
    }

    /// Uses the hypervisor to map the rutabaga blob resource.
    pub fn resource_map_blob(&mut self, resource_id: u32, offset: u64) -> VirtioGpuResult {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        let map_info = self.rutabaga.map_info(resource_id).map_err(|_| ErrUnspec)?;
        let vulkan_info_opt = self.rutabaga.vulkan_info(resource_id).ok();

        let export = self.rutabaga.export_blob(resource_id);

        let request = match export {
            Ok(export) => match vulkan_info_opt {
                Some(vulkan_info) => VmMemoryRequest::RegisterVulkanMemoryAtPciBarOffset {
                    alloc: self.pci_bar,
                    descriptor: export.os_handle,
                    handle_type: export.handle_type,
                    memory_idx: vulkan_info.memory_idx,
                    physical_device_idx: vulkan_info.physical_device_idx,
                    offset,
                    size: resource.size,
                },
                None => VmMemoryRequest::RegisterFdAtPciBarOffset(
                    self.pci_bar,
                    export.os_handle,
                    resource.size as usize,
                    offset,
                ),
            },
            Err(_) => {
                if self.external_blob {
                    return Err(ErrUnspec);
                }

                let mapping = self.rutabaga.map(resource_id)?;
                // Scope for lock
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

        self.gpu_device_tube.send(&request)?;
        let response = self.gpu_device_tube.recv()?;

        match response {
            VmMemoryResponse::RegisterMemory { pfn: _, slot } => {
                resource.slot = Some(slot);
                Ok(OkMapInfo { map_info })
            }
            VmMemoryResponse::Err(e) => Err(ErrSys(e)),
            _ => Err(ErrUnspec),
        }
    }

    /// Uses the hypervisor to unmap the blob resource.
    pub fn resource_unmap_blob(&mut self, resource_id: u32) -> VirtioGpuResult {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        let slot = resource.slot.ok_or(ErrUnspec)?;
        let request = VmMemoryRequest::UnregisterMemory(slot);
        self.gpu_device_tube.send(&request)?;
        let response = self.gpu_device_tube.recv()?;

        match response {
            VmMemoryResponse::Ok => {
                resource.slot = None;
                Ok(OkNoData)
            }
            VmMemoryResponse::Err(e) => Err(ErrSys(e)),
            _ => Err(ErrUnspec),
        }
    }

    /// Creates a rutabaga context.
    pub fn create_context(&mut self, ctx_id: u32, context_init: u32) -> VirtioGpuResult {
        self.rutabaga.create_context(ctx_id, context_init)?;
        Ok(OkNoData)
    }

    /// Destroys a rutabaga context.
    pub fn destroy_context(&mut self, ctx_id: u32) -> VirtioGpuResult {
        self.rutabaga.destroy_context(ctx_id)?;
        Ok(OkNoData)
    }

    /// Attaches a resource to a rutabaga context.
    pub fn context_attach_resource(&mut self, ctx_id: u32, resource_id: u32) -> VirtioGpuResult {
        self.rutabaga.context_attach_resource(ctx_id, resource_id)?;
        Ok(OkNoData)
    }

    /// Detaches a resource from a rutabaga context.
    pub fn context_detach_resource(&mut self, ctx_id: u32, resource_id: u32) -> VirtioGpuResult {
        self.rutabaga.context_detach_resource(ctx_id, resource_id)?;
        Ok(OkNoData)
    }

    /// Submits a command buffer to a rutabaga context.
    pub fn submit_command(&mut self, ctx_id: u32, commands: &mut [u8]) -> VirtioGpuResult {
        self.rutabaga.submit_command(ctx_id, commands)?;
        Ok(OkNoData)
    }

    // Non-public function -- no doc comment needed!
    fn result_from_query(&mut self, resource_id: u32) -> GpuResponse {
        match self.rutabaga.query(resource_id) {
            Ok(query) => {
                let mut plane_info = Vec::with_capacity(4);
                for plane_index in 0..4 {
                    plane_info.push(GpuResponsePlaneInfo {
                        stride: query.strides[plane_index],
                        offset: query.offsets[plane_index],
                    });
                }
                let format_modifier = query.modifier;
                OkResourcePlaneInfo {
                    format_modifier,
                    plane_info,
                }
            }
            Err(_) => OkNoData,
        }
    }
}

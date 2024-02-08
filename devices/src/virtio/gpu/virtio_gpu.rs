// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cell::RefCell;
use std::collections::BTreeMap as Map;
use std::collections::BTreeSet as Set;
use std::io::IoSliceMut;
use std::num::NonZeroU32;
use std::rc::Rc;
use std::result::Result;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::Context;
use base::error;
use base::FromRawDescriptor;
use base::IntoRawDescriptor;
use base::Protection;
use base::SafeDescriptor;
use base::VolatileSlice;
use gpu_display::*;
use hypervisor::MemCacheType;
use libc::c_void;
use rutabaga_gfx::ResourceCreate3D;
use rutabaga_gfx::ResourceCreateBlob;
use rutabaga_gfx::Rutabaga;
use rutabaga_gfx::RutabagaDescriptor;
#[cfg(windows)]
use rutabaga_gfx::RutabagaError;
use rutabaga_gfx::RutabagaFence;
use rutabaga_gfx::RutabagaFromRawDescriptor;
use rutabaga_gfx::RutabagaHandle;
use rutabaga_gfx::RutabagaIntoRawDescriptor;
use rutabaga_gfx::RutabagaIovec;
use rutabaga_gfx::Transfer3D;
use rutabaga_gfx::RUTABAGA_MAP_ACCESS_MASK;
use rutabaga_gfx::RUTABAGA_MAP_ACCESS_READ;
use rutabaga_gfx::RUTABAGA_MAP_ACCESS_RW;
use rutabaga_gfx::RUTABAGA_MAP_ACCESS_WRITE;
use rutabaga_gfx::RUTABAGA_MAP_CACHE_CACHED;
use rutabaga_gfx::RUTABAGA_MAP_CACHE_MASK;
use rutabaga_gfx::RUTABAGA_MEM_HANDLE_TYPE_DMABUF;
use rutabaga_gfx::RUTABAGA_MEM_HANDLE_TYPE_OPAQUE_FD;
use serde::Deserialize;
use serde::Serialize;
use sync::Mutex;
use vm_control::gpu::DisplayParameters;
use vm_control::gpu::GpuControlCommand;
use vm_control::gpu::GpuControlResult;
use vm_control::VmMemorySource;
use vm_memory::udmabuf::UdmabufDriver;
use vm_memory::udmabuf::UdmabufDriverTrait;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

use super::protocol::GpuResponse;
use super::protocol::GpuResponse::*;
use super::protocol::GpuResponsePlaneInfo;
use super::protocol::VirtioGpuResult;
use super::protocol::VIRTIO_GPU_BLOB_FLAG_CREATE_GUEST_HANDLE;
use super::protocol::VIRTIO_GPU_BLOB_MEM_HOST3D;
use super::VirtioScanoutBlobData;
use crate::virtio::gpu::edid::DisplayInfo;
use crate::virtio::gpu::edid::EdidBytes;
use crate::virtio::gpu::GpuDisplayParameters;
use crate::virtio::gpu::VIRTIO_GPU_MAX_SCANOUTS;
use crate::virtio::resource_bridge::BufferInfo;
use crate::virtio::resource_bridge::PlaneInfo;
use crate::virtio::resource_bridge::ResourceInfo;
use crate::virtio::resource_bridge::ResourceResponse;
use crate::virtio::SharedMemoryMapper;

pub fn to_rutabaga_descriptor(s: SafeDescriptor) -> RutabagaDescriptor {
    // SAFETY:
    // Safe because we own the SafeDescriptor at this point.
    unsafe { RutabagaDescriptor::from_raw_descriptor(s.into_raw_descriptor()) }
}

fn to_safe_descriptor(r: RutabagaDescriptor) -> SafeDescriptor {
    // SAFETY:
    // Safe because we own the SafeDescriptor at this point.
    unsafe { SafeDescriptor::from_raw_descriptor(r.into_raw_descriptor()) }
}

struct VirtioGpuResource {
    resource_id: u32,
    width: u32,
    height: u32,
    size: u64,
    shmem_offset: Option<u64>,
    scanout_data: Option<VirtioScanoutBlobData>,
    display_import: Option<u32>,
    rutabaga_external_mapping: bool,

    // Only saved for snapshotting, so that we can re-attach backing iovecs with the correct new
    // host addresses.
    backing_iovecs: Option<Vec<(GuestAddress, usize)>>,
}

#[derive(Serialize, Deserialize)]
struct VirtioGpuResourceSnapshot {
    resource_id: u32,
    width: u32,
    height: u32,
    size: u64,

    backing_iovecs: Option<Vec<(GuestAddress, usize)>>,
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
            shmem_offset: None,
            scanout_data: None,
            display_import: None,
            rutabaga_external_mapping: false,
            backing_iovecs: None,
        }
    }

    fn snapshot(&self) -> VirtioGpuResourceSnapshot {
        // Only the 2D backend is support and it doesn't use these fields.
        assert!(self.shmem_offset.is_none());
        assert!(self.scanout_data.is_none());
        assert!(self.display_import.is_none());
        assert_eq!(self.rutabaga_external_mapping, false);
        VirtioGpuResourceSnapshot {
            resource_id: self.resource_id,
            width: self.width,
            height: self.height,
            size: self.size,
            backing_iovecs: self.backing_iovecs.clone(),
        }
    }

    fn restore(s: VirtioGpuResourceSnapshot) -> Self {
        let mut resource = VirtioGpuResource::new(s.resource_id, s.width, s.height, s.size);
        resource.backing_iovecs = s.backing_iovecs;
        resource
    }
}

struct VirtioGpuScanout {
    width: u32,
    height: u32,
    scanout_type: SurfaceType,
    // If this scanout is a primary scanout, the scanout id.
    scanout_id: Option<u32>,
    // If this scanout is a primary scanout, the display properties.
    display_params: Option<GpuDisplayParameters>,
    // If this scanout is a cursor scanout, the scanout that this is cursor is overlayed onto.
    parent_surface_id: Option<u32>,

    surface_id: Option<u32>,
    parent_scanout_id: Option<u32>,

    resource_id: Option<NonZeroU32>,
    position: Option<(u32, u32)>,
}

#[derive(Serialize, Deserialize)]
struct VirtioGpuScanoutSnapshot {
    width: u32,
    height: u32,
    scanout_type: SurfaceType,
    scanout_id: Option<u32>,
    display_params: Option<GpuDisplayParameters>,

    // The surface IDs aren't guest visible. Instead of storing them and then having to fix up
    // `gpu_display` internals, we'll allocate new ones on restore. So, we just need to store
    // whether a surface was allocated and the parent's scanout ID.
    has_surface: bool,
    parent_scanout_id: Option<u32>,

    resource_id: Option<NonZeroU32>,
    position: Option<(u32, u32)>,
}

impl VirtioGpuScanout {
    fn new_primary(scanout_id: u32, params: GpuDisplayParameters) -> VirtioGpuScanout {
        let (width, height) = params.get_virtual_display_size();
        VirtioGpuScanout {
            width,
            height,
            scanout_type: SurfaceType::Scanout,
            scanout_id: Some(scanout_id),
            display_params: Some(params),
            parent_surface_id: None,
            surface_id: None,
            parent_scanout_id: None,
            resource_id: None,
            position: None,
        }
    }

    fn new_cursor() -> VirtioGpuScanout {
        // Per virtio spec: "The mouse cursor image is a normal resource, except that it must be
        // 64x64 in size."
        VirtioGpuScanout {
            width: 64,
            height: 64,
            scanout_type: SurfaceType::Cursor,
            scanout_id: None,
            display_params: None,
            parent_surface_id: None,
            surface_id: None,
            parent_scanout_id: None,
            resource_id: None,
            position: None,
        }
    }

    fn snapshot(&self) -> VirtioGpuScanoutSnapshot {
        VirtioGpuScanoutSnapshot {
            width: self.width,
            height: self.height,
            has_surface: self.surface_id.is_some(),
            resource_id: self.resource_id,
            scanout_type: self.scanout_type,
            scanout_id: self.scanout_id,
            display_params: self.display_params.clone(),
            parent_scanout_id: self.parent_scanout_id,
            position: self.position,
        }
    }

    fn restore(
        &mut self,
        snapshot: VirtioGpuScanoutSnapshot,
        parent_surface_id: Option<u32>,
        display: &Rc<RefCell<GpuDisplay>>,
    ) -> VirtioGpuResult {
        // Scanouts are mainly controlled by the host, we just need to make sure it looks same,
        // restore the resource_id association, and create a surface in the display.

        assert_eq!(self.width, snapshot.width);
        assert_eq!(self.height, snapshot.height);
        assert_eq!(self.scanout_type, snapshot.scanout_type);
        assert_eq!(self.scanout_id, snapshot.scanout_id);
        assert_eq!(self.display_params, snapshot.display_params);

        self.resource_id = snapshot.resource_id;
        if snapshot.has_surface {
            self.create_surface(display, parent_surface_id)?;
        } else {
            self.release_surface(display);
        }
        if let Some((x, y)) = snapshot.position {
            self.set_position(display, x, y)?;
        }

        Ok(OkNoData)
    }

    fn create_surface(
        &mut self,
        display: &Rc<RefCell<GpuDisplay>>,
        new_parent_surface_id: Option<u32>,
    ) -> VirtioGpuResult {
        let mut need_to_create = false;

        if self.surface_id.is_none() {
            need_to_create = true;
        }

        if self.parent_surface_id != new_parent_surface_id {
            self.parent_surface_id = new_parent_surface_id;
            need_to_create = true;
        }

        if !need_to_create {
            return Ok(OkNoData);
        }

        self.release_surface(display);

        let mut display = display.borrow_mut();

        let surface_id = display.create_surface(
            self.parent_surface_id,
            self.scanout_id,
            self.width,
            self.height,
            self.scanout_type,
        )?;

        self.surface_id = Some(surface_id);

        Ok(OkNoData)
    }

    fn release_surface(&mut self, display: &Rc<RefCell<GpuDisplay>>) {
        if let Some(surface_id) = self.surface_id {
            display.borrow_mut().release_surface(surface_id);
        }

        self.surface_id = None;
    }

    fn set_position(
        &mut self,
        display: &Rc<RefCell<GpuDisplay>>,
        x: u32,
        y: u32,
    ) -> VirtioGpuResult {
        if let Some(surface_id) = self.surface_id {
            display.borrow_mut().set_position(surface_id, x, y)?;
            self.position = Some((x, y));
        }
        Ok(OkNoData)
    }

    fn commit(&self, display: &Rc<RefCell<GpuDisplay>>) -> VirtioGpuResult {
        if let Some(surface_id) = self.surface_id {
            display.borrow_mut().commit(surface_id)?;
        }
        Ok(OkNoData)
    }

    fn flush(
        &mut self,
        display: &Rc<RefCell<GpuDisplay>>,
        resource: &mut VirtioGpuResource,
        rutabaga: &mut Rutabaga,
    ) -> VirtioGpuResult {
        let surface_id = match self.surface_id {
            Some(id) => id,
            _ => return Ok(OkNoData),
        };

        if let Some(import_id) =
            VirtioGpuScanout::import_resource_to_display(display, resource, rutabaga)
        {
            display.borrow_mut().flip_to(surface_id, import_id)?;
            return Ok(OkNoData);
        }

        // Import failed, fall back to a copy.
        let mut display = display.borrow_mut();

        // Prevent overwriting a buffer that is currently being used by the compositor.
        if display.next_buffer_in_use(surface_id) {
            return Ok(OkNoData);
        }

        let fb = display
            .framebuffer_region(surface_id, 0, 0, self.width, self.height)
            .ok_or(ErrUnspec)?;

        let mut transfer = Transfer3D::new_2d(0, 0, self.width, self.height);
        transfer.stride = fb.stride();
        let fb_slice = fb.as_volatile_slice();
        let buf = IoSliceMut::new(
            // SAFETY: trivially safe
            unsafe { std::slice::from_raw_parts_mut(fb_slice.as_mut_ptr(), fb_slice.size()) },
        );
        rutabaga.transfer_read(0, resource.resource_id, transfer, Some(buf))?;

        display.flip(surface_id);
        Ok(OkNoData)
    }

    fn import_resource_to_display(
        display: &Rc<RefCell<GpuDisplay>>,
        resource: &mut VirtioGpuResource,
        rutabaga: &mut Rutabaga,
    ) -> Option<u32> {
        if let Some(import_id) = resource.display_import {
            return Some(import_id);
        }

        let dmabuf = to_safe_descriptor(rutabaga.export_blob(resource.resource_id).ok()?.os_handle);
        let query = rutabaga.query(resource.resource_id).ok()?;

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

        let import_id = display
            .borrow_mut()
            .import_memory(
                &dmabuf,
                offset,
                stride,
                query.modifier,
                width,
                height,
                format,
            )
            .ok()?;
        resource.display_import = Some(import_id);
        Some(import_id)
    }
}

/// Handles functionality related to displays, input events and hypervisor memory management.
pub struct VirtioGpu {
    display: Rc<RefCell<GpuDisplay>>,
    scanouts: Map<u32, VirtioGpuScanout>,
    scanouts_updated: Arc<AtomicBool>,
    cursor_scanout: VirtioGpuScanout,
    mapper: Arc<Mutex<Option<Box<dyn SharedMemoryMapper>>>>,
    rutabaga: Rutabaga,
    resources: Map<u32, VirtioGpuResource>,
    external_blob: bool,
    fixed_blob_mapping: bool,
    udmabuf_driver: Option<UdmabufDriver>,
}

// Only the 2D mode is supported. Notes on `VirtioGpu` fields:
//
//   * display: re-initialized from scratch using the scanout snapshots
//   * scanouts: snapshot'd
//   * scanouts_updated: snapshot'd
//   * cursor_scanout: snapshot'd
//   * mapper: not needed for 2d mode
//   * rutabaga: re-initialized from scatch using the resource snapshots
//   * resources: snapshot'd
//   * external_blob: not needed for 2d mode
//   * udmabuf_driver: not needed for 2d mode
#[derive(Serialize, Deserialize)]
pub struct VirtioGpuSnapshot {
    scanouts: Map<u32, VirtioGpuScanoutSnapshot>,
    scanouts_updated: bool,
    cursor_scanout: VirtioGpuScanoutSnapshot,
    rutabaga: Vec<u8>,
    resources: Map<u32, VirtioGpuResourceSnapshot>,
}

#[derive(Serialize, Deserialize)]
struct RutabagaResourceSnapshotSerializable {
    resource_id: u32,

    width: u32,
    height: u32,
    host_mem_size: usize,

    backing_iovecs: Option<Vec<(GuestAddress, usize)>>,
    component_mask: u8,
    size: u64,
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

pub enum ProcessDisplayResult {
    Success,
    CloseRequested,
    Error(GpuDisplayError),
}

impl VirtioGpu {
    /// Creates a new instance of the VirtioGpu state tracker.
    pub fn new(
        display: GpuDisplay,
        display_params: Vec<GpuDisplayParameters>,
        display_event: Arc<AtomicBool>,
        rutabaga: Rutabaga,
        mapper: Arc<Mutex<Option<Box<dyn SharedMemoryMapper>>>>,
        external_blob: bool,
        fixed_blob_mapping: bool,
        udmabuf: bool,
    ) -> Option<VirtioGpu> {
        let mut udmabuf_driver = None;
        if udmabuf {
            udmabuf_driver = Some(
                UdmabufDriver::new()
                    .map_err(|e| error!("failed to initialize udmabuf: {}", e))
                    .ok()?,
            );
        }

        let scanouts = display_params
            .iter()
            .enumerate()
            .map(|(display_index, display_param)| {
                (
                    display_index as u32,
                    VirtioGpuScanout::new_primary(display_index as u32, display_param.clone()),
                )
            })
            .collect::<Map<_, _>>();
        let cursor_scanout = VirtioGpuScanout::new_cursor();

        Some(VirtioGpu {
            display: Rc::new(RefCell::new(display)),
            scanouts,
            scanouts_updated: display_event,
            cursor_scanout,
            mapper,
            rutabaga,
            resources: Default::default(),
            external_blob,
            fixed_blob_mapping,
            udmabuf_driver,
        })
    }

    /// Imports the event device
    pub fn import_event_device(&mut self, event_device: EventDevice) -> VirtioGpuResult {
        let mut display = self.display.borrow_mut();
        let _event_device_id = display.import_event_device(event_device)?;
        Ok(OkNoData)
    }

    /// Gets a reference to the display passed into `new`.
    pub fn display(&mut self) -> &Rc<RefCell<GpuDisplay>> {
        &self.display
    }

    /// Gets the list of supported display resolutions as a slice of `(width, height, enabled)` tuples.
    pub fn display_info(&self) -> Vec<(u32, u32, bool)> {
        (0..VIRTIO_GPU_MAX_SCANOUTS)
            .map(|scanout_id| scanout_id as u32)
            .map(|scanout_id| {
                self.scanouts
                    .get(&scanout_id)
                    .map_or((0, 0, false), |scanout| {
                        (scanout.width, scanout.height, true)
                    })
            })
            .collect::<Vec<_>>()
    }

    // Connects new displays to the device.
    fn add_displays(&mut self, displays: Vec<DisplayParameters>) -> GpuControlResult {
        if self.scanouts.len() + displays.len() > VIRTIO_GPU_MAX_SCANOUTS {
            return GpuControlResult::TooManyDisplays(VIRTIO_GPU_MAX_SCANOUTS);
        }

        let mut available_scanout_ids = (0..VIRTIO_GPU_MAX_SCANOUTS)
            .map(|s| s as u32)
            .collect::<Set<u32>>();

        self.scanouts.keys().for_each(|scanout_id| {
            available_scanout_ids.remove(scanout_id);
        });

        for display_params in displays.into_iter() {
            let new_scanout_id = *available_scanout_ids.iter().next().unwrap();
            available_scanout_ids.remove(&new_scanout_id);

            self.scanouts.insert(
                new_scanout_id,
                VirtioGpuScanout::new_primary(new_scanout_id, display_params),
            );
        }

        self.scanouts_updated.store(true, Ordering::Relaxed);

        GpuControlResult::DisplaysUpdated
    }

    /// Returns the list of displays currently connected to the device.
    fn list_displays(&self) -> GpuControlResult {
        GpuControlResult::DisplayList {
            displays: self
                .scanouts
                .iter()
                .filter_map(|(scanout_id, scanout)| {
                    scanout
                        .display_params
                        .as_ref()
                        .cloned()
                        .map(|display_params| (*scanout_id, display_params))
                })
                .collect(),
        }
    }

    /// Removes the specified displays from the device.
    fn remove_displays(&mut self, display_ids: Vec<u32>) -> GpuControlResult {
        let display_ids_to_remove = Set::from_iter(display_ids.iter());
        display_ids_to_remove
            .into_iter()
            .try_for_each(|display_id| {
                self.scanouts
                    .get_mut(display_id)
                    .ok_or(GpuControlResult::NoSuchDisplay {
                        display_id: *display_id,
                    })
                    .map(|scanout| {
                        scanout.release_surface(&self.display);
                        scanout
                    })?;

                self.scanouts.remove(display_id);

                Ok(())
            })
            .err()
            .unwrap_or_else(|| {
                self.scanouts_updated.store(true, Ordering::Relaxed);
                GpuControlResult::DisplaysUpdated
            })
    }

    /// Performs the given command to interact with or modify the device.
    pub fn process_gpu_control_command(&mut self, cmd: GpuControlCommand) -> GpuControlResult {
        match cmd {
            GpuControlCommand::AddDisplays { displays } => self.add_displays(displays),
            GpuControlCommand::ListDisplays => self.list_displays(),
            GpuControlCommand::RemoveDisplays { display_ids } => self.remove_displays(display_ids),
        }
    }

    /// Processes the internal `display` events and returns `true` if any display was closed.
    pub fn process_display(&mut self) -> ProcessDisplayResult {
        let mut display = self.display.borrow_mut();
        let result = display.dispatch_events();
        match result {
            Ok(_) => (),
            Err(e) => {
                error!("failed to dispatch events: {}", e);
                return ProcessDisplayResult::Error(e);
            }
        }

        for scanout in self.scanouts.values() {
            let close_requested = scanout
                .surface_id
                .map(|surface_id| display.close_requested(surface_id))
                .unwrap_or(false);

            if close_requested {
                return ProcessDisplayResult::CloseRequested;
            }
        }

        ProcessDisplayResult::Success
    }

    /// Sets the given resource id as the source of scanout to the display.
    pub fn set_scanout(
        &mut self,
        scanout_id: u32,
        resource_id: u32,
        scanout_data: Option<VirtioScanoutBlobData>,
    ) -> VirtioGpuResult {
        self.update_scanout_resource(SurfaceType::Scanout, scanout_id, scanout_data, resource_id)
    }

    /// If the resource is the scanout resource, flush it to the display.
    pub fn flush_resource(&mut self, resource_id: u32) -> VirtioGpuResult {
        if resource_id == 0 {
            return Ok(OkNoData);
        }

        #[cfg(windows)]
        match self.rutabaga.resource_flush(resource_id) {
            Ok(_) => return Ok(OkNoData),
            Err(RutabagaError::Unsupported) => {}
            Err(e) => return Err(ErrRutabaga(e)),
        }

        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        // `resource_id` has already been verified to be non-zero
        let resource_id = match NonZeroU32::new(resource_id) {
            Some(id) => Some(id),
            None => return Ok(OkNoData),
        };

        for scanout in self.scanouts.values_mut() {
            if scanout.resource_id == resource_id {
                scanout.flush(&self.display, resource, &mut self.rutabaga)?;
            }
        }
        if self.cursor_scanout.resource_id == resource_id {
            self.cursor_scanout
                .flush(&self.display, resource, &mut self.rutabaga)?;
        }

        Ok(OkNoData)
    }

    /// Updates the cursor's memory to the given resource_id, and sets its position to the given
    /// coordinates.
    pub fn update_cursor(
        &mut self,
        resource_id: u32,
        scanout_id: u32,
        x: u32,
        y: u32,
    ) -> VirtioGpuResult {
        self.update_scanout_resource(SurfaceType::Cursor, scanout_id, None, resource_id)?;

        self.cursor_scanout.set_position(&self.display, x, y)?;

        self.flush_resource(resource_id)
    }

    /// Moves the cursor's position to the given coordinates.
    pub fn move_cursor(&mut self, _scanout_id: u32, x: u32, y: u32) -> VirtioGpuResult {
        self.cursor_scanout.set_position(&self.display, x, y)?;
        self.cursor_scanout.commit(&self.display)?;
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
        let handle = match self.rutabaga.export_blob(resource_id) {
            Ok(handle) => to_safe_descriptor(handle.os_handle),
            Err(_) => return ResourceResponse::Invalid,
        };

        let q = match self.rutabaga.query(resource_id) {
            Ok(query) => query,
            Err(_) => return ResourceResponse::Invalid,
        };

        ResourceResponse::Resource(ResourceInfo::Buffer(BufferInfo {
            handle,
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
            guest_cpu_mappable: q.guest_cpu_mappable,
        }))
    }

    /// If supported, export the fence with the given `fence_id` to a file.
    pub fn export_fence(&self, fence_id: u64) -> ResourceResponse {
        match self.rutabaga.export_fence(fence_id) {
            Ok(handle) => ResourceResponse::Resource(ResourceInfo::Fence {
                handle: to_safe_descriptor(handle.os_handle),
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

    /// Creates a fence with the RutabagaFence that can be used to determine when the previous
    /// command completed.
    pub fn create_fence(&mut self, rutabaga_fence: RutabagaFence) -> VirtioGpuResult {
        self.rutabaga.create_fence(rutabaga_fence)?;
        Ok(OkNoData)
    }

    /// Polls the Rutabaga backend.
    pub fn event_poll(&self) {
        self.rutabaga.event_poll();
    }

    /// Gets a pollable eventfd that signals the device to wakeup and poll the
    /// Rutabaga backend.
    pub fn poll_descriptor(&self) -> Option<SafeDescriptor> {
        self.rutabaga.poll_descriptor().map(to_safe_descriptor)
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
    /// tuples in the guest's physical address space. Converts to RutabagaIovec from the memory
    /// mapping.
    pub fn attach_backing(
        &mut self,
        resource_id: u32,
        mem: &GuestMemory,
        vecs: Vec<(GuestAddress, usize)>,
    ) -> VirtioGpuResult {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        let rutabaga_iovecs = sglist_to_rutabaga_iovecs(&vecs[..], mem).map_err(|_| ErrUnspec)?;
        self.rutabaga.attach_backing(resource_id, rutabaga_iovecs)?;
        resource.backing_iovecs = Some(vecs);
        Ok(OkNoData)
    }

    /// Detaches any previously attached iovecs from the resource.
    pub fn detach_backing(&mut self, resource_id: u32) -> VirtioGpuResult {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        self.rutabaga.detach_backing(resource_id)?;
        resource.backing_iovecs = None;
        Ok(OkNoData)
    }

    /// Releases guest kernel reference on the resource.
    pub fn unref_resource(&mut self, resource_id: u32) -> VirtioGpuResult {
        let resource = self
            .resources
            .remove(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        if resource.rutabaga_external_mapping {
            self.rutabaga.unmap(resource_id)?;
        }

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
        let buf = buf.map(|vs| {
            IoSliceMut::new(
                // SAFETY: trivially safe
                unsafe { std::slice::from_raw_parts_mut(vs.as_mut_ptr(), vs.size()) },
            )
        });
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
        let mut descriptor = None;
        let mut rutabaga_iovecs = None;

        if resource_create_blob.blob_flags & VIRTIO_GPU_BLOB_FLAG_CREATE_GUEST_HANDLE != 0 {
            descriptor = match self.udmabuf_driver {
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
            descriptor.map(|descriptor| RutabagaHandle {
                os_handle: to_rutabaga_descriptor(descriptor),
                handle_type: RUTABAGA_MEM_HANDLE_TYPE_DMABUF,
            }),
        )?;

        let resource = VirtioGpuResource::new(resource_id, 0, 0, resource_create_blob.size);

        // Rely on rutabaga to check for duplicate resource ids.
        self.resources.insert(resource_id, resource);
        Ok(self.result_from_query(resource_id))
    }

    /// Uses the hypervisor to map the rutabaga blob resource.
    ///
    /// When sandboxing is disabled, external_blob is unset and opaque fds are mapped by
    /// rutabaga as ExternalMapping.
    /// When sandboxing is enabled, external_blob is set and opaque fds must be mapped in the
    /// hypervisor process by Vulkano using metadata provided by Rutabaga::vulkan_info().
    pub fn resource_map_blob(&mut self, resource_id: u32, offset: u64) -> VirtioGpuResult {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        let map_info = self.rutabaga.map_info(resource_id).map_err(|_| ErrUnspec)?;

        let mut source: Option<VmMemorySource> = None;
        if let Ok(export) = self.rutabaga.export_blob(resource_id) {
            if let Ok(vulkan_info) = self.rutabaga.vulkan_info(resource_id) {
                source = Some(VmMemorySource::Vulkan {
                    descriptor: to_safe_descriptor(export.os_handle),
                    handle_type: export.handle_type,
                    memory_idx: vulkan_info.memory_idx,
                    device_uuid: vulkan_info.device_id.device_uuid,
                    driver_uuid: vulkan_info.device_id.driver_uuid,
                    size: resource.size,
                });
            } else if export.handle_type != RUTABAGA_MEM_HANDLE_TYPE_OPAQUE_FD {
                source = Some(VmMemorySource::Descriptor {
                    descriptor: to_safe_descriptor(export.os_handle),
                    offset: 0,
                    size: resource.size,
                });
            }
        }

        // fallback to ExternalMapping via rutabaga if sandboxing (hence external_blob) and fixed
        // mapping are both disabled as neither is currently compatible.
        if source.is_none() {
            if self.external_blob || self.fixed_blob_mapping {
                return Err(ErrUnspec);
            }

            let mapping = self.rutabaga.map(resource_id)?;
            // resources mapped via rutabaga must also be marked for unmap via rutabaga.
            resource.rutabaga_external_mapping = true;
            source = Some(VmMemorySource::ExternalMapping {
                ptr: mapping.ptr,
                size: mapping.size,
            });
        };

        let prot = match map_info & RUTABAGA_MAP_ACCESS_MASK {
            RUTABAGA_MAP_ACCESS_READ => Protection::read(),
            RUTABAGA_MAP_ACCESS_WRITE => Protection::write(),
            RUTABAGA_MAP_ACCESS_RW => Protection::read_write(),
            _ => return Err(ErrUnspec),
        };

        let cache = if cfg!(feature = "noncoherent-dma")
            && map_info & RUTABAGA_MAP_CACHE_MASK != RUTABAGA_MAP_CACHE_CACHED
        {
            MemCacheType::CacheNonCoherent
        } else {
            MemCacheType::CacheCoherent
        };

        self.mapper
            .lock()
            .as_mut()
            .expect("No backend request connection found")
            .add_mapping(source.unwrap(), offset, prot, cache)
            .map_err(|_| ErrUnspec)?;

        resource.shmem_offset = Some(offset);
        // Access flags not a part of the virtio-gpu spec.
        Ok(OkMapInfo {
            map_info: map_info & RUTABAGA_MAP_CACHE_MASK,
        })
    }

    /// Uses the hypervisor to unmap the blob resource.
    pub fn resource_unmap_blob(&mut self, resource_id: u32) -> VirtioGpuResult {
        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        let shmem_offset = resource.shmem_offset.ok_or(ErrUnspec)?;
        self.mapper
            .lock()
            .as_mut()
            .expect("No backend request connection found")
            .remove_mapping(shmem_offset)
            .map_err(|_| ErrUnspec)?;
        resource.shmem_offset = None;

        if resource.rutabaga_external_mapping {
            self.rutabaga.unmap(resource_id)?;
            resource.rutabaga_external_mapping = false;
        }

        Ok(OkNoData)
    }

    /// Gets the EDID for the specified scanout ID. If that scanout is not enabled, it would return
    /// the EDID of a default display.
    pub fn get_edid(&self, scanout_id: u32) -> VirtioGpuResult {
        let display_info = match self.scanouts.get(&scanout_id) {
            Some(scanout) => {
                // Primary scanouts should always have display params.
                let params = scanout.display_params.as_ref().unwrap();
                DisplayInfo::new(params)
            }
            None => DisplayInfo::new(&Default::default()),
        };
        EdidBytes::new(&display_info)
    }

    /// Creates a rutabaga context.
    pub fn create_context(
        &mut self,
        ctx_id: u32,
        context_init: u32,
        context_name: Option<&str>,
    ) -> VirtioGpuResult {
        self.rutabaga
            .create_context(ctx_id, context_init, context_name)?;
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
    pub fn submit_command(
        &mut self,
        ctx_id: u32,
        commands: &mut [u8],
        fence_ids: &[u64],
    ) -> VirtioGpuResult {
        self.rutabaga.submit_command(ctx_id, commands, fence_ids)?;
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

    fn update_scanout_resource(
        &mut self,
        scanout_type: SurfaceType,
        scanout_id: u32,
        scanout_data: Option<VirtioScanoutBlobData>,
        resource_id: u32,
    ) -> VirtioGpuResult {
        let scanout: &mut VirtioGpuScanout;
        let mut scanout_parent_surface_id = None;

        match scanout_type {
            SurfaceType::Cursor => {
                let parent_scanout_id = scanout_id;

                scanout_parent_surface_id = self
                    .scanouts
                    .get(&parent_scanout_id)
                    .ok_or(ErrInvalidScanoutId)
                    .map(|parent_scanout| parent_scanout.surface_id)?;

                scanout = &mut self.cursor_scanout;
            }
            SurfaceType::Scanout => {
                scanout = self
                    .scanouts
                    .get_mut(&scanout_id)
                    .ok_or(ErrInvalidScanoutId)?;
            }
        };

        // Virtio spec: "The driver can use resource_id = 0 to disable a scanout."
        if resource_id == 0 {
            // Ignore any initial set_scanout(..., resource_id: 0) calls.
            if scanout.resource_id.is_some() {
                scanout.release_surface(&self.display);
            }

            scanout.resource_id = None;
            return Ok(OkNoData);
        }

        let resource = self
            .resources
            .get_mut(&resource_id)
            .ok_or(ErrInvalidResourceId)?;

        // Ensure scanout has a display surface.
        match scanout_type {
            SurfaceType::Cursor => {
                if let Some(scanout_parent_surface_id) = scanout_parent_surface_id {
                    scanout.create_surface(&self.display, Some(scanout_parent_surface_id))?;
                }
            }
            SurfaceType::Scanout => {
                scanout.create_surface(&self.display, None)?;
            }
        }

        resource.scanout_data = scanout_data;

        // `resource_id` has already been verified to be non-zero
        let resource_id = match NonZeroU32::new(resource_id) {
            Some(id) => id,
            None => return Ok(OkNoData),
        };
        scanout.resource_id = Some(resource_id);

        Ok(OkNoData)
    }

    pub fn snapshot(&self) -> anyhow::Result<VirtioGpuSnapshot> {
        Ok(VirtioGpuSnapshot {
            scanouts: self
                .scanouts
                .iter()
                .map(|(i, s)| (*i, s.snapshot()))
                .collect(),
            scanouts_updated: self.scanouts_updated.load(Ordering::SeqCst),
            cursor_scanout: self.cursor_scanout.snapshot(),
            rutabaga: {
                let mut buffer = std::io::Cursor::new(Vec::new());
                self.rutabaga
                    .snapshot(&mut buffer, "")
                    .context("failed to snapshot rutabaga")?;
                buffer.into_inner()
            },
            resources: self
                .resources
                .iter()
                .map(|(i, r)| (*i, r.snapshot()))
                .collect(),
        })
    }

    pub fn restore(
        &mut self,
        snapshot: VirtioGpuSnapshot,
        mem: &GuestMemory,
    ) -> anyhow::Result<()> {
        assert!(self.scanouts.keys().eq(snapshot.scanouts.keys()));
        for (i, s) in snapshot.scanouts.into_iter() {
            self.scanouts.get_mut(&i).unwrap().restore(
                s,
                // Only the cursor scanout can have a parent.
                None,
                &self.display,
            )?;
        }
        self.scanouts_updated
            .store(snapshot.scanouts_updated, Ordering::SeqCst);

        let cursor_parent_surface_id = snapshot
            .cursor_scanout
            .parent_scanout_id
            .and_then(|i| self.scanouts.get(&i).unwrap().surface_id);
        self.cursor_scanout.restore(
            snapshot.cursor_scanout,
            cursor_parent_surface_id,
            &self.display,
        )?;

        self.rutabaga
            .restore(&mut &snapshot.rutabaga[..], "")
            .context("failed to restore rutabaga")?;

        for (id, s) in snapshot.resources.into_iter() {
            let backing_iovecs = s.backing_iovecs.clone();
            self.resources.insert(id, VirtioGpuResource::restore(s));
            if let Some(backing_iovecs) = backing_iovecs {
                self.attach_backing(id, mem, backing_iovecs)?;
            }
        }

        Ok(())
    }
}

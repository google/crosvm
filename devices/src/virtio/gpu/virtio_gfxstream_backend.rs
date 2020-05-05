// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implementation of a virtio-gpu protocol command processor for
//! API passthrough.

#![cfg(feature = "gfxstream")]

use std::cell::RefCell;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap as Map;
use std::fmt::{self, Display};
use std::mem::{size_of, transmute};
use std::os::raw::{c_char, c_int, c_uchar, c_uint, c_void};
use std::panic;
use std::ptr::null_mut;
use std::rc::Rc;
use std::sync::Arc;
use std::usize;

use base::{error, ExternalMapping, ExternalMappingError, ExternalMappingResult};
use gpu_display::*;
use gpu_renderer::RendererFlags;
use msg_socket::{MsgReceiver, MsgSender};
use resources::Alloc;
use sync::Mutex;
use vm_control::{VmMemoryControlRequestSocket, VmMemoryRequest, VmMemoryResponse};
use vm_memory::{GuestAddress, GuestMemory};

use super::protocol::GpuResponse;
pub use super::virtio_backend::{VirtioBackend, VirtioResource};
use crate::virtio::gpu::{
    Backend, VirtioScanoutBlobData, VIRTIO_F_VERSION_1, VIRTIO_GPU_F_RESOURCE_BLOB,
    VIRTIO_GPU_F_VIRGL,
};
use crate::virtio::resource_bridge::ResourceResponse;

/// Errors for gfxstream-specific usage
#[derive(Debug)]
pub enum GfxStreamError {
    /// Invalid size used for a command.
    InvalidCommandSize(usize),
}

impl Display for GfxStreamError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::GfxStreamError::*;

        match self {
            InvalidCommandSize(size) => write!(
                f,
                "gfxstream: invalid command size: {} (expected u32 multiple)",
                size
            ),
        }
    }
}

/// The result of an operation for gfxstream-specific ops.
pub type GfxStreamResult<T> = std::result::Result<T, GfxStreamError>;

// C definitions related to gfxstream
// In gfxstream, only write_fence is used
// (for synchronization of commands delivered)
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct GfxStreamRendererCallbacks {
    pub version: c_int,
    pub write_fence: unsafe extern "C" fn(cookie: *mut c_void, fence: u32),
}

// virtio-gpu-3d transfer-related structs (begin)
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct virgl_renderer_resource_create_args {
    pub handle: u32,
    pub target: u32,
    pub format: u32,
    pub bind: u32,
    pub width: u32,
    pub height: u32,
    pub depth: u32,
    pub array_size: u32,
    pub last_level: u32,
    pub nr_samples: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct virgl_renderer_resource_info {
    pub handle: u32,
    pub virgl_format: u32,
    pub width: u32,
    pub height: u32,
    pub depth: u32,
    pub flags: u32,
    pub tex_id: u32,
    pub stride: u32,
    pub drm_fourcc: c_int,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct virgl_box {
    pub x: u32,
    pub y: u32,
    pub z: u32,
    pub w: u32,
    pub h: u32,
    pub d: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct iovec {
    pub iov_base: *mut c_void,
    pub iov_len: usize,
}

// virtio-gpu-3d transfer-related structs (end)

#[link(name = "gfxstream_backend")]
extern "C" {

    // Function to globally init gfxstream backend's internal state, taking display/renderer
    // parameters.
    fn gfxstream_backend_init(
        display_width: u32,
        display_height: u32,
        display_type: u32,
        renderer_cookie: *mut c_void,
        renderer_flags: i32,
        renderer_callbacks: *mut GfxStreamRendererCallbacks,
    );

    // virtio-gpu-3d ioctl functions (begin)

    // In gfxstream, the resource create/transfer ioctls correspond to creating buffers for API
    // forwarding and the notification of new API calls forwarded by the guest, unless they
    // correspond to minigbm resource targets (PIPE_TEXTURE_2D), in which case they create globally
    // visible shared GL textures to support gralloc.
    fn pipe_virgl_renderer_poll();
    fn pipe_virgl_renderer_resource_create(
        args: *mut virgl_renderer_resource_create_args,
        iov: *mut iovec,
        num_iovs: u32,
    ) -> c_int;

    fn pipe_virgl_renderer_resource_unref(res_handle: u32);
    fn pipe_virgl_renderer_context_create(handle: u32, nlen: u32, name: *const c_char) -> c_int;
    fn pipe_virgl_renderer_context_destroy(handle: u32);
    fn pipe_virgl_renderer_transfer_read_iov(
        handle: u32,
        ctx_id: u32,
        level: u32,
        stride: u32,
        layer_stride: u32,
        box_: *mut virgl_box,
        offset: u64,
        iov: *mut iovec,
        iovec_cnt: c_int,
    ) -> c_int;
    fn pipe_virgl_renderer_transfer_write_iov(
        handle: u32,
        ctx_id: u32,
        level: c_int,
        stride: u32,
        layer_stride: u32,
        box_: *mut virgl_box,
        offset: u64,
        iovec: *mut iovec,
        iovec_cnt: c_uint,
    ) -> c_int;
    fn pipe_virgl_renderer_submit_cmd(
        commands: *mut c_void,
        ctx_id: i32,
        dword_count: i32,
    ) -> c_int;
    fn pipe_virgl_renderer_resource_attach_iov(
        res_handle: c_int,
        iov: *mut iovec,
        num_iovs: c_int,
    ) -> c_int;
    fn pipe_virgl_renderer_resource_detach_iov(
        res_handle: c_int,
        iov: *mut *mut iovec,
        num_iovs: *mut c_int,
    );
    fn pipe_virgl_renderer_create_fence(client_fence_id: c_int, ctx_id: u32) -> c_int;
    fn pipe_virgl_renderer_ctx_attach_resource(ctx_id: c_int, res_handle: c_int);
    fn pipe_virgl_renderer_ctx_detach_resource(ctx_id: c_int, res_handle: c_int);

    fn stream_renderer_flush_resource_and_readback(
        res_handle: u32,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        pixels: *mut c_uchar,
        max_bytes: u32,
    );

    fn stream_renderer_resource_create_v2(res_handle: u32, hostmemId: u64);
    fn stream_renderer_resource_map(
        res_handle: u32,
        map: *mut *mut c_void,
        out_size: *mut u64,
    ) -> c_int;
    fn stream_renderer_resource_unmap(res_handle: u32) -> c_int;
}

// Fence state stuff (begin)

struct FenceState {
    latest_fence: u32,
}

impl FenceState {
    pub fn write(&mut self, latest_fence: u32) {
        if latest_fence > self.latest_fence {
            self.latest_fence = latest_fence;
        }
    }
}

struct VirglCookie {
    fence_state: Rc<RefCell<FenceState>>,
}

extern "C" fn write_fence(cookie: *mut c_void, fence: u32) {
    assert!(!cookie.is_null());
    let cookie = unsafe { &*(cookie as *mut VirglCookie) };

    // Track the most recent fence.
    let mut fence_state = cookie.fence_state.borrow_mut();
    fence_state.write(fence);
}

const GFXSTREAM_RENDERER_CALLBACKS: &GfxStreamRendererCallbacks = &GfxStreamRendererCallbacks {
    version: 1,
    write_fence,
};

// Fence state stuff (end)

struct VirtioGfxStreamResource {
    guest_memory_backing: Option<Vec<iovec>>,
    kvm_slot: Option<u32>,
}

pub struct VirtioGfxStreamBackend {
    base: VirtioBackend,

    /// Mapping from resource ids to in-use GuestMemory.
    resources: Map<u32, VirtioGfxStreamResource>,

    /// All commands processed by this backend are synchronous
    /// and are either completed immediately or handled in a different layer,
    /// so we just need to keep track of the latest created fence
    /// and return that in fence_poll().
    fence_state: Rc<RefCell<FenceState>>,

    /// For host coherent memory: Retrieves the result
    /// of mapping host memory to the guest along with
    /// kvm slot.
    gpu_device_socket: VmMemoryControlRequestSocket,
    pci_bar: Alloc,

    map_request: Arc<Mutex<Option<ExternalMapping>>>,
}

fn map_func(resource_id: u32) -> ExternalMappingResult<(u64, usize)> {
    let mut map: *mut c_void = null_mut();
    let map_ptr: *mut *mut c_void = &mut map;
    let mut size: u64 = 0;

    // Safe because the Stream renderer wraps and validates use of vkMapMemory.
    let ret = unsafe { stream_renderer_resource_map(resource_id, map_ptr, &mut size) };
    if ret != 0 {
        return Err(ExternalMappingError::LibraryError(ret));
    }
    Ok((map as u64, size as usize))
}

fn unmap_func(resource_id: u32) -> () {
    unsafe { stream_renderer_resource_unmap(resource_id) };
}

impl VirtioGfxStreamBackend {
    pub fn new(
        display: GpuDisplay,
        display_width: u32,
        display_height: u32,
        renderer_flags: RendererFlags,
        gpu_device_socket: VmMemoryControlRequestSocket,
        pci_bar: Alloc,
        map_request: Arc<Mutex<Option<ExternalMapping>>>,
    ) -> VirtioGfxStreamBackend {
        let fence_state = Rc::new(RefCell::new(FenceState { latest_fence: 0 }));
        let cookie: *mut VirglCookie = Box::into_raw(Box::new(VirglCookie {
            fence_state: Rc::clone(&fence_state),
        }));

        let display_rc_refcell = Rc::new(RefCell::new(display));

        let scanout_surface = match (display_rc_refcell.borrow_mut()).create_surface(
            None,
            display_width,
            display_height,
        ) {
            Ok(surface) => surface,
            Err(e) => {
                error!("Failed to create display surface: {}", e);
                0
            }
        };

        unsafe {
            gfxstream_backend_init(
                display_width,
                display_height,
                1, /* default to shmem display */
                cookie as *mut c_void,
                renderer_flags.into(),
                transmute(GFXSTREAM_RENDERER_CALLBACKS),
            );
        }

        VirtioGfxStreamBackend {
            base: VirtioBackend {
                display: Rc::clone(&display_rc_refcell),
                display_width,
                display_height,
                event_devices: Default::default(),
                scanout_resource_id: None,
                scanout_surface_id: Some(scanout_surface),
                cursor_resource_id: None,
                cursor_surface_id: None,
            },
            resources: Default::default(),
            fence_state,
            gpu_device_socket,
            pci_bar,
            map_request,
        }
    }

    fn submit_command_impl(&mut self, ctx_id: u32, commands: &mut [u8]) -> GfxStreamResult<()> {
        if commands.len() % size_of::<u32>() != 0 {
            return Err(GfxStreamError::InvalidCommandSize(commands.len()));
        }

        let dword_count = commands.len() / size_of::<u32>();

        unsafe {
            pipe_virgl_renderer_submit_cmd(
                commands.as_mut_ptr() as *mut c_void,
                ctx_id as i32,
                dword_count as i32,
            );
        }

        Ok(())
    }
}

impl Backend for VirtioGfxStreamBackend {
    /// Returns the number of capsets provided by the Backend.
    fn capsets() -> u32 {
        1
    }

    /// Returns the bitset of virtio features provided by the Backend.
    fn features() -> u64 {
        1 << VIRTIO_GPU_F_VIRGL | 1 << VIRTIO_F_VERSION_1 | 1 << VIRTIO_GPU_F_RESOURCE_BLOB
    }

    /// Returns the underlying Backend.
    fn build(
        display: GpuDisplay,
        display_width: u32,
        display_height: u32,
        renderer_flags: RendererFlags,
        _event_devices: Vec<EventDevice>,
        gpu_device_socket: VmMemoryControlRequestSocket,
        pci_bar: Alloc,
        map_request: Arc<Mutex<Option<ExternalMapping>>>,
        _external_blob: bool,
    ) -> Option<Box<dyn Backend>> {
        Some(Box::new(VirtioGfxStreamBackend::new(
            display,
            display_width,
            display_height,
            renderer_flags,
            gpu_device_socket,
            pci_bar,
            map_request,
        )))
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
    /// from a X11 window for example).
    fn import_event_device(&mut self, event_device: EventDevice, scanout: u32) {
        self.base.import_event_device(event_device, scanout);
    }

    /// If supported, export the resource with the given id to a file.
    fn export_resource(&mut self, _id: u32) -> ResourceResponse {
        ResourceResponse::Invalid
    }

    /// Creates a fence with the given id that can be used to determine when the previous command
    /// completed.
    fn create_fence(&mut self, ctx_id: u32, fence_id: u32) -> GpuResponse {
        unsafe {
            pipe_virgl_renderer_create_fence(fence_id as i32, ctx_id);
        }
        GpuResponse::OkNoData
    }

    /// Returns the id of the latest fence to complete.
    fn fence_poll(&mut self) -> u32 {
        unsafe {
            pipe_virgl_renderer_poll();
        }
        self.fence_state.borrow().latest_fence
    }

    fn create_resource_2d(
        &mut self,
        _id: u32,
        _width: u32,
        _height: u32,
        _format: u32,
    ) -> GpuResponse {
        // Not considered for gfxstream
        GpuResponse::ErrUnspec
    }

    /// Removes the guest's reference count for the given resource id.
    fn unref_resource(&mut self, id: u32) -> GpuResponse {
        match self.resources.remove(&id) {
            Some(_) => (),
            None => {
                return GpuResponse::ErrInvalidResourceId;
            }
        }

        unsafe {
            pipe_virgl_renderer_resource_unref(id);
        }

        GpuResponse::OkNoData
    }

    /// Sets the given resource id as the source of scanout to the display.
    fn set_scanout(
        &mut self,
        _scanout_id: u32,
        _resource_id: u32,
        _scanout_data: Option<VirtioScanoutBlobData>,
    ) -> GpuResponse {
        GpuResponse::OkNoData
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
        // For now, always update the whole display.
        let mut display_ref = self.base.display.borrow_mut();

        let scanout_surface_id = match self.base.scanout_surface_id {
            Some(id) => id,
            _ => {
                error!("No scanout surface created for backend!");
                return GpuResponse::ErrInvalidResourceId;
            }
        };

        let fb = match display_ref.framebuffer_region(
            scanout_surface_id,
            0,
            0,
            self.base.display_width,
            self.base.display_height,
        ) {
            Some(fb) => fb,
            None => {
                panic!(
                    "failed to access framebuffer for surface {}",
                    scanout_surface_id
                );
            }
        };

        let fb_volatile_slice = fb.as_volatile_slice();
        let fb_begin = fb_volatile_slice.as_ptr() as *mut c_uchar;
        let fb_bytes = fb_volatile_slice.size() as usize;

        unsafe {
            stream_renderer_flush_resource_and_readback(
                id,
                0,
                0,
                self.base.display_width,
                self.base.display_height,
                fb_begin,
                fb_bytes as u32,
            );
        }

        display_ref.flip(scanout_surface_id);

        GpuResponse::OkNoData
    }

    /// Copes the given rectangle of pixels of the given resource's backing memory to the host side
    /// resource.
    fn transfer_to_resource_2d(
        &mut self,
        _id: u32,
        _x: u32,
        _y: u32,
        _width: u32,
        _height: u32,
        _src_offset: u64,
        _mem: &GuestMemory,
    ) -> GpuResponse {
        // Not considered for gfxstream
        GpuResponse::ErrInvalidResourceId
    }

    /// Attaches backing memory to the given resource, represented by a `Vec` of `(address, size)`
    /// tuples in the guest's physical address space.
    fn attach_backing(
        &mut self,
        id: u32,
        mem: &GuestMemory,
        vecs: Vec<(GuestAddress, usize)>,
    ) -> GpuResponse {
        let resource = match self.resources.get_mut(&id) {
            Some(resource) => resource,
            None => return GpuResponse::ErrInvalidResourceId,
        };

        let mut backing_iovecs: Vec<iovec> = Vec::new();

        for (addr, len) in vecs {
            let slice = mem.get_slice_at_addr(addr, len).unwrap();
            backing_iovecs.push(iovec {
                iov_base: slice.as_ptr() as *mut c_void,
                iov_len: len as usize,
            });
        }

        unsafe {
            pipe_virgl_renderer_resource_attach_iov(
                id as i32,
                backing_iovecs.as_mut_ptr() as *mut iovec,
                backing_iovecs.len() as i32,
            );
        }

        resource.guest_memory_backing = Some(backing_iovecs);
        GpuResponse::OkNoData
    }

    /// Detaches any backing memory from the given resource, if there is any.
    fn detach_backing(&mut self, id: u32) -> GpuResponse {
        let resource = match self.resources.get_mut(&id) {
            Some(resource) => resource,
            None => return GpuResponse::ErrInvalidResourceId,
        };

        unsafe {
            pipe_virgl_renderer_resource_detach_iov(
                id as i32,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
        }

        resource.guest_memory_backing = None;
        GpuResponse::OkNoData
    }

    fn update_cursor(&mut self, _id: u32, _x: u32, _y: u32) -> GpuResponse {
        // Not considered for gfxstream
        GpuResponse::OkNoData
    }

    fn move_cursor(&mut self, _x: u32, _y: u32) -> GpuResponse {
        // Not considered for gfxstream
        GpuResponse::OkNoData
    }

    fn get_capset_info(&self, index: u32) -> GpuResponse {
        if 0 != index {
            return GpuResponse::ErrUnspec;
        }
        GpuResponse::OkCapsetInfo {
            id: index,
            version: 1,
            size: 0,
        }
    }

    fn get_capset(&self, id: u32, _version: u32) -> GpuResponse {
        if 0 != id {
            return GpuResponse::ErrUnspec;
        }
        GpuResponse::OkCapset(Vec::new())
    }

    fn create_renderer_context(&mut self, id: u32) -> GpuResponse {
        unsafe {
            pipe_virgl_renderer_context_create(id, 1, std::ptr::null_mut());
        }
        GpuResponse::OkNoData
    }

    fn destroy_renderer_context(&mut self, id: u32) -> GpuResponse {
        unsafe {
            pipe_virgl_renderer_context_destroy(id);
        }
        GpuResponse::OkNoData
    }

    fn context_attach_resource(&mut self, ctx_id: u32, res_id: u32) -> GpuResponse {
        unsafe {
            pipe_virgl_renderer_ctx_attach_resource(ctx_id as i32, res_id as i32);
        }
        GpuResponse::OkNoData
    }

    fn context_detach_resource(&mut self, ctx_id: u32, res_id: u32) -> GpuResponse {
        unsafe {
            pipe_virgl_renderer_ctx_detach_resource(ctx_id as i32, res_id as i32);
        }
        GpuResponse::OkNoData
    }

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

        match self.resources.entry(id) {
            Entry::Vacant(entry) => {
                entry.insert(VirtioGfxStreamResource {
                    guest_memory_backing: None, /* no guest memory attached yet */
                    kvm_slot: None,
                });
            }
            Entry::Occupied(_) => {
                return GpuResponse::ErrInvalidResourceId;
            }
        }

        let mut create_args = virgl_renderer_resource_create_args {
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

        unsafe {
            pipe_virgl_renderer_resource_create(
                &mut create_args as *mut virgl_renderer_resource_create_args,
                std::ptr::null_mut(),
                0,
            );
        }

        GpuResponse::OkNoData
    }

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
        let mut transfer_box = virgl_box {
            x,
            y,
            z,
            w: width,
            h: height,
            d: depth,
        };

        unsafe {
            pipe_virgl_renderer_transfer_write_iov(
                res_id,
                ctx_id,
                level as i32,
                stride,
                layer_stride,
                &mut transfer_box as *mut virgl_box,
                offset,
                std::ptr::null_mut(),
                0,
            );
        }
        GpuResponse::OkNoData
    }

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
        let mut transfer_box = virgl_box {
            x,
            y,
            z,
            w: width,
            h: height,
            d: depth,
        };

        unsafe {
            pipe_virgl_renderer_transfer_read_iov(
                res_id,
                ctx_id,
                level,
                stride,
                layer_stride,
                &mut transfer_box as *mut virgl_box,
                offset,
                std::ptr::null_mut(),
                0,
            );
        }
        GpuResponse::OkNoData
    }

    fn submit_command(&mut self, ctx_id: u32, commands: &mut [u8]) -> GpuResponse {
        match self.submit_command_impl(ctx_id, commands) {
            Ok(_) => GpuResponse::OkNoData,
            Err(e) => {
                error!("submit_command error: {}", e);
                GpuResponse::ErrUnspec
            }
        }
    }

    // Not considered for gfxstream
    fn force_ctx_0(&mut self) {}

    fn resource_create_blob(
        &mut self,
        resource_id: u32,
        _ctx_id: u32,
        _blob_mem: u32,
        _blob_flags: u32,
        blob_id: u64,
        _size: u64,
        _vecs: Vec<(GuestAddress, usize)>,
        _mem: &GuestMemory,
    ) -> GpuResponse {
        match self.resources.entry(resource_id) {
            Entry::Vacant(entry) => {
                entry.insert(VirtioGfxStreamResource {
                    guest_memory_backing: None, /* no guest memory attached yet */
                    kvm_slot: None,
                });
            }
            Entry::Occupied(_) => {
                return GpuResponse::ErrInvalidResourceId;
            }
        }

        unsafe {
            stream_renderer_resource_create_v2(resource_id, blob_id);
        }
        GpuResponse::OkNoData
    }

    fn resource_map_blob(&mut self, resource_id: u32, offset: u64) -> GpuResponse {
        let resource = match self.resources.get_mut(&resource_id) {
            Some(resource) => resource,
            None => return GpuResponse::ErrInvalidResourceId,
        };

        let map_result = unsafe { ExternalMapping::new(resource_id, map_func, unmap_func) };
        if map_result.is_err() {
            return GpuResponse::ErrUnspec;
        }

        let mapping = map_result.unwrap();
        {
            // scope for lock
            let mut map_req = self.map_request.lock();
            if map_req.is_some() {
                return GpuResponse::ErrUnspec;
            }
            *map_req = Some(mapping);
        }

        let request = VmMemoryRequest::RegisterHostPointerAtPciBarOffset(self.pci_bar, offset);
        match self.gpu_device_socket.send(&request) {
            Ok(_) => (),
            Err(e) => {
                error!("failed to send map request: {}", e);
                return GpuResponse::ErrUnspec;
            }
        }

        let response = match self.gpu_device_socket.recv() {
            Ok(response) => response,
            Err(e) => {
                error!("failed to receive data from map request: {}", e);
                return GpuResponse::ErrUnspec;
            }
        };

        match response {
            VmMemoryResponse::RegisterMemory { pfn: _, slot } => {
                // 0x02 for uncached type in map info
                resource.kvm_slot = Some(slot);
                GpuResponse::OkMapInfo { map_info: 0x02 }
            }
            VmMemoryResponse::Err(e) => {
                error!("received an error on mapping memory: {}", e);
                GpuResponse::ErrUnspec
            }
            _ => {
                error!("recieved an unexpected response while mapping memory");
                GpuResponse::ErrUnspec
            }
        }
    }

    fn resource_unmap_blob(&mut self, resource_id: u32) -> GpuResponse {
        let resource = match self.resources.get_mut(&resource_id) {
            Some(r) => r,
            None => return GpuResponse::ErrInvalidResourceId,
        };

        let kvm_slot = match resource.kvm_slot {
            Some(kvm_slot) => kvm_slot,
            None => return GpuResponse::ErrUnspec,
        };

        let request = VmMemoryRequest::UnregisterMemory(kvm_slot);
        match self.gpu_device_socket.send(&request) {
            Ok(_) => (),
            Err(e) => {
                error!("failed to send request on unmapping memory: {}", e);
                return GpuResponse::ErrUnspec;
            }
        }

        let response = match self.gpu_device_socket.recv() {
            Ok(response) => response,
            Err(e) => {
                error!("failed to receive data on unmapping memory: {}", e);
                return GpuResponse::ErrUnspec;
            }
        };

        match response {
            VmMemoryResponse::Ok => {
                resource.kvm_slot = None;
                GpuResponse::OkNoData
            }
            VmMemoryResponse::Err(e) => {
                error!("received an error when unmapping memory: {}", e);
                GpuResponse::ErrUnspec
            }
            _ => {
                error!("recieved an unexpected response when unmapping memory");
                GpuResponse::ErrUnspec
            }
        }
    }
}

// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implementation of a virtio-gpu protocol command processor which supports only display.

use std::cell::RefCell;
use std::cmp::{max, min};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap as Map;
use std::fmt::{self, Display};
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;
use std::usize;

use base::{error, ExternalMapping};
use data_model::*;
use gpu_display::*;
use gpu_renderer::RendererFlags;
use resources::Alloc;
use sync::Mutex;
use vm_control::VmMemoryControlRequestSocket;
use vm_memory::{GuestAddress, GuestMemory};

use super::protocol::GpuResponse;
pub use super::virtio_backend::{VirtioBackend, VirtioResource};
use crate::virtio::gpu::{Backend, VirtioScanoutBlobData, VIRTIO_F_VERSION_1};
use crate::virtio::resource_bridge::ResourceResponse;

#[derive(Debug)]
pub enum Error {
    CheckedArithmetic {
        field1: (&'static str, usize),
        field2: (&'static str, usize),
        op: &'static str,
    },
    CheckedRange {
        field1: (&'static str, usize),
        field2: (&'static str, usize),
    },
    MemCopy(VolatileMemoryError),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            CheckedArithmetic {
                field1: (label1, value1),
                field2: (label2, value2),
                op,
            } => write!(
                f,
                "arithmetic failed: {}({}) {} {}({})",
                label1, value1, op, label2, value2
            ),
            CheckedRange {
                field1: (label1, value1),
                field2: (label2, value2),
            } => write!(
                f,
                "range check failed: {}({}) vs {}({})",
                label1, value1, label2, value2
            ),
            MemCopy(e) => write!(f, "{}", e),
        }
    }
}

macro_rules! checked_arithmetic {
    ($x:ident $op:ident $y:ident $op_name:expr) => {
        $x.$op($y).ok_or_else(|| Error::CheckedArithmetic {
            field1: (stringify!($x), $x as usize),
            field2: (stringify!($y), $y as usize),
            op: $op_name,
        })
    };
    ($x:ident + $y:ident) => {
        checked_arithmetic!($x checked_add $y "+")
    };
    ($x:ident - $y:ident) => {
        checked_arithmetic!($x checked_sub $y "-")
    };
    ($x:ident * $y:ident) => {
        checked_arithmetic!($x checked_mul $y "*")
    };
}

macro_rules! checked_range {
    ($x:expr; <= $y:expr) => {
        if $x <= $y {
            Ok(())
        } else {
            Err(Error::CheckedRange {
                field1: (stringify!($x), $x as usize),
                field2: (stringify!($y), $y as usize),
            })
        }
    };
    ($x:ident <= $y:ident) => {
        check_range!($x; <= $y)
    };
}

pub struct Virtio2DResource {
    width: u32,
    height: u32,
    guest_iovecs: Vec<(GuestAddress, usize)>,
    guest_mem: Option<GuestMemory>,
    host_mem: Vec<u8>,
    host_mem_stride: u32,
    no_sync_send: PhantomData<*mut ()>,
}

/// Transfers a resource from potentially many chunked src VolatileSlices to a dst VolatileSlice.
pub fn transfer<'a, S: Iterator<Item = VolatileSlice<'a>>>(
    resource_w: u32,
    resource_h: u32,
    rect_x: u32,
    rect_y: u32,
    rect_w: u32,
    rect_h: u32,
    dst_stride: u32,
    dst_offset: u64,
    dst: VolatileSlice,
    src_stride: u32,
    src_offset: u64,
    mut srcs: S,
) -> Result<(), Error> {
    if rect_w == 0 || rect_h == 0 {
        return Ok(());
    }

    checked_range!(checked_arithmetic!(rect_x + rect_w)?; <= resource_w)?;
    checked_range!(checked_arithmetic!(rect_y + rect_h)?; <= resource_h)?;

    let bytes_per_pixel = 4 as u64;

    let rect_x = rect_x as u64;
    let rect_y = rect_y as u64;
    let rect_w = rect_w as u64;
    let rect_h = rect_h as u64;

    let dst_stride = dst_stride as u64;
    let dst_offset = dst_offset as u64;
    let dst_resource_offset = dst_offset + (rect_y * dst_stride) + (rect_x * bytes_per_pixel);

    let src_stride = src_stride as u64;
    let src_offset = src_offset as u64;
    let src_resource_offset = src_offset + (rect_y * src_stride) + (rect_x * bytes_per_pixel);

    let mut next_src;
    let mut next_line;
    let mut current_height = 0 as u64;
    let mut src_opt = srcs.next();

    // Cumulative start offset of the current src.
    let mut src_start_offset = 0 as u64;
    while let Some(src) = src_opt {
        if current_height >= rect_h {
            break;
        }

        let src_size = src.size() as u64;

        // Cumulative end offset of the current src.
        let src_end_offset = checked_arithmetic!(src_start_offset + src_size)?;

        let src_line_vertical_offset = checked_arithmetic!(current_height * src_stride)?;
        let src_line_horizontal_offset = checked_arithmetic!(rect_w * bytes_per_pixel)?;

        // Cumulative start/end offsets of the next line to copy within all srcs.
        let src_line_start_offset =
            checked_arithmetic!(src_resource_offset + src_line_vertical_offset)?;
        let src_line_end_offset =
            checked_arithmetic!(src_line_start_offset + src_line_horizontal_offset)?;

        // Clamp the line start/end offset to be inside the current src.
        let src_copyable_start_offset = max(src_line_start_offset, src_start_offset);
        let src_copyable_end_offset = min(src_line_end_offset, src_end_offset);

        if src_copyable_start_offset < src_copyable_end_offset {
            let copyable_size =
                checked_arithmetic!(src_copyable_end_offset - src_copyable_start_offset)?;

            let offset_within_src = match src_copyable_start_offset.checked_sub(src_start_offset) {
                Some(difference) => difference,
                None => 0,
            };

            if src_line_end_offset > src_end_offset {
                next_src = true;
                next_line = false;
            } else if src_line_end_offset == src_end_offset {
                next_src = true;
                next_line = true;
            } else {
                next_src = false;
                next_line = true;
            }

            let src_subslice = src
                .get_slice(offset_within_src as usize, copyable_size as usize)
                .map_err(|e| Error::MemCopy(e))?;

            let dst_line_vertical_offset = checked_arithmetic!(current_height * dst_stride)?;
            let dst_line_horizontal_offset =
                checked_arithmetic!(src_copyable_start_offset - src_line_start_offset)?;
            let dst_line_offset =
                checked_arithmetic!(dst_line_vertical_offset + dst_line_horizontal_offset)?;
            let dst_start_offset = checked_arithmetic!(dst_resource_offset + dst_line_offset)?;

            let dst_subslice = dst
                .get_slice(dst_start_offset as usize, copyable_size as usize)
                .map_err(|e| Error::MemCopy(e))?;

            src_subslice.copy_to_volatile_slice(dst_subslice);
        } else {
            if src_line_start_offset >= src_start_offset {
                next_src = true;
                next_line = false;
            } else {
                next_src = false;
                next_line = true;
            }
        };

        if next_src {
            src_start_offset = checked_arithmetic!(src_start_offset + src_size)?;
            src_opt = srcs.next();
        }

        if next_line {
            current_height += 1;
        }
    }

    Ok(())
}

impl Virtio2DResource {
    /// Attaches scatter-gather memory to this resource.
    pub fn attach_backing(
        &mut self,
        iovecs: Vec<(GuestAddress, usize)>,
        mem: &GuestMemory,
    ) -> bool {
        if iovecs
            .iter()
            .any(|&(addr, len)| mem.get_slice_at_addr(addr, len).is_err())
        {
            return false;
        }
        self.detach_backing();
        self.guest_mem = Some(mem.clone());
        for (addr, len) in iovecs {
            self.guest_iovecs.push((addr, len));
        }
        true
    }

    /// Detaches previously attached scatter-gather memory from this resource.
    pub fn detach_backing(&mut self) {
        self.guest_iovecs.clear();
        self.guest_mem = None;
    }

    fn as_mut(&mut self) -> &mut dyn VirtioResource {
        self
    }
}

impl VirtioResource for Virtio2DResource {
    fn width(&self) -> u32 {
        self.width
    }

    fn height(&self) -> u32 {
        self.height
    }

    fn import_to_display(&mut self, _display: &Rc<RefCell<GpuDisplay>>) -> Option<u32> {
        None
    }

    /// Performs a transfer to the given host side resource from its backing in guest memory.
    fn write_from_guest_memory(
        &mut self,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        src_offset: u64,
        _mem: &GuestMemory,
    ) {
        let guest_mem = match &self.guest_mem {
            Some(mem) => mem,
            None => {
                error!("failed to write to resource: no guest memory attached");
                return;
            }
        };

        if self
            .guest_iovecs
            .iter()
            .any(|&(addr, len)| guest_mem.get_slice_at_addr(addr, len).is_err())
        {
            error!("failed to write to resource: invalid iovec attached");
            return;
        }

        let mut src_slices = Vec::with_capacity(self.guest_iovecs.len());
        for &(addr, len) in &self.guest_iovecs {
            // Unwrap will not panic because we already checked the slices.
            src_slices.push(guest_mem.get_slice_at_addr(addr, len).unwrap());
        }

        let src_stride = self.host_mem_stride;
        let src_offset = src_offset;

        let dst_stride = self.host_mem_stride;
        let dst_offset = 0;

        if let Err(e) = transfer(
            self.width(),
            self.height(),
            x,
            y,
            width,
            height,
            dst_stride,
            dst_offset,
            VolatileSlice::new(self.host_mem.as_mut_slice()),
            src_stride,
            src_offset,
            src_slices.iter().cloned(),
        ) {
            error!("failed to write to resource: {}", e);
        }
    }

    /// Reads from this host side resource to a volatile slice of memory.
    fn read_to_volatile(
        &mut self,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        dst: VolatileSlice,
        dst_stride: u32,
    ) {
        let src_stride = self.host_mem_stride;
        let src_offset = 0;

        let dst_offset = 0;

        if let Err(e) = transfer(
            self.width(),
            self.height(),
            x,
            y,
            width,
            height,
            dst_stride,
            dst_offset,
            dst,
            src_stride,
            src_offset,
            [VolatileSlice::new(self.host_mem.as_mut_slice())]
                .iter()
                .cloned(),
        ) {
            error!("failed to read from resource: {}", e);
        }
    }
}

/// The virtio-gpu backend state tracker which does not support accelerated rendering.
pub struct Virtio2DBackend {
    base: VirtioBackend,
    resources: Map<u32, Virtio2DResource>,
    /// All commands processed by this 2D backend are synchronous and are completed immediately so
    /// we just need to keep track of the latest created fence and return that in fence_poll().
    latest_created_fence_id: u32,
}

impl Virtio2DBackend {
    pub fn new(display: GpuDisplay, display_width: u32, display_height: u32) -> Virtio2DBackend {
        Virtio2DBackend {
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
            resources: Default::default(),
            latest_created_fence_id: 0,
        }
    }
}

impl Backend for Virtio2DBackend {
    /// Returns the number of capsets provided by the Backend.
    fn capsets() -> u32 {
        0
    }

    /// Returns the bitset of virtio features provided by the Backend.
    fn features() -> u64 {
        1 << VIRTIO_F_VERSION_1
    }

    /// Returns the underlying Backend.
    fn build(
        display: GpuDisplay,
        display_width: u32,
        display_height: u32,
        _renderer_flags: RendererFlags,
        _event_devices: Vec<EventDevice>,
        _gpu_device_socket: VmMemoryControlRequestSocket,
        _pci_bar: Alloc,
        _map_request: Arc<Mutex<Option<ExternalMapping>>>,
        _external_blob: bool,
    ) -> Option<Box<dyn Backend>> {
        Some(Box::new(Virtio2DBackend::new(
            display,
            display_width,
            display_height,
        )))
    }

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
    fn create_fence(&mut self, _ctx_id: u32, fence_id: u32) -> GpuResponse {
        self.latest_created_fence_id = fence_id;

        GpuResponse::OkNoData
    }

    /// Returns the id of the latest fence to complete.
    fn fence_poll(&mut self) -> u32 {
        self.latest_created_fence_id
    }

    fn create_resource_2d(
        &mut self,
        id: u32,
        width: u32,
        height: u32,
        _format: u32,
    ) -> GpuResponse {
        if id == 0 {
            return GpuResponse::ErrInvalidResourceId;
        }
        match self.resources.entry(id) {
            Entry::Vacant(slot) => {
                // All virtio formats are 4 bytes per pixel.
                let resource_bpp = 4;
                let resource_stride = resource_bpp * width;
                let resource_size = (resource_stride as usize) * (height as usize);

                let gpu_resource = Virtio2DResource {
                    width,
                    height,
                    guest_iovecs: Vec::new(),
                    guest_mem: None,
                    host_mem: vec![0; resource_size],
                    host_mem_stride: resource_stride,
                    no_sync_send: PhantomData,
                };
                slot.insert(gpu_resource);
                GpuResponse::OkNoData
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
    fn set_scanout(
        &mut self,
        _scanout_id: u32,
        resource_id: u32,
        _scanout_data: Option<VirtioScanoutBlobData>,
    ) -> GpuResponse {
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
        if let Some(resource) = self.resources.get_mut(&id) {
            resource.write_from_guest_memory(x, y, width, height, src_offset, mem);
            GpuResponse::OkNoData
        } else {
            GpuResponse::ErrInvalidResourceId
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
            Some(resource) => {
                if resource.attach_backing(vecs, mem) {
                    GpuResponse::OkNoData
                } else {
                    GpuResponse::ErrUnspec
                }
            }
            None => GpuResponse::ErrInvalidResourceId,
        }
    }

    /// Detaches any backing memory from the given resource, if there is any.
    fn detach_backing(&mut self, id: u32) -> GpuResponse {
        match self.resources.get_mut(&id) {
            Some(resource) => {
                resource.detach_backing();
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
    fn get_capset_info(&self, _index: u32) -> GpuResponse {
        GpuResponse::ErrUnspec
    }

    /// Gets the capset of `version` associated with `id`.
    fn get_capset(&self, _id: u32, _version: u32) -> GpuResponse {
        GpuResponse::ErrUnspec
    }
}

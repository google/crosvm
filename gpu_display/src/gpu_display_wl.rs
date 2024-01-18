// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Crate for displaying simple surfaces and GPU buffers over wayland.

extern crate base;

#[path = "dwl.rs"]
mod dwl;

use std::cell::Cell;
use std::cmp::max;
use std::collections::HashMap;
use std::ffi::CStr;
use std::ffi::CString;
use std::mem::zeroed;
use std::panic::catch_unwind;
use std::path::Path;
use std::process::abort;
use std::ptr::null;

use anyhow::bail;
use base::error;
use base::round_up_to_page_size;
use base::AsRawDescriptor;
use base::MemoryMapping;
use base::MemoryMappingBuilder;
use base::RawDescriptor;
use base::SharedMemory;
use base::VolatileMemory;
use dwl::*;
use linux_input_sys::virtio_input_event;
use sync::Waitable;

use crate::DisplayExternalResourceImport;
use crate::DisplayT;
use crate::EventDeviceKind;
use crate::FlipToExtraInfo;
use crate::GpuDisplayError;
use crate::GpuDisplayEvents;
use crate::GpuDisplayFramebuffer;
use crate::GpuDisplayResult;
use crate::GpuDisplaySurface;
use crate::SemaphoreTimepoint;
use crate::SurfaceType;
use crate::SysDisplayT;

const BUFFER_COUNT: usize = 3;
const BYTES_PER_PIXEL: u32 = 4;

struct DwlContext(*mut dwl_context);
impl Drop for DwlContext {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY:
            // Safe given that we checked the pointer for non-null and it should always be of the
            // correct type.
            unsafe {
                dwl_context_destroy(&mut self.0);
            }
        }
    }
}

impl AsRawDescriptor for DwlContext {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        // SAFETY:
        // Safe given that the context pointer is valid.
        unsafe { dwl_context_fd(self.0) }
    }
}

struct DwlDmabuf(*mut dwl_dmabuf);

impl Drop for DwlDmabuf {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY:
            // Safe given that we checked the pointer for non-null and it should always be of the
            // correct type.
            unsafe {
                dwl_dmabuf_destroy(&mut self.0);
            }
        }
    }
}

struct DwlSurface(*mut dwl_surface);
impl Drop for DwlSurface {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY:
            // Safe given that we checked the pointer for non-null and it should always be of the
            // correct type.
            unsafe {
                dwl_surface_destroy(&mut self.0);
            }
        }
    }
}

struct WaylandSurface {
    surface: DwlSurface,
    row_size: u32,
    buffer_size: usize,
    buffer_index: Cell<usize>,
    buffer_mem: MemoryMapping,
}

impl WaylandSurface {
    fn surface(&self) -> *mut dwl_surface {
        self.surface.0
    }
}

impl GpuDisplaySurface for WaylandSurface {
    fn surface_descriptor(&self) -> u64 {
        // SAFETY:
        // Safe if the surface is valid.
        let pointer = unsafe { dwl_surface_descriptor(self.surface.0) };
        pointer as u64
    }

    fn framebuffer(&mut self) -> Option<GpuDisplayFramebuffer> {
        let buffer_index = (self.buffer_index.get() + 1) % BUFFER_COUNT;
        let framebuffer = self
            .buffer_mem
            .get_slice(buffer_index * self.buffer_size, self.buffer_size)
            .ok()?;

        Some(GpuDisplayFramebuffer::new(
            framebuffer,
            self.row_size,
            BYTES_PER_PIXEL,
        ))
    }

    fn next_buffer_in_use(&self) -> bool {
        let next_buffer_index = (self.buffer_index.get() + 1) % BUFFER_COUNT;
        // SAFETY:
        // Safe because only a valid surface and buffer index is used.
        unsafe { dwl_surface_buffer_in_use(self.surface(), next_buffer_index) }
    }

    fn close_requested(&self) -> bool {
        // SAFETY:
        // Safe because only a valid surface is used.
        unsafe { dwl_surface_close_requested(self.surface()) }
    }

    fn flip(&mut self) {
        self.buffer_index
            .set((self.buffer_index.get() + 1) % BUFFER_COUNT);

        // SAFETY:
        // Safe because only a valid surface and buffer index is used.
        unsafe {
            dwl_surface_flip(self.surface(), self.buffer_index.get());
        }
    }

    fn flip_to(
        &mut self,
        import_id: u32,
        _acquire_timepoint: Option<SemaphoreTimepoint>,
        _release_timepoint: Option<SemaphoreTimepoint>,
        _extra_info: Option<FlipToExtraInfo>,
    ) -> anyhow::Result<Waitable> {
        // SAFETY:
        // Safe because only a valid surface and import_id is used.
        unsafe { dwl_surface_flip_to(self.surface(), import_id) };
        Ok(Waitable::signaled())
    }

    fn commit(&mut self) -> GpuDisplayResult<()> {
        // SAFETY:
        // Safe because only a valid surface is used.
        unsafe {
            dwl_surface_commit(self.surface());
        }

        Ok(())
    }

    fn set_position(&mut self, x: u32, y: u32) {
        // SAFETY:
        // Safe because only a valid surface is used.
        unsafe {
            dwl_surface_set_position(self.surface(), x, y);
        }
    }
}

/// A connection to the compositor and associated collection of state.
///
/// The user of `GpuDisplay` can use `AsRawDescriptor` to poll on the compositor connection's file
/// descriptor. When the connection is readable, `dispatch_events` can be called to process it.

pub struct DisplayWl {
    dmabufs: HashMap<u32, DwlDmabuf>,
    ctx: DwlContext,
    current_event: Option<dwl_event>,
    mt_tracking_id: u16,
}

/// Error logging callback used by wrapped C implementation.
///
/// # Safety
///
/// safe because it must be passed a valid pointer to null-terminated c-string.
#[allow(clippy::unnecessary_cast)]
unsafe extern "C" fn error_callback(message: *const ::std::os::raw::c_char) {
    catch_unwind(|| {
        assert!(!message.is_null());
        // SAFETY: trivially safe
        let msg = unsafe {
            std::str::from_utf8(std::slice::from_raw_parts(
                message as *const u8,
                libc::strlen(message),
            ))
            .unwrap()
        };
        error!("{}", msg);
    })
    .unwrap_or_else(|_| abort())
}

impl DisplayWl {
    /// Opens a fresh connection to the compositor.
    pub fn new(wayland_path: Option<&Path>) -> GpuDisplayResult<DisplayWl> {
        // SAFETY:
        // The dwl_context_new call should always be safe to call, and we check its result.
        let ctx = DwlContext(unsafe { dwl_context_new(Some(error_callback)) });
        if ctx.0.is_null() {
            return Err(GpuDisplayError::Allocate);
        }

        // The dwl_context_setup call is always safe to call given that the supplied context is
        // valid. and we check its result.
        let cstr_path = match wayland_path.map(|p| p.as_os_str().to_str()) {
            Some(Some(s)) => match CString::new(s) {
                Ok(cstr) => Some(cstr),
                Err(_) => return Err(GpuDisplayError::InvalidPath),
            },
            Some(None) => return Err(GpuDisplayError::InvalidPath),
            None => None,
        };
        // This grabs a pointer to cstr_path without moving the CString into the .map closure
        // accidentally, which triggeres a really hard to catch use after free in
        // dwl_context_setup.
        let cstr_path_ptr = cstr_path
            .as_ref()
            .map(|s: &CString| CStr::as_ptr(s))
            .unwrap_or(null());
        // SAFETY: args are valid and the return value is checked.
        let setup_success = unsafe { dwl_context_setup(ctx.0, cstr_path_ptr) };
        if !setup_success {
            return Err(GpuDisplayError::Connect);
        }

        Ok(DisplayWl {
            dmabufs: HashMap::new(),
            ctx,
            current_event: None,
            mt_tracking_id: 0u16,
        })
    }

    fn ctx(&self) -> *mut dwl_context {
        self.ctx.0
    }

    fn pop_event(&self) -> dwl_event {
        // SAFETY:
        // Safe because dwl_next_events from a context's circular buffer.
        unsafe {
            let mut ev = zeroed();
            dwl_context_next_event(self.ctx(), &mut ev);
            ev
        }
    }

    fn next_tracking_id(&mut self) -> i32 {
        let cur_id: i32 = self.mt_tracking_id as i32;
        self.mt_tracking_id = self.mt_tracking_id.wrapping_add(1);
        cur_id
    }

    fn current_tracking_id(&self) -> i32 {
        self.mt_tracking_id as i32
    }
}

impl DisplayT for DisplayWl {
    fn pending_events(&self) -> bool {
        // SAFETY:
        // Safe because the function just queries the values of two variables in a context.
        unsafe { dwl_context_pending_events(self.ctx()) }
    }

    fn next_event(&mut self) -> GpuDisplayResult<u64> {
        let ev = self.pop_event();
        let descriptor = ev.surface_descriptor as u64;
        self.current_event = Some(ev);
        Ok(descriptor)
    }

    fn handle_next_event(
        &mut self,
        _surface: &mut Box<dyn GpuDisplaySurface>,
    ) -> Option<GpuDisplayEvents> {
        // Should not panic since the common layer only calls this when an event occurs.
        let event = self.current_event.take().unwrap();

        match event.event_type {
            DWL_EVENT_TYPE_KEYBOARD_ENTER => None,
            DWL_EVENT_TYPE_KEYBOARD_LEAVE => None,
            DWL_EVENT_TYPE_KEYBOARD_KEY => {
                let linux_keycode = event.params[0] as u16;
                let pressed = event.params[1] == DWL_KEYBOARD_KEY_STATE_PRESSED;
                let events = vec![virtio_input_event::key(linux_keycode, pressed, false)];
                Some(GpuDisplayEvents {
                    events,
                    device_type: EventDeviceKind::Keyboard,
                })
            }
            // TODO(tutankhamen): slot is always 0, because all the input
            // events come from mouse device, i.e. only one touch is possible at a time.
            // Full MT protocol has to be implemented and properly wired later.
            DWL_EVENT_TYPE_TOUCH_DOWN | DWL_EVENT_TYPE_TOUCH_MOTION => {
                let tracking_id = if event.event_type == DWL_EVENT_TYPE_TOUCH_DOWN {
                    self.next_tracking_id()
                } else {
                    self.current_tracking_id()
                };

                let events = vec![
                    virtio_input_event::multitouch_slot(0),
                    virtio_input_event::multitouch_tracking_id(tracking_id),
                    virtio_input_event::multitouch_absolute_x(max(0, event.params[0])),
                    virtio_input_event::multitouch_absolute_y(max(0, event.params[1])),
                ];
                Some(GpuDisplayEvents {
                    events,
                    device_type: EventDeviceKind::Touchscreen,
                })
            }
            DWL_EVENT_TYPE_TOUCH_UP => {
                let events = vec![
                    virtio_input_event::multitouch_slot(0),
                    virtio_input_event::multitouch_tracking_id(-1),
                ];
                Some(GpuDisplayEvents {
                    events,
                    device_type: EventDeviceKind::Touchscreen,
                })
            }
            _ => {
                error!("unknown event type {}", event.event_type);
                None
            }
        }
    }

    fn flush(&self) {
        // SAFETY:
        // Safe given that the context pointer is valid.
        unsafe {
            dwl_context_dispatch(self.ctx());
        }
    }

    fn create_surface(
        &mut self,
        parent_surface_id: Option<u32>,
        surface_id: u32,
        scanout_id: Option<u32>,
        width: u32,
        height: u32,
        surf_type: SurfaceType,
    ) -> GpuDisplayResult<Box<dyn GpuDisplaySurface>> {
        let parent_id = parent_surface_id.unwrap_or(0);

        let row_size = width * BYTES_PER_PIXEL;
        let fb_size = row_size * height;
        let buffer_size = round_up_to_page_size(fb_size as usize * BUFFER_COUNT);
        let buffer_shm = SharedMemory::new("GpuDisplaySurface", buffer_size as u64)?;
        let buffer_mem = MemoryMappingBuilder::new(buffer_size)
            .from_shared_memory(&buffer_shm)
            .build()
            .unwrap();

        let dwl_surf_flags = match surf_type {
            SurfaceType::Cursor => DWL_SURFACE_FLAG_HAS_ALPHA,
            SurfaceType::Scanout => DWL_SURFACE_FLAG_RECEIVE_INPUT,
        };
        // SAFETY:
        // Safe because only a valid context, parent ID (if not non-zero), and buffer FD are used.
        // The returned surface is checked for validity before being filed away.
        let surface = DwlSurface(unsafe {
            dwl_context_surface_new(
                self.ctx(),
                parent_id,
                surface_id,
                buffer_shm.as_raw_descriptor(),
                buffer_size,
                fb_size as usize,
                width,
                height,
                row_size,
                dwl_surf_flags,
            )
        });

        if surface.0.is_null() {
            return Err(GpuDisplayError::CreateSurface);
        }

        if let Some(scanout_id) = scanout_id {
            // SAFETY:
            // Safe because only a valid surface is used.
            unsafe {
                dwl_surface_set_scanout_id(surface.0, scanout_id);
            }
        }

        Ok(Box::new(WaylandSurface {
            surface,
            row_size,
            buffer_size: fb_size as usize,
            buffer_index: Cell::new(0),
            buffer_mem,
        }))
    }

    fn import_resource(
        &mut self,
        import_id: u32,
        _surface_id: u32,
        external_display_resource: DisplayExternalResourceImport,
    ) -> anyhow::Result<()> {
        // This let pattern is always true if the vulkan_display feature is disabled.
        #[allow(irrefutable_let_patterns)]
        if let DisplayExternalResourceImport::Dmabuf {
            descriptor,
            offset,
            stride,
            modifiers,
            width,
            height,
            fourcc,
        } = external_display_resource
        {
            // SAFETY:
            // Safe given that the context pointer is valid. Any other invalid parameters would be
            // rejected by dwl_context_dmabuf_new safely. We check that the resulting dmabuf is
            // valid before filing it away.
            let dmabuf = DwlDmabuf(unsafe {
                dwl_context_dmabuf_new(
                    self.ctx(),
                    import_id,
                    descriptor.as_raw_descriptor(),
                    offset,
                    stride,
                    modifiers,
                    width,
                    height,
                    fourcc,
                )
            });

            if dmabuf.0.is_null() {
                bail!("dmabuf import failed.");
            }

            self.dmabufs.insert(import_id, dmabuf);

            Ok(())
        } else {
            bail!("gpu_display_wl only supports Dmabuf imports");
        }
    }

    fn release_import(&mut self, _surface_id: u32, import_id: u32) {
        self.dmabufs.remove(&import_id);
    }
}

impl SysDisplayT for DisplayWl {}

impl AsRawDescriptor for DisplayWl {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        // Safe given that the context pointer is valid.
        self.ctx.as_raw_descriptor()
    }
}

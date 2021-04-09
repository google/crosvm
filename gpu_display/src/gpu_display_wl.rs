// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Crate for displaying simple surfaces and GPU buffers over wayland.

extern crate base;
extern crate data_model;

#[path = "dwl.rs"]
mod dwl;

use dwl::*;

use crate::{DisplayT, EventDevice, GpuDisplayError, GpuDisplayFramebuffer};

use std::cell::Cell;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::path::Path;
use std::ptr::{null, null_mut};

use base::{
    round_up_to_page_size, AsRawDescriptor, MemoryMapping, MemoryMappingBuilder, RawDescriptor,
    SharedMemory,
};
use data_model::VolatileMemory;

const BUFFER_COUNT: usize = 3;
const BYTES_PER_PIXEL: u32 = 4;

struct DwlContext(*mut dwl_context);
impl Drop for DwlContext {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // Safe given that we checked the pointer for non-null and it should always be of the
            // correct type.
            unsafe {
                dwl_context_destroy(&mut self.0);
            }
        }
    }
}

struct DwlDmabuf(*mut dwl_dmabuf);
impl Drop for DwlDmabuf {
    fn drop(&mut self) {
        if !self.0.is_null() {
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
            // Safe given that we checked the pointer for non-null and it should always be of the
            // correct type.
            unsafe {
                dwl_surface_destroy(&mut self.0);
            }
        }
    }
}

struct Surface {
    surface: DwlSurface,
    row_size: u32,
    buffer_size: usize,
    buffer_index: Cell<usize>,
    buffer_mem: MemoryMapping,
}

impl Surface {
    fn surface(&self) -> *mut dwl_surface {
        self.surface.0
    }
}

/// A connection to the compositor and associated collection of state.
///
/// The user of `GpuDisplay` can use `AsRawDescriptor` to poll on the compositor connection's file
/// descriptor. When the connection is readable, `dispatch_events` can be called to process it.
pub struct DisplayWl {
    dmabufs: HashMap<u32, DwlDmabuf>,
    dmabuf_next_id: u32,
    surfaces: HashMap<u32, Surface>,
    surface_next_id: u32,
    ctx: DwlContext,
}

impl DisplayWl {
    /// Opens a fresh connection to the compositor.
    pub fn new(wayland_path: Option<&Path>) -> Result<DisplayWl, GpuDisplayError> {
        // The dwl_context_new call should always be safe to call, and we check its result.
        let ctx = DwlContext(unsafe { dwl_context_new() });
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
        let setup_success = unsafe { dwl_context_setup(ctx.0, cstr_path_ptr) };
        if !setup_success {
            return Err(GpuDisplayError::Connect);
        }

        Ok(DisplayWl {
            dmabufs: Default::default(),
            dmabuf_next_id: 0,
            surfaces: Default::default(),
            surface_next_id: 0,
            ctx,
        })
    }

    fn ctx(&self) -> *mut dwl_context {
        self.ctx.0
    }

    fn get_surface(&self, surface_id: u32) -> Option<&Surface> {
        self.surfaces.get(&surface_id)
    }
}

impl DisplayT for DisplayWl {
    fn import_dmabuf(
        &mut self,
        fd: RawDescriptor,
        offset: u32,
        stride: u32,
        modifiers: u64,
        width: u32,
        height: u32,
        fourcc: u32,
    ) -> Result<u32, GpuDisplayError> {
        // Safe given that the context pointer is valid. Any other invalid parameters would be
        // rejected by dwl_context_dmabuf_new safely. We check that the resulting dmabuf is valid
        // before filing it away.
        let dmabuf = DwlDmabuf(unsafe {
            dwl_context_dmabuf_new(
                self.ctx(),
                fd,
                offset,
                stride,
                modifiers,
                width,
                height,
                fourcc,
            )
        });
        if dmabuf.0.is_null() {
            return Err(GpuDisplayError::FailedImport);
        }

        let next_id = self.dmabuf_next_id;
        self.dmabufs.insert(next_id, dmabuf);
        self.dmabuf_next_id += 1;
        Ok(next_id)
    }

    fn release_import(&mut self, import_id: u32) {
        self.dmabufs.remove(&import_id);
    }

    fn dispatch_events(&mut self) {
        // Safe given that the context pointer is valid.
        unsafe {
            dwl_context_dispatch(self.ctx());
        }
    }

    fn create_surface(
        &mut self,
        parent_surface_id: Option<u32>,
        width: u32,
        height: u32,
    ) -> Result<u32, GpuDisplayError> {
        let parent_ptr = match parent_surface_id {
            Some(id) => match self.get_surface(id).map(|p| p.surface()) {
                Some(ptr) => ptr,
                None => return Err(GpuDisplayError::InvalidSurfaceId),
            },
            None => null_mut(),
        };
        let row_size = width * BYTES_PER_PIXEL;
        let fb_size = row_size * height;
        let buffer_size = round_up_to_page_size(fb_size as usize * BUFFER_COUNT);
        let buffer_shm = SharedMemory::named("GpuDisplaySurface", buffer_size as u64)
            .map_err(GpuDisplayError::CreateShm)?;
        let buffer_mem = MemoryMappingBuilder::new(buffer_size)
            .from_shared_memory(&buffer_shm)
            .build()
            .unwrap();

        // Safe because only a valid context, parent pointer (if not  None), and buffer FD are used.
        // The returned surface is checked for validity before being filed away.
        let surface = DwlSurface(unsafe {
            dwl_context_surface_new(
                self.ctx(),
                parent_ptr,
                buffer_shm.as_raw_descriptor(),
                buffer_size,
                fb_size as usize,
                width,
                height,
                row_size,
            )
        });

        if surface.0.is_null() {
            return Err(GpuDisplayError::CreateSurface);
        }

        let next_id = self.surface_next_id;
        self.surfaces.insert(
            next_id,
            Surface {
                surface,
                row_size,
                buffer_size: fb_size as usize,
                buffer_index: Cell::new(0),
                buffer_mem,
            },
        );

        self.surface_next_id += 1;
        Ok(next_id)
    }

    fn release_surface(&mut self, surface_id: u32) {
        self.surfaces.remove(&surface_id);
    }

    fn framebuffer(&mut self, surface_id: u32) -> Option<GpuDisplayFramebuffer> {
        let surface = self.get_surface(surface_id)?;
        let buffer_index = (surface.buffer_index.get() + 1) % BUFFER_COUNT;
        let framebuffer = surface
            .buffer_mem
            .get_slice(buffer_index * surface.buffer_size, surface.buffer_size)
            .ok()?;
        Some(GpuDisplayFramebuffer::new(
            framebuffer,
            surface.row_size,
            BYTES_PER_PIXEL,
        ))
    }

    fn commit(&mut self, surface_id: u32) {
        match self.get_surface(surface_id) {
            Some(surface) => {
                // Safe because only a valid surface is used.
                unsafe {
                    dwl_surface_commit(surface.surface());
                }
            }
            None => debug_assert!(false, "invalid surface_id {}", surface_id),
        }
    }

    fn next_buffer_in_use(&self, surface_id: u32) -> bool {
        match self.get_surface(surface_id) {
            Some(surface) => {
                let next_buffer_index = (surface.buffer_index.get() + 1) % BUFFER_COUNT;
                // Safe because only a valid surface and buffer index is used.
                unsafe { dwl_surface_buffer_in_use(surface.surface(), next_buffer_index) }
            }
            None => {
                debug_assert!(false, "invalid surface_id {}", surface_id);
                false
            }
        }
    }

    fn flip(&mut self, surface_id: u32) {
        match self.get_surface(surface_id) {
            Some(surface) => {
                surface
                    .buffer_index
                    .set((surface.buffer_index.get() + 1) % BUFFER_COUNT);
                // Safe because only a valid surface and buffer index is used.
                unsafe {
                    dwl_surface_flip(surface.surface(), surface.buffer_index.get());
                }
            }
            None => debug_assert!(false, "invalid surface_id {}", surface_id),
        }
    }

    fn flip_to(&mut self, surface_id: u32, import_id: u32) {
        match self.get_surface(surface_id) {
            Some(surface) => {
                match self.dmabufs.get(&import_id) {
                    // Safe because only a valid surface and dmabuf is used.
                    Some(dmabuf) => unsafe { dwl_surface_flip_to(surface.surface(), dmabuf.0) },
                    None => debug_assert!(false, "invalid import_id {}", import_id),
                }
            }
            None => debug_assert!(false, "invalid surface_id {}", surface_id),
        }
    }

    fn close_requested(&self, surface_id: u32) -> bool {
        match self.get_surface(surface_id) {
            Some(surface) =>
            // Safe because only a valid surface is used.
            unsafe { dwl_surface_close_requested(surface.surface()) }
            None => false,
        }
    }

    fn set_position(&mut self, surface_id: u32, x: u32, y: u32) {
        match self.get_surface(surface_id) {
            Some(surface) => {
                // Safe because only a valid surface is used.
                unsafe {
                    dwl_surface_set_position(surface.surface(), x, y);
                }
            }
            None => debug_assert!(false, "invalid surface_id {}", surface_id),
        }
    }

    fn import_event_device(&mut self, _event_device: EventDevice) -> Result<u32, GpuDisplayError> {
        Err(GpuDisplayError::Unsupported)
    }
    fn release_event_device(&mut self, _event_device_id: u32) {
        // unsupported
    }
    fn attach_event_device(&mut self, _surface_id: u32, _event_device_id: u32) {
        // unsupported
    }
}

impl AsRawDescriptor for DisplayWl {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        // Safe given that the context pointer is valid.
        unsafe { dwl_context_fd(self.ctx.0) }
    }
}

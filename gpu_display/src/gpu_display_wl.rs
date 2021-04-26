// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Crate for displaying simple surfaces and GPU buffers over wayland.

extern crate base;
extern crate data_model;

#[path = "dwl.rs"]
mod dwl;

use dwl::*;

use crate::{
    DisplayT, GpuDisplayError, GpuDisplayFramebuffer, GpuDisplayImport, GpuDisplayResult,
    GpuDisplaySurface,
};

use std::cell::Cell;
use std::ffi::{CStr, CString};
use std::path::Path;
use std::ptr::null;

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

impl GpuDisplayImport for DwlDmabuf {}

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
        // Safe because only a valid surface and buffer index is used.
        unsafe { dwl_surface_buffer_in_use(self.surface(), next_buffer_index) }
    }

    fn close_requested(&self) -> bool {
        // Safe because only a valid surface is used.
        unsafe { dwl_surface_close_requested(self.surface()) }
    }

    fn flip(&mut self) {
        self.buffer_index
            .set((self.buffer_index.get() + 1) % BUFFER_COUNT);

        // Safe because only a valid surface and buffer index is used.
        unsafe {
            dwl_surface_flip(self.surface(), self.buffer_index.get());
        }
    }

    fn flip_to(&mut self, import_id: u32) {
        // Safe because only a valid surface and import_id is used.
        unsafe { dwl_surface_flip_to(self.surface(), import_id) }
    }

    fn commit(&mut self) -> GpuDisplayResult<()> {
        // Safe because only a valid surface is used.
        unsafe {
            dwl_surface_commit(self.surface());
        }

        Ok(())
    }

    fn set_position(&mut self, x: u32, y: u32) {
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
    ctx: DwlContext,
}

impl DisplayWl {
    /// Opens a fresh connection to the compositor.
    pub fn new(wayland_path: Option<&Path>) -> GpuDisplayResult<DisplayWl> {
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

        Ok(DisplayWl { ctx })
    }

    fn ctx(&self) -> *mut dwl_context {
        self.ctx.0
    }
}

impl DisplayT for DisplayWl {
    fn flush(&self) {
        // Safe given that the context pointer is valid.
        unsafe {
            dwl_context_dispatch(self.ctx());
        }
    }

    fn create_surface(
        &mut self,
        parent_surface_id: Option<u32>,
        surface_id: u32,
        width: u32,
        height: u32,
    ) -> GpuDisplayResult<Box<dyn GpuDisplaySurface>> {
        let parent_id = parent_surface_id.unwrap_or(0);

        let row_size = width * BYTES_PER_PIXEL;
        let fb_size = row_size * height;
        let buffer_size = round_up_to_page_size(fb_size as usize * BUFFER_COUNT);
        let buffer_shm = SharedMemory::named("GpuDisplaySurface", buffer_size as u64)?;
        let buffer_mem = MemoryMappingBuilder::new(buffer_size)
            .from_shared_memory(&buffer_shm)
            .build()
            .unwrap();

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
            )
        });

        if surface.0.is_null() {
            return Err(GpuDisplayError::CreateSurface);
        }

        Ok(Box::new(WaylandSurface {
            surface,
            row_size,
            buffer_size: fb_size as usize,
            buffer_index: Cell::new(0),
            buffer_mem,
        }))
    }

    fn import_memory(
        &mut self,
        import_id: u32,
        descriptor: &dyn AsRawDescriptor,
        offset: u32,
        stride: u32,
        modifiers: u64,
        width: u32,
        height: u32,
        fourcc: u32,
    ) -> GpuDisplayResult<Box<dyn GpuDisplayImport>> {
        // Safe given that the context pointer is valid. Any other invalid parameters would be
        // rejected by dwl_context_dmabuf_new safely. We check that the resulting dmabuf is valid
        // before filing it away.
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
            return Err(GpuDisplayError::FailedImport);
        }

        Ok(Box::new(dmabuf))
    }
}

impl AsRawDescriptor for DisplayWl {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        // Safe given that the context pointer is valid.
        unsafe { dwl_context_fd(self.ctx.0) }
    }
}

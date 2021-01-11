// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use crate::{DisplayT, EventDevice, GpuDisplayError, GpuDisplayFramebuffer};

use base::{AsRawDescriptor, Event, RawDescriptor};
use data_model::VolatileSlice;

type SurfaceId = NonZeroU32;

#[allow(dead_code)]
struct Buffer {
    width: u32,
    height: u32,
    bytes_per_pixel: u32,
    bytes: Vec<u8>,
}

impl Drop for Buffer {
    fn drop(&mut self) {}
}

impl Buffer {
    fn as_volatile_slice(&mut self) -> VolatileSlice {
        VolatileSlice::new(self.bytes.as_mut_slice())
    }

    fn stride(&self) -> usize {
        (self.bytes_per_pixel as usize) * (self.width as usize)
    }

    fn bytes_per_pixel(&self) -> usize {
        self.bytes_per_pixel as usize
    }
}

struct Surface {
    width: u32,
    height: u32,
    buffer: Option<Buffer>,
}

impl Surface {
    fn create(width: u32, height: u32) -> Result<Surface, GpuDisplayError> {
        Ok(Surface {
            width,
            height,
            buffer: None,
        })
    }

    /// Gets the buffer at buffer_index, allocating it if necessary.
    fn lazily_allocate_buffer(&mut self) -> Option<&mut Buffer> {
        if self.buffer.is_none() {
            // XRGB8888
            let bytes_per_pixel = 4;
            let bytes_total = (self.width as u64) * (self.height as u64) * (bytes_per_pixel as u64);

            self.buffer = Some(Buffer {
                width: self.width,
                height: self.height,
                bytes_per_pixel,
                bytes: vec![0; bytes_total as usize],
            });
        }

        self.buffer.as_mut()
    }

    /// Gets the next framebuffer, allocating if necessary.
    fn framebuffer(&mut self) -> Option<GpuDisplayFramebuffer> {
        let framebuffer = self.lazily_allocate_buffer()?;
        let framebuffer_stride = framebuffer.stride() as u32;
        let framebuffer_bytes_per_pixel = framebuffer.bytes_per_pixel() as u32;
        Some(GpuDisplayFramebuffer::new(
            framebuffer.as_volatile_slice(),
            framebuffer_stride,
            framebuffer_bytes_per_pixel,
        ))
    }

    fn flip(&mut self) {}
}

impl Drop for Surface {
    fn drop(&mut self) {}
}

struct SurfacesHelper {
    next_surface_id: SurfaceId,
    surfaces: BTreeMap<SurfaceId, Surface>,
}

impl SurfacesHelper {
    fn new() -> SurfacesHelper {
        SurfacesHelper {
            next_surface_id: SurfaceId::new(1).unwrap(),
            surfaces: Default::default(),
        }
    }

    fn create_surface(&mut self, width: u32, height: u32) -> Result<u32, GpuDisplayError> {
        let new_surface = Surface::create(width, height)?;
        let new_surface_id = self.next_surface_id;

        self.surfaces.insert(new_surface_id, new_surface);
        self.next_surface_id = SurfaceId::new(self.next_surface_id.get() + 1).unwrap();

        Ok(new_surface_id.get())
    }

    fn get_surface(&mut self, surface_id: u32) -> Option<&mut Surface> {
        SurfaceId::new(surface_id).and_then(move |id| self.surfaces.get_mut(&id))
    }

    fn destroy_surface(&mut self, surface_id: u32) {
        SurfaceId::new(surface_id).and_then(|id| self.surfaces.remove(&id));
    }

    fn flip_surface(&mut self, surface_id: u32) {
        if let Some(surface) = self.get_surface(surface_id) {
            surface.flip();
        }
    }
}

pub struct DisplayStub {
    /// This event is never triggered and is used solely to fulfill AsRawDescriptor.
    event: Event,
    surfaces: SurfacesHelper,
}

impl DisplayStub {
    pub fn new() -> Result<DisplayStub, GpuDisplayError> {
        let event = Event::new().map_err(|_| GpuDisplayError::CreateEvent)?;

        Ok(DisplayStub {
            event,
            surfaces: SurfacesHelper::new(),
        })
    }
}

impl DisplayT for DisplayStub {
    fn dispatch_events(&mut self) {}

    fn create_surface(
        &mut self,
        parent_surface_id: Option<u32>,
        width: u32,
        height: u32,
    ) -> Result<u32, GpuDisplayError> {
        if parent_surface_id.is_some() {
            return Err(GpuDisplayError::Unsupported);
        }
        self.surfaces.create_surface(width, height)
    }

    fn release_surface(&mut self, surface_id: u32) {
        self.surfaces.destroy_surface(surface_id);
    }

    fn framebuffer(&mut self, surface_id: u32) -> Option<GpuDisplayFramebuffer> {
        self.surfaces
            .get_surface(surface_id)
            .and_then(|s| s.framebuffer())
    }

    fn next_buffer_in_use(&self, _surface_id: u32) -> bool {
        false
    }

    fn flip(&mut self, surface_id: u32) {
        self.surfaces.flip_surface(surface_id);
    }

    fn close_requested(&self, _surface_id: u32) -> bool {
        false
    }

    fn import_dmabuf(
        &mut self,
        _fd: RawDescriptor,
        _offset: u32,
        _stride: u32,
        _modifiers: u64,
        _width: u32,
        _height: u32,
        _fourcc: u32,
    ) -> Result<u32, GpuDisplayError> {
        Err(GpuDisplayError::Unsupported)
    }

    fn release_import(&mut self, _import_id: u32) {
        // unsupported
    }

    fn commit(&mut self, _surface_id: u32) {
        // unsupported
    }

    fn flip_to(&mut self, _surface_id: u32, _import_id: u32) {
        // unsupported
    }

    fn set_position(&mut self, _surface_id: u32, _x: u32, _y: u32) {
        // unsupported
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

impl AsRawDescriptor for DisplayStub {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.event.as_raw_descriptor()
    }
}

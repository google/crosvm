// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::AsRawDescriptor;
use base::Event;
use base::RawDescriptor;
use base::VolatileSlice;

use crate::DisplayT;
use crate::GpuDisplayError;
use crate::GpuDisplayFramebuffer;
use crate::GpuDisplayResult;
use crate::GpuDisplaySurface;
use crate::SurfaceType;
use crate::SysDisplayT;

#[allow(dead_code)]
struct Buffer {
    width: u32,
    _height: u32,
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

struct StubSurface {
    width: u32,
    height: u32,
    buffer: Option<Buffer>,
}

impl StubSurface {
    /// Gets the buffer at buffer_index, allocating it if necessary.
    fn lazily_allocate_buffer(&mut self) -> Option<&mut Buffer> {
        if self.buffer.is_none() {
            // XRGB8888
            let bytes_per_pixel = 4;
            let bytes_total = (self.width as u64) * (self.height as u64) * (bytes_per_pixel as u64);

            self.buffer = Some(Buffer {
                width: self.width,
                _height: self.height,
                bytes_per_pixel,
                bytes: vec![0; bytes_total as usize],
            });
        }

        self.buffer.as_mut()
    }
}

impl GpuDisplaySurface for StubSurface {
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
}

impl Drop for StubSurface {
    fn drop(&mut self) {}
}

pub struct DisplayStub {
    /// This event is never triggered and is used solely to fulfill AsRawDescriptor.
    event: Event,
}

impl DisplayStub {
    pub fn new() -> GpuDisplayResult<DisplayStub> {
        let event = Event::new().map_err(|_| GpuDisplayError::CreateEvent)?;

        Ok(DisplayStub { event })
    }
}

impl DisplayT for DisplayStub {
    fn create_surface(
        &mut self,
        parent_surface_id: Option<u32>,
        _surface_id: u32,
        width: u32,
        height: u32,
        _surf_type: SurfaceType,
    ) -> GpuDisplayResult<Box<dyn GpuDisplaySurface>> {
        if parent_surface_id.is_some() {
            return Err(GpuDisplayError::Unsupported);
        }

        Ok(Box::new(StubSurface {
            width,
            height,
            buffer: None,
        }))
    }
}

impl SysDisplayT for DisplayStub {}

impl AsRawDescriptor for DisplayStub {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.event.as_raw_descriptor()
    }
}

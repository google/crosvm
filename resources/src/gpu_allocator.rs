// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt::Debug;
use std::fs::File;

#[cfg(feature = "wl-dmabuf")]
use libc::EINVAL;

#[cfg(feature = "wl-dmabuf")]
use gpu_buffer;
use msg_socket::MsgOnSocket;
use sys_util;

#[allow(dead_code)]
#[derive(Debug, Eq, PartialEq)]
pub enum GpuAllocatorError {
    OpenGpuBufferDevice,
    CreateGpuBufferDevice,
}

/// Struct that describes the offset and stride of a plane located in GPU memory.
#[derive(Clone, Copy, Debug, PartialEq, Default, MsgOnSocket)]
pub struct GpuMemoryPlaneDesc {
    pub stride: u32,
    pub offset: u32,
}

/// Struct that describes a GPU memory allocation that consists of up to 3 planes.
#[derive(Clone, Copy, Debug, Default, MsgOnSocket)]
pub struct GpuMemoryDesc {
    pub planes: [GpuMemoryPlaneDesc; 3],
}

/// Trait that needs to be implemented in order to service GPU memory allocation
/// requests. Implementations are expected to support some set of buffer sizes and
/// formats but every possible combination is not required.
pub trait GpuMemoryAllocator: Debug {
    /// Allocates GPU memory for a buffer of a specific size and format. The memory
    /// layout for the returned buffer must be linear. A file handle and the
    /// description of the planes for the buffer are returned on success.
    ///
    /// # Arguments
    /// * `width` - Width of buffer.
    /// * `height` - Height of buffer.
    /// * `format` - Fourcc format of buffer.
    fn allocate(
        &self,
        width: u32,
        height: u32,
        format: u32,
    ) -> sys_util::Result<(File, GpuMemoryDesc)>;
}

#[cfg(feature = "wl-dmabuf")]
pub struct GpuBufferDevice {
    device: gpu_buffer::Device,
}

#[cfg(feature = "wl-dmabuf")]
impl std::fmt::Debug for GpuBufferDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "GpuBufferDevice {{opaque}}")
    }
}

#[cfg(feature = "wl-dmabuf")]
impl GpuMemoryAllocator for GpuBufferDevice {
    fn allocate(
        &self,
        width: u32,
        height: u32,
        format: u32,
    ) -> sys_util::Result<(File, GpuMemoryDesc)> {
        let buffer = match self.device.create_buffer(
            width,
            height,
            gpu_buffer::Format::from(format),
            // Linear layout is a requirement as virtio wayland guest expects
            // this for CPU access to the buffer. Scanout and texturing are
            // optional as the consumer (wayland compositor) is expected to
            // fall-back to a less efficient meachnisms for presentation if
            // neccesary. In practice, linear buffers for commonly used formats
            // will also support scanout and texturing.
            gpu_buffer::Flags::empty().use_linear(true),
        ) {
            Ok(v) => v,
            Err(_) => return Err(sys_util::Error::new(EINVAL)),
        };
        // We only support one FD. Buffers with multiple planes are supported
        // as long as each plane is associated with the same handle.
        let fd = match buffer.export_plane_fd(0) {
            Ok(v) => v,
            Err(e) => return Err(sys_util::Error::new(e)),
        };

        let mut desc = GpuMemoryDesc::default();
        for i in 0..buffer.num_planes() {
            // Use stride and offset for plane if handle matches first plane.
            if buffer.plane_handle(i) == buffer.plane_handle(0) {
                desc.planes[i] = GpuMemoryPlaneDesc {
                    stride: buffer.plane_stride(i),
                    offset: buffer.plane_offset(i),
                }
            }
        }

        Ok((fd, desc))
    }
}

#[cfg(feature = "wl-dmabuf")]
pub fn create_gpu_memory_allocator() -> Result<Option<Box<GpuMemoryAllocator>>, GpuAllocatorError> {
    let undesired: &[&str] = &["vgem", "pvr"];
    let fd = gpu_buffer::rendernode::open_device(undesired)
        .map_err(|_| GpuAllocatorError::OpenGpuBufferDevice)?;
    let device =
        gpu_buffer::Device::new(fd).map_err(|_| GpuAllocatorError::CreateGpuBufferDevice)?;
    Ok(Some(Box::new(GpuBufferDevice { device })))
}

#[cfg(not(feature = "wl-dmabuf"))]
pub fn create_gpu_memory_allocator(
) -> Result<Option<Box<dyn GpuMemoryAllocator>>, GpuAllocatorError> {
    Ok(None)
}

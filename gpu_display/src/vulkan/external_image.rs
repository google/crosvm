// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use anyhow::Result;
use vulkano::command_buffer::sys::UnsafeCommandBufferBuilder;
use vulkano::device::Device;
use vulkano::image::sys::UnsafeImage;
use vulkano::image::sys::UnsafeImageCreateInfo;
use vulkano::image::ImageLayout;
use vulkano::image::ImageSubresourceRange;
use vulkano::memory::DeviceMemory;
use vulkano::memory::MemoryAllocateInfo;
use vulkano::memory::MemoryImportInfo;
use vulkano::sync::AccessFlags;
use vulkano::sync::PipelineStages;
use vulkano::DeviceSize;

pub struct AcquireImageMemoryBarrier {
    pub source_stages: PipelineStages,
    pub destination_stages: PipelineStages,
    pub destination_access: AccessFlags,
    pub destination_queue_family_index: u32,
    pub subresource_range: ImageSubresourceRange,
}

pub struct ReleaseImageMemoryBarrier {
    pub source_stages: PipelineStages,
    pub source_access: AccessFlags,
    pub destination_stages: PipelineStages,
    pub new_layout: ImageLayout,
    pub source_queue_family_index: u32,
}

/// ExternalImage represents a vulkan image that is imported from an external context.
pub struct ExternalImage {
    image: Arc<UnsafeImage>,
    memory: DeviceMemory,
}

impl ExternalImage {
    /// Import an external image into this Device. This function will take the ownership of the
    /// handle in `memory_import_info` on all platforms.
    pub fn import(
        _device: &Arc<Device>,
        _image_create_info: UnsafeImageCreateInfo,
        _memory_allocate_info: MemoryAllocateInfo<'_>,
        _memory_import_info: MemoryImportInfo,
        _dedicated_allocation: bool,
        _bind_offset: DeviceSize,
    ) -> Result<Self> {
        unimplemented!()
    }

    /// Transition this image from the external source to be useable. This means performing the
    /// layout transition that it was exported with and applying the appropriate queue family
    /// transfers.
    pub fn acquire(
        self,
        _command_buffer_builder: &mut UnsafeCommandBufferBuilder,
        _image_memory_barrier: AcquireImageMemoryBarrier,
        _last_layout_transition: (ImageLayout, ImageLayout),
    ) -> ExternalImageAccess {
        unimplemented!()
    }
}

#[derive(Debug)]
/// ExternalImageAccess represents a vulkan image that is imported from an external context and
/// transitioned for use by another context.
pub struct ExternalImageAccess {
    image: Arc<UnsafeImage>,
    memory: DeviceMemory,
    layout: ImageLayout,
    subresource_range: ImageSubresourceRange,
}

impl ExternalImageAccess {
    /// Transition this image back to an ExternalImage, after which it can be used by other
    /// contexts. This undoes the queue family and layout transitions done by acquire.
    pub fn release(
        self,
        _command_buffer_builder: &mut UnsafeCommandBufferBuilder,
        _image_memory_barrier: ReleaseImageMemoryBarrier,
    ) -> ExternalImage {
        unimplemented!()
    }
}

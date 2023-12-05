// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use ash::vk;
#[cfg(windows)]
use base::FromRawDescriptor;
use base::SafeDescriptor;
use smallvec::SmallVec;
use vulkano::command_buffer::sys::UnsafeCommandBufferBuilder;
use vulkano::device::Device;
use vulkano::device::DeviceOwned;
use vulkano::image::sys::UnsafeImage;
use vulkano::image::sys::UnsafeImageCreateInfo;
use vulkano::image::ImageAccess;
use vulkano::image::ImageDescriptorLayouts;
use vulkano::image::ImageInner;
use vulkano::image::ImageLayout;
use vulkano::image::ImageSubresourceRange;
use vulkano::memory::DedicatedAllocation;
use vulkano::memory::DeviceMemory;
use vulkano::memory::ExternalMemoryHandleType;
use vulkano::memory::ExternalMemoryHandleTypes;
use vulkano::memory::MemoryAllocateInfo;
use vulkano::memory::MemoryImportInfo;
use vulkano::sync::AccessFlags;
use vulkano::sync::DependencyInfo;
use vulkano::sync::ImageMemoryBarrier;
use vulkano::sync::PipelineStages;
use vulkano::sync::QueueFamilyTransfer;
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
        device: &Arc<Device>,
        image_create_info: UnsafeImageCreateInfo,
        memory_allocate_info: MemoryAllocateInfo<'_>,
        memory_import_info: MemoryImportInfo,
        dedicated_allocation: bool,
        bind_offset: DeviceSize,
    ) -> Result<Self> {
        // See https://registry.khronos.org/vulkan/specs/1.3-extensions/man/html/VkImportMemoryWin32HandleInfoKHR.html#_description.
        let _descriptor_to_close: Option<SafeDescriptor> = match memory_import_info {
            #[cfg(windows)]
            MemoryImportInfo::Win32 {
                handle_type: ExternalMemoryHandleType::OpaqueWin32,
                handle,
                // SAFETY: Safe because we are consuming `memory_import_info` and do not use handle
                // again.
            } => Some(unsafe { SafeDescriptor::from_raw_descriptor(handle) }),
            #[cfg(unix)]
            MemoryImportInfo::Fd {
                handle_type: ExternalMemoryHandleType::OpaqueFd,
                ..
            } => None,
            _ => unimplemented!(),
        };
        let image = UnsafeImage::new(Arc::clone(device), image_create_info)
            .with_context(|| "create image for external memory")?;
        let dedicated_allocation = if dedicated_allocation {
            Some(DedicatedAllocation::Image(image.as_ref()))
        } else {
            None
        };
        let memory_allocate_info = MemoryAllocateInfo {
            dedicated_allocation,
            export_handle_types: ExternalMemoryHandleTypes::empty(),
            ..memory_allocate_info
        };
        // SAFETY: Safe because `memory_import_info` and `memory_allocate_info` outlive the call
        // to import and they contain no pointers. The handle in memory_import_info is consumed by
        // this function and closed when this function completes.
        let memory = unsafe {
            DeviceMemory::import(Arc::clone(device), memory_allocate_info, memory_import_info)
        }
        .context("import external Vulkan device memory")?;

        // SAFETY: Safe irrespective of vulkan spec conformance.
        unsafe { image.bind_memory(&memory, bind_offset) }
            .context("bind the image to the external memory")?;
        Ok(Self { image, memory })
    }

    /// Transition this image from the external source to be useable. This means performing the
    /// layout transition that it was exported with and applying the appropriate queue family
    /// transfers.
    ///
    /// # Safety
    ///
    /// - The ExternalImageAccess returned by this function needs to outlive
    ///   `command_buffer_builder`.
    #[deny(unsafe_op_in_unsafe_fn)]
    pub unsafe fn acquire(
        self,
        command_buffer_builder: &mut UnsafeCommandBufferBuilder,
        image_memory_barrier: AcquireImageMemoryBarrier,
        last_layout_transition: (ImageLayout, ImageLayout),
    ) -> ExternalImageAccess {
        let dep_info = DependencyInfo {
            image_memory_barriers: SmallVec::from_vec(vec![ImageMemoryBarrier {
                source_stages: image_memory_barrier.source_stages,
                // The acquire queue transfer will ignore the `srcAccessMask`.
                source_access: AccessFlags::empty(),
                destination_stages: image_memory_barrier.destination_stages,
                destination_access: image_memory_barrier.destination_access,
                old_layout: last_layout_transition.0,
                new_layout: last_layout_transition.1,
                queue_family_transfer: Some(QueueFamilyTransfer {
                    source_index: vk::QUEUE_FAMILY_EXTERNAL,
                    destination_index: image_memory_barrier.destination_queue_family_index,
                }),
                subresource_range: image_memory_barrier.subresource_range.clone(),
                ..ImageMemoryBarrier::image(Arc::clone(&self.image))
            }]),
            ..Default::default()
        };

        // SAFETY: Safe irrespective of vulkan spec conformance: `pipeline_barriers` copies all of
        // the contents of `dep_info` into new structs, so dep_info itself does not need to outlive
        // this function call. Safety comments for this function require caller to ensure this
        // object outlives the command_buffer.
        unsafe { command_buffer_builder.pipeline_barrier(&dep_info) };

        ExternalImageAccess {
            image: self.image,
            memory: self.memory,
            layout: last_layout_transition.1,
            subresource_range: image_memory_barrier.subresource_range,
        }
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
    /// # Safety
    ///
    /// - The ExternalImage returned by this function needs to outlive `command_buffer_builder`.
    pub unsafe fn release(
        self,
        command_buffer_builder: &mut UnsafeCommandBufferBuilder,
        image_memory_barrier: ReleaseImageMemoryBarrier,
    ) -> ExternalImage {
        let old_layout = self.layout;
        let new_layout = image_memory_barrier.new_layout;
        let dep_info = DependencyInfo {
            image_memory_barriers: SmallVec::from_vec(vec![ImageMemoryBarrier {
                source_stages: image_memory_barrier.source_stages,
                source_access: image_memory_barrier.source_access,
                destination_stages: image_memory_barrier.destination_stages,
                // The release queue transfer will ignore the `dstAccessMask`.
                destination_access: AccessFlags::empty(),
                old_layout,
                new_layout,
                queue_family_transfer: Some(QueueFamilyTransfer {
                    source_index: image_memory_barrier.source_queue_family_index,
                    destination_index: vk::QUEUE_FAMILY_EXTERNAL,
                }),
                subresource_range: self.subresource_range,
                ..ImageMemoryBarrier::image(Arc::clone(&self.image))
            }]),
            ..Default::default()
        };
        // SAFETY: Safe irrespective of vulkan spec conformance: `pipeline_barriers` copies all of
        // the contents of `dep_info` into new structs, so dep_info itself does not need to
        // outlive this function call. Safety comments for this function require caller to
        // ensure this object outlives the command_buffer.
        unsafe { command_buffer_builder.pipeline_barrier(&dep_info) };
        ExternalImage {
            image: self.image,
            memory: self.memory,
        }
    }
}

// SAFETY: Safe irrespective of vulkan spec conformance.
unsafe impl DeviceOwned for ExternalImageAccess {
    fn device(&self) -> &Arc<Device> {
        self.image.device()
    }
}

// SAFETY: Safe irrespective of vulkan spec conformance.
unsafe impl ImageAccess for ExternalImageAccess {
    fn inner(&self) -> ImageInner<'_> {
        ImageInner {
            image: &self.image,
            first_layer: self.subresource_range.array_layers.start,
            num_layers: self
                .subresource_range
                .array_layers
                .len()
                .try_into()
                .expect("number of layers too large"),
            first_mipmap_level: self.subresource_range.mip_levels.start,
            num_mipmap_levels: self
                .subresource_range
                .mip_levels
                .len()
                .try_into()
                .expect("number of mip levels too large"),
        }
    }

    fn initial_layout_requirement(&self) -> ImageLayout {
        self.layout
    }

    fn final_layout_requirement(&self) -> ImageLayout {
        self.layout
    }

    fn descriptor_layouts(&self) -> Option<ImageDescriptorLayouts> {
        todo!()
    }

    // The image layout should have been transitioned to the `self.layout` at the creation time of
    // this struct.
    #[deny(unsafe_op_in_unsafe_fn)]
    unsafe fn layout_initialized(&self) {
        unreachable!()
    }

    fn is_layout_initialized(&self) -> bool {
        true
    }
}

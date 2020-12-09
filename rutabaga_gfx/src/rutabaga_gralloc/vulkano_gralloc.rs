// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! vulkano_gralloc: Implements swapchain allocation and memory mapping
//! using Vulkano.
//!
//! External code found at https://github.com/vulkano-rs/vulkano.

#![cfg(feature = "vulkano")]

use std::iter::Empty;
use std::sync::Arc;

use crate::rutabaga_gralloc::gralloc::{Gralloc, ImageAllocationInfo, ImageMemoryRequirements};
use crate::rutabaga_utils::*;

use vulkano::device::{Device, DeviceCreationError, DeviceExtensions};
use vulkano::image::{sys, ImageCreationError, ImageDimensions, ImageUsage};

use vulkano::instance::{
    Instance, InstanceCreationError, InstanceExtensions, MemoryType, PhysicalDevice,
};

use vulkano::memory::{
    DedicatedAlloc, DeviceMemoryAllocError, DeviceMemoryBuilder, ExternalMemoryHandleType,
    MemoryRequirements,
};

use vulkano::memory::pool::AllocFromRequirementsFilter;
use vulkano::sync::Sharing;

/// A gralloc implementation capable of allocation `VkDeviceMemory`.
pub struct VulkanoGralloc {
    device: Arc<Device>,
}

impl VulkanoGralloc {
    /// Returns a new `VulkanGralloc' instance upon success.
    pub fn init() -> RutabagaResult<Box<dyn Gralloc>> {
        // Initialization copied from triangle.rs in Vulkano.  Look there for a more detailed
        // explanation of VK initialization.
        let instance = Instance::new(None, &InstanceExtensions::none(), None)?;

        // We should really check for integrated GPU versus dGPU.
        let physical = PhysicalDevice::enumerate(&instance)
            .next()
            .ok_or(RutabagaError::Unsupported)?;

        let queue_family = physical
            .queue_families()
            .find(|&q| {
                // We take the first queue family that supports graphics.
                q.supports_graphics()
            })
            .ok_or(RutabagaError::Unsupported)?;

        let supported_extensions = DeviceExtensions::supported_by_device(physical);
        let desired_extensions = DeviceExtensions {
            khr_dedicated_allocation: true,
            khr_get_memory_requirements2: true,
            khr_external_memory: true,
            khr_external_memory_fd: true,
            ext_external_memory_dmabuf: true,
            ..DeviceExtensions::none()
        };

        let intersection = supported_extensions.intersection(&desired_extensions);

        let (device, mut _queues) = Device::new(
            physical,
            physical.supported_features(),
            &intersection,
            [(queue_family, 0.5)].iter().cloned(),
        )?;

        Ok(Box::new(VulkanoGralloc { device }))
    }

    // This function is used safely in this module because gralloc does not:
    //
    //  (1) bind images to any memory.
    //  (2) transition the layout of images.
    //  (3) transfer ownership of images between queues.
    //
    // In addition, we trust Vulkano to validate image parameters are within the Vulkan spec.
    unsafe fn create_image(
        &mut self,
        info: ImageAllocationInfo,
    ) -> RutabagaResult<(sys::UnsafeImage, MemoryRequirements)> {
        let usage = match info.flags.uses_rendering() {
            true => ImageUsage {
                color_attachment: true,
                ..ImageUsage::none()
            },
            false => ImageUsage {
                sampled: true,
                ..ImageUsage::none()
            },
        };

        // Reasonable bounds on image width.
        if info.width == 0 || info.width > 4096 {
            return Err(RutabagaError::SpecViolation);
        }

        // Reasonable bounds on image height.
        if info.height == 0 || info.height > 4096 {
            return Err(RutabagaError::SpecViolation);
        }

        let vulkan_format = info.drm_format.vulkan_format()?;
        let (unsafe_image, memory_requirements) = sys::UnsafeImage::new(
            self.device.clone(),
            usage,
            vulkan_format,
            ImageDimensions::Dim2d {
                width: info.width,
                height: info.height,
                array_layers: 1,
                cubemap_compatible: false,
            },
            1, /* number of samples */
            1, /* mipmap count */
            Sharing::Exclusive::<Empty<_>>,
            true,  /* linear images only currently */
            false, /* not preinitialized */
        )?;

        Ok((unsafe_image, memory_requirements))
    }
}

impl Gralloc for VulkanoGralloc {
    fn supports_external_gpu_memory(&self) -> bool {
        self.device.loaded_extensions().khr_external_memory
    }

    fn supports_dmabuf(&self) -> bool {
        self.device.loaded_extensions().ext_external_memory_dmabuf
    }

    fn get_image_memory_requirements(
        &mut self,
        info: ImageAllocationInfo,
    ) -> RutabagaResult<ImageMemoryRequirements> {
        let mut reqs: ImageMemoryRequirements = Default::default();

        let (unsafe_image, memory_requirements) = unsafe { self.create_image(info)? };

        let planar_layout = info.drm_format.planar_layout()?;

        // Safe because we created the image with the linear bit set and verified the format is
        // not a depth or stencil format.  We are also using the correct image aspect.  Vulkano
        // will panic if we are not.
        for plane in 0..planar_layout.num_planes {
            let aspect = info.drm_format.vulkan_image_aspect(plane)?;
            let layout = unsafe { unsafe_image.multiplane_color_layout(aspect) };
            reqs.strides[plane] = layout.row_pitch as u32;
            reqs.offsets[plane] = layout.offset as u32;
        }

        let need_visible = info.flags.host_visible();
        let want_cached = info.flags.host_cached();

        let memory_type = {
            let filter = |current_type: MemoryType| {
                if need_visible && !current_type.is_host_visible() {
                    return AllocFromRequirementsFilter::Forbidden;
                }

                if !need_visible && current_type.is_device_local() {
                    return AllocFromRequirementsFilter::Preferred;
                }

                if need_visible && want_cached && current_type.is_host_cached() {
                    return AllocFromRequirementsFilter::Preferred;
                }

                if need_visible
                    && !want_cached
                    && current_type.is_host_coherent()
                    && !current_type.is_host_cached()
                {
                    return AllocFromRequirementsFilter::Preferred;
                }

                AllocFromRequirementsFilter::Allowed
            };

            let first_loop = self
                .device
                .physical_device()
                .memory_types()
                .map(|t| (t, AllocFromRequirementsFilter::Preferred));
            let second_loop = self
                .device
                .physical_device()
                .memory_types()
                .map(|t| (t, AllocFromRequirementsFilter::Allowed));
            first_loop
                .chain(second_loop)
                .filter(|&(t, _)| (memory_requirements.memory_type_bits & (1 << t.id())) != 0)
                .find(|&(t, rq)| filter(t) == rq)
                .ok_or(RutabagaError::Unsupported)?
                .0
        };

        reqs.info = info;
        reqs.size = memory_requirements.size as u64;

        if memory_type.is_host_visible() {
            if memory_type.is_host_cached() {
                reqs.map_info = RUTABAGA_MAP_CACHE_CACHED;
            } else if memory_type.is_host_coherent() {
                reqs.map_info = RUTABAGA_MAP_CACHE_WC;
            }
        }

        reqs.vulkan_info = Some(VulkanInfo {
            memory_idx: memory_type.id() as u32,
            physical_device_idx: self.device.physical_device().index() as u32,
        });

        Ok(reqs)
    }

    fn allocate_memory(&mut self, reqs: ImageMemoryRequirements) -> RutabagaResult<RutabagaHandle> {
        let (unsafe_image, memory_requirements) = unsafe { self.create_image(reqs.info)? };
        let vulkan_info = reqs.vulkan_info.ok_or(RutabagaError::SpecViolation)?;
        let memory_type = self
            .device
            .physical_device()
            .memory_type_by_id(vulkan_info.memory_idx)
            .ok_or(RutabagaError::SpecViolation)?;

        let (handle_type, rutabaga_type) =
            match self.device.loaded_extensions().ext_external_memory_dmabuf {
                true => (
                    ExternalMemoryHandleType {
                        dma_buf: true,
                        ..ExternalMemoryHandleType::none()
                    },
                    RUTABAGA_MEM_HANDLE_TYPE_DMABUF,
                ),
                false => (
                    ExternalMemoryHandleType {
                        opaque_fd: true,
                        ..ExternalMemoryHandleType::none()
                    },
                    RUTABAGA_MEM_HANDLE_TYPE_OPAQUE_FD,
                ),
            };

        let dedicated = match self.device.loaded_extensions().khr_dedicated_allocation {
            true => {
                if memory_requirements.prefer_dedicated {
                    DedicatedAlloc::Image(&unsafe_image)
                } else {
                    DedicatedAlloc::None
                }
            }
            false => DedicatedAlloc::None,
        };

        let device_memory =
            DeviceMemoryBuilder::new(self.device.clone(), memory_type, reqs.size as usize)
                .dedicated_info(dedicated)
                .export_info(handle_type)
                .build()?;

        let file = device_memory.export_fd(handle_type)?;

        Ok(RutabagaHandle {
            os_handle: file,
            handle_type: rutabaga_type,
        })
    }
}

// Vulkano should really define an universal type that wraps all these errors, say
// "VulkanoError(e)".
impl From<InstanceCreationError> for RutabagaError {
    fn from(e: InstanceCreationError) -> RutabagaError {
        RutabagaError::VkInstanceCreationError(e)
    }
}

impl From<ImageCreationError> for RutabagaError {
    fn from(e: ImageCreationError) -> RutabagaError {
        RutabagaError::VkImageCreationError(e)
    }
}

impl From<DeviceCreationError> for RutabagaError {
    fn from(e: DeviceCreationError) -> RutabagaError {
        RutabagaError::VkDeviceCreationError(e)
    }
}

impl From<DeviceMemoryAllocError> for RutabagaError {
    fn from(e: DeviceMemoryAllocError) -> RutabagaError {
        RutabagaError::VkDeviceMemoryAllocError(e)
    }
}

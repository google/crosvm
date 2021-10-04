// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! vulkano_gralloc: Implements swapchain allocation and memory mapping
//! using Vulkano.
//!
//! External code found at https://github.com/vulkano-rs/vulkano.

#![cfg(feature = "vulkano")]

use std::collections::BTreeMap as Map;
use std::convert::TryInto;
use std::iter::Empty;
use std::sync::Arc;

use base::MappedRegion;

use crate::rutabaga_gralloc::gralloc::{Gralloc, ImageAllocationInfo, ImageMemoryRequirements};
use crate::rutabaga_utils::*;

use vulkano::device::physical::{MemoryType, PhysicalDevice, PhysicalDeviceType};
use vulkano::device::{Device, DeviceCreationError, DeviceExtensions};
use vulkano::image::{
    sys, ImageCreateFlags, ImageCreationError, ImageDimensions, ImageUsage, SampleCount,
};

use vulkano::instance::{Instance, InstanceCreationError, InstanceExtensions, Version};

use vulkano::memory::{
    DedicatedAlloc, DeviceMemoryAllocError, DeviceMemoryBuilder, DeviceMemoryMapping,
    ExternalMemoryHandleType, MemoryRequirements,
};

use vulkano::memory::pool::AllocFromRequirementsFilter;
use vulkano::sync::Sharing;

/// A gralloc implementation capable of allocation `VkDeviceMemory`.
pub struct VulkanoGralloc {
    devices: Map<PhysicalDeviceType, Arc<Device>>,
    has_integrated_gpu: bool,
}

struct VulkanoMapping {
    mapping: DeviceMemoryMapping,
    size: usize,
}

impl VulkanoMapping {
    pub fn new(mapping: DeviceMemoryMapping, size: usize) -> VulkanoMapping {
        VulkanoMapping { mapping, size }
    }
}

unsafe impl MappedRegion for VulkanoMapping {
    /// Used for passing this region for hypervisor memory mappings.  We trust crosvm to use this
    /// safely.
    fn as_ptr(&self) -> *mut u8 {
        unsafe { self.mapping.as_ptr() }
    }

    /// Returns the size of the memory region in bytes.
    fn size(&self) -> usize {
        self.size
    }
}

impl VulkanoGralloc {
    /// Returns a new `VulkanGralloc' instance upon success.
    pub fn init() -> RutabagaResult<Box<dyn Gralloc>> {
        // Initialization copied from triangle.rs in Vulkano.  Look there for a more detailed
        // explanation of VK initialization.
        let instance_extensions = InstanceExtensions {
            khr_external_memory_capabilities: true,
            khr_get_physical_device_properties2: true,
            ..InstanceExtensions::none()
        };
        let instance = Instance::new(None, Version::V1_1, &instance_extensions, None)?;

        let mut devices: Map<PhysicalDeviceType, Arc<Device>> = Default::default();
        let mut has_integrated_gpu = false;

        for physical in PhysicalDevice::enumerate(&instance) {
            let queue_family = physical
                .queue_families()
                .find(|&q| {
                    // We take the first queue family that supports graphics.
                    q.supports_graphics()
                })
                .ok_or(RutabagaError::SpecViolation(
                    "need graphics queue family to proceed",
                ))?;

            let supported_extensions = physical.supported_extensions();

            let desired_extensions = DeviceExtensions {
                khr_dedicated_allocation: true,
                khr_get_memory_requirements2: true,
                khr_external_memory: true,
                khr_external_memory_fd: true,
                ext_external_memory_dma_buf: true,
                ..DeviceExtensions::none()
            };

            let intersection = supported_extensions.intersection(&desired_extensions);

            if let Ok(device, mut _queues) = Device::new(
                physical,
                physical.supported_features(),
                &intersection,
                [(queue_family, 0.5)].iter().cloned(),
            ) {
                let device_type = device.physical_device().properties().device_type;
                if device_type == PhysicalDeviceType::IntegratedGpu {
                    has_integrated_gpu = true
                }

                // If we have two devices of the same type (two integrated GPUs), the old value is
                // dropped.  Vulkano is verbose enough such that a keener selection algorithm may
                // be used, but the need for such complexity does not seem to exist now.
                devices.insert(device_type, device);
            };
        }

        if devices.is_empty() {
            return Err(RutabagaError::SpecViolation(
                "no matching VK devices available",
            ));
        }

        Ok(Box::new(VulkanoGralloc {
            devices,
            has_integrated_gpu,
        }))
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
        let device = if self.has_integrated_gpu {
            self.devices
                .get(&PhysicalDeviceType::IntegratedGpu)
                .ok_or(RutabagaError::InvalidGrallocGpuType)?
        } else {
            self.devices
                .get(&PhysicalDeviceType::DiscreteGpu)
                .ok_or(RutabagaError::InvalidGrallocGpuType)?
        };

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
            return Err(RutabagaError::InvalidGrallocDimensions);
        }

        // Reasonable bounds on image height.
        if info.height == 0 || info.height > 4096 {
            return Err(RutabagaError::InvalidGrallocDimensions);
        }

        let vulkan_format = info.drm_format.vulkan_format()?;
        let (unsafe_image, memory_requirements) = sys::UnsafeImage::new(
            device.clone(),
            usage,
            vulkan_format,
            ImageCreateFlags::none(),
            ImageDimensions::Dim2d {
                width: info.width,
                height: info.height,
                array_layers: 1,
            },
            SampleCount::Sample1,
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
        for device in self.devices.values() {
            if !device.enabled_extensions().khr_external_memory {
                return false;
            }
        }

        true
    }

    fn supports_dmabuf(&self) -> bool {
        for device in self.devices.values() {
            if !device.enabled_extensions().ext_external_memory_dma_buf {
                return false;
            }
        }

        true
    }

    fn get_image_memory_requirements(
        &mut self,
        info: ImageAllocationInfo,
    ) -> RutabagaResult<ImageMemoryRequirements> {
        let mut reqs: ImageMemoryRequirements = Default::default();

        let (unsafe_image, memory_requirements) = unsafe { self.create_image(info)? };

        let device = if self.has_integrated_gpu {
            self.devices
                .get(&PhysicalDeviceType::IntegratedGpu)
                .ok_or(RutabagaError::InvalidGrallocGpuType)?
        } else {
            self.devices
                .get(&PhysicalDeviceType::DiscreteGpu)
                .ok_or(RutabagaError::InvalidGrallocGpuType)?
        };

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

            let first_loop = device
                .physical_device()
                .memory_types()
                .map(|t| (t, AllocFromRequirementsFilter::Preferred));
            let second_loop = device
                .physical_device()
                .memory_types()
                .map(|t| (t, AllocFromRequirementsFilter::Allowed));
            first_loop
                .chain(second_loop)
                .filter(|&(t, _)| (memory_requirements.memory_type_bits & (1 << t.id())) != 0)
                .find(|&(t, rq)| filter(t) == rq)
                .ok_or(RutabagaError::SpecViolation(
                    "unable to find required memory type",
                ))?
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
            physical_device_idx: device.physical_device().index() as u32,
        });

        Ok(reqs)
    }

    fn allocate_memory(&mut self, reqs: ImageMemoryRequirements) -> RutabagaResult<RutabagaHandle> {
        let (unsafe_image, memory_requirements) = unsafe { self.create_image(reqs.info)? };

        let vulkan_info = reqs.vulkan_info.ok_or(RutabagaError::InvalidVulkanInfo)?;

        let device = if self.has_integrated_gpu {
            self.devices
                .get(&PhysicalDeviceType::IntegratedGpu)
                .ok_or(RutabagaError::InvalidGrallocGpuType)?
        } else {
            self.devices
                .get(&PhysicalDeviceType::DiscreteGpu)
                .ok_or(RutabagaError::InvalidGrallocGpuType)?
        };

        let memory_type = device
            .physical_device()
            .memory_type_by_id(vulkan_info.memory_idx)
            .ok_or(RutabagaError::InvalidVulkanInfo)?;

        let (handle_type, rutabaga_type) =
            match device.enabled_extensions().ext_external_memory_dma_buf {
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

        let dedicated = match device.enabled_extensions().khr_dedicated_allocation {
            true => {
                if memory_requirements.prefer_dedicated {
                    DedicatedAlloc::Image(&unsafe_image)
                } else {
                    DedicatedAlloc::None
                }
            }
            false => DedicatedAlloc::None,
        };

        let device_memory = DeviceMemoryBuilder::new(device.clone(), memory_type.id(), reqs.size)
            .dedicated_info(dedicated)
            .export_info(handle_type)
            .build()?;

        let descriptor = device_memory.export_fd(handle_type)?.into();

        Ok(RutabagaHandle {
            os_handle: descriptor,
            handle_type: rutabaga_type,
        })
    }

    /// Implementations must map the memory associated with the `resource_id` upon success.
    fn import_and_map(
        &mut self,
        handle: RutabagaHandle,
        vulkan_info: VulkanInfo,
        size: u64,
    ) -> RutabagaResult<Box<dyn MappedRegion>> {
        let device = self
            .devices
            .values()
            .find(|device| {
                device.physical_device().index() as u32 == vulkan_info.physical_device_idx
            })
            .ok_or(RutabagaError::InvalidVulkanInfo)?;

        let handle_type = match handle.handle_type {
            RUTABAGA_MEM_HANDLE_TYPE_DMABUF => ExternalMemoryHandleType {
                dma_buf: true,
                ..ExternalMemoryHandleType::none()
            },
            RUTABAGA_MEM_HANDLE_TYPE_OPAQUE_FD => ExternalMemoryHandleType {
                opaque_fd: true,
                ..ExternalMemoryHandleType::none()
            },
            _ => return Err(RutabagaError::InvalidRutabagaHandle),
        };

        let device_memory = DeviceMemoryBuilder::new(device.clone(), vulkan_info.memory_idx, size)
            .import_info(handle.os_handle.into(), handle_type)
            .build()?;
        let mapping = DeviceMemoryMapping::new(device.clone(), device_memory.clone(), 0, size, 0)?;

        Ok(Box::new(VulkanoMapping::new(mapping, size.try_into()?)))
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

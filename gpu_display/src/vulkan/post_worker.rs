// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::any::Any;
use std::borrow::Borrow;
use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use anyhow::ensure;
use anyhow::format_err;
use anyhow::Context;
use anyhow::Result;
use ash::vk::UUID_SIZE;
use ash::vk::{self};
use base::error;
use base::info;
use euclid::size2;
use euclid::Size2D;
use rand::rngs::ThreadRng;
use rand::seq::IteratorRandom;
use smallvec::SmallVec;
use vulkano::command_buffer::pool::standard::StandardCommandPoolAlloc;
use vulkano::command_buffer::pool::CommandPool;
use vulkano::command_buffer::pool::CommandPoolAlloc;
use vulkano::command_buffer::pool::CommandPoolBuilderAlloc;
use vulkano::command_buffer::pool::StandardCommandPool;
use vulkano::command_buffer::submit::SubmitPresentBuilder;
use vulkano::command_buffer::submit::SubmitPresentError;
use vulkano::command_buffer::sys::CommandBufferBeginInfo;
use vulkano::command_buffer::sys::UnsafeCommandBufferBuilder;
use vulkano::command_buffer::BlitImageInfo;
use vulkano::command_buffer::CommandBufferLevel;
use vulkano::command_buffer::CommandBufferUsage;
use vulkano::device::physical::PhysicalDevice;
use vulkano::device::Device;
use vulkano::device::DeviceCreateInfo;
use vulkano::device::DeviceExtensions;
use vulkano::device::Features;
use vulkano::device::Queue;
use vulkano::device::QueueCreateInfo;
use vulkano::format::Format;
use vulkano::image::ImageAccess;
use vulkano::image::ImageAspects;
use vulkano::image::ImageLayout;
use vulkano::image::ImageSubresourceRange;
use vulkano::image::ImageUsage;
use vulkano::image::{self};
use vulkano::instance::Instance;
use vulkano::instance::InstanceCreateInfo;
use vulkano::instance::InstanceExtensions;
use vulkano::swapchain::acquire_next_image_raw;
use vulkano::swapchain::AcquireError;
use vulkano::swapchain::AcquiredImage;
use vulkano::swapchain::CompositeAlpha;
use vulkano::swapchain::PresentInfo;
use vulkano::swapchain::PresentMode;
use vulkano::swapchain::SwapchainCreateInfo;
use vulkano::swapchain::{self};
use vulkano::sync::AccessFlags;
use vulkano::sync::DependencyInfo;
use vulkano::sync::ExternalFenceHandleTypes;
use vulkano::sync::Fence;
use vulkano::sync::FenceCreateInfo;
use vulkano::sync::ImageMemoryBarrier;
use vulkano::sync::PipelineStages;
use vulkano::sync::QueueFamilyTransfer;
use vulkano::sync::Semaphore;
use vulkano::sync::SemaphoreCreateInfo;
use vulkano::sync::Sharing;
use vulkano::SynchronizedVulkanObject;
use vulkano::Version;
use vulkano::VulkanLibrary;
use vulkano::VulkanObject;

use super::sys::Window;
use super::ExternalImage;
use crate::vulkan::external_image::AcquireImageMemoryBarrier;
use crate::vulkan::external_image::ReleaseImageMemoryBarrier;

type VulkanoWindow = Arc<dyn Any + Send + Sync>;
type Surface = swapchain::Surface<VulkanoWindow>;
type Swapchain = swapchain::Swapchain<VulkanoWindow>;
type SwapchainImage = image::swapchain::SwapchainImage<VulkanoWindow>;

fn create_swapchain_create_info<T>(
    physical_device: &PhysicalDevice,
    surface: &Surface,
    image_size: &Size2D<u32, T>,
) -> Result<SwapchainCreateInfo> {
    let surface_capabilities = physical_device
        .surface_capabilities(surface, Default::default())
        .context("query surface cpabilities")?;
    ensure!(
        surface_capabilities.supported_usage_flags.transfer_dst,
        "The swapchain image must support USAGE_TRANSFER_DST. Supported usages: {:?}",
        surface_capabilities,
    );
    if let Some([width, height]) = surface_capabilities.current_extent {
        ensure!(
            *image_size == size2(width, height),
            "The passed in size {}x{} doesn't match the current surface extent {}x{}.",
            image_size.width,
            image_size.height,
            width,
            height
        );
    }
    ensure!(
        image_size.width <= surface_capabilities.max_image_extent[0]
            && image_size.width >= surface_capabilities.min_image_extent[0],
        "The passed in width {} must be within the range of [{}, {}].",
        image_size.width,
        surface_capabilities.min_image_extent[0],
        surface_capabilities.max_image_extent[0]
    );
    ensure!(
        image_size.height <= surface_capabilities.max_image_extent[1]
            && image_size.height >= surface_capabilities.min_image_extent[1],
        "The passed in width {} must be within the range of [{}, {}].",
        image_size.height,
        surface_capabilities.min_image_extent[1],
        surface_capabilities.max_image_extent[1]
    );
    // Triple buffering if possible.
    let min_image_count = 3.clamp(
        surface_capabilities.min_image_count,
        surface_capabilities.max_image_count.unwrap_or(u32::MAX),
    );
    let pre_transform = surface_capabilities.current_transform;
    let available_format_and_color_space = physical_device
        .surface_formats(surface, Default::default())
        .context("query formats and color spaces supported by the surface")?;
    let (image_format, image_color_space) = available_format_and_color_space
        .iter()
        .find(|(image_format, _)| matches!(image_format, Format::B8G8R8A8_UNORM))
        .copied()
        .ok_or_else(|| {
            format_err!(
                concat!(
                    "No supported formats and color spaces found. All supported formats and color ",
                    "spaces are {:?}"
                ),
                available_format_and_color_space
            )
        })?;
    let present_modes = physical_device
        .surface_present_modes(surface)
        .context("query the supported present mode")?
        .collect::<Vec<_>>();
    assert!(
        present_modes
            .iter()
            .any(|mode| matches!(mode, PresentMode::Fifo)),
        concat!(
            "The Vulkan spec requires the support of FIFO present mode, but it is not supported. ",
            "All supported present modes: {:?}."
        ),
        present_modes
    );
    let present_mode = PresentMode::Fifo;
    Ok(SwapchainCreateInfo {
        min_image_count,
        image_format: Some(image_format),
        image_color_space,
        image_extent: [image_size.width, image_size.height],
        image_array_layers: 1,
        image_usage: ImageUsage {
            transfer_dst: true,
            ..ImageUsage::empty()
        },
        image_sharing: Sharing::Exclusive,
        pre_transform,
        composite_alpha: CompositeAlpha::Opaque,
        present_mode,
        clipped: true,
        ..Default::default()
    })
}

#[derive(Clone)]
pub struct Timepoint {
    pub semaphore: Arc<Semaphore>,
    pub value: u64,
}

/// PostResource contains the required structures and information for posting to an individual
/// swapchain image.
struct PostResource {
    acquire_swapchain_image_semaphore: Semaphore,
    command_buffer_alloc: StandardCommandPoolAlloc,
    command_complete_fence: Fence,
    command_complete_semaphore: Semaphore,
}

impl PostResource {
    fn new(device: &Arc<Device>, command_buffer_alloc: StandardCommandPoolAlloc) -> Result<Self> {
        let acquire_swapchain_image_semaphore =
            Semaphore::new(Arc::clone(device), SemaphoreCreateInfo::default())
                .context("create semaphore for acquiring next swapchain image")?;
        let command_complete_semaphore =
            Semaphore::new(Arc::clone(device), SemaphoreCreateInfo::default())
                .context("create semaphore to be signaled after the command has completed")?;
        let command_complete_fence = Fence::new(
            Arc::clone(device),
            FenceCreateInfo {
                signaled: true,
                export_handle_types: ExternalFenceHandleTypes::empty(),
                ..Default::default()
            },
        )
        .context("create fence signaled when the command has completed")?;
        Ok(Self {
            acquire_swapchain_image_semaphore,
            command_buffer_alloc,
            command_complete_fence,
            command_complete_semaphore,
        })
    }

    /// Submit a blit of post_image to swap_chain image.
    ///
    /// The image in `post_image` needs to be transferred from an ExternalImage before it can be
    /// used as a blit source. It also may need to be transitioned to TransferSrcOptimal. This
    /// function will transition it back to an ExternalImage as part of the same submission. The
    /// image in `swapchain_image` will also be transferred to TransferDstOptimal for the blit and
    /// then finally to PresentSrc after the blit.
    fn record_and_submit_post_command(
        &mut self,
        device: &Device,
        ash_device: &ash::Device,
        post_image: ExternalImage,
        last_layout_transition: (ImageLayout, ImageLayout),
        swapchain_image: Arc<SwapchainImage>,
        graphics_queue: &Queue,
        present_queue: &Queue,
        post_image_acquire_timepoint: Option<&Timepoint>,
        post_image_release_timepoint: &Timepoint,
    ) -> ExternalImage {
        assert_eq!(
            device.internal_object(),
            ash_device.handle(),
            "The vulkano device and the ash device must refer to the same VkDevice."
        );
        // SAFETY: Safe because self.command_buffer_alloc outlives command_buffer_builder.
        let mut command_buffer_builder = unsafe {
            UnsafeCommandBufferBuilder::new(
                self.command_buffer_alloc.inner(),
                CommandBufferBeginInfo {
                    usage: CommandBufferUsage::OneTimeSubmit,
                    inheritance_info: None,
                    ..Default::default()
                },
            )
        }
        .unwrap_or_else(|e| panic!("Failed to begin recording the command buffer: {:?}", e));
        let post_image_old_layout = last_layout_transition.0;
        // SAFETY: Safe because the image in image_access (which is eventually converted back to
        // post_image where it still lives) outlives the command buffer.
        let image_access = unsafe {
            post_image.acquire(
                &mut command_buffer_builder,
                AcquireImageMemoryBarrier {
                    source_stages: PipelineStages {
                        transfer: true,
                        ..PipelineStages::empty()
                    },
                    destination_stages: PipelineStages {
                        transfer: true,
                        ..PipelineStages::empty()
                    },
                    destination_access: AccessFlags {
                        transfer_read: true,
                        ..AccessFlags::empty()
                    },
                    destination_queue_family_index: graphics_queue.queue_family_index(),
                    subresource_range: ImageSubresourceRange {
                        aspects: ImageAspects {
                            color: true,
                            ..ImageAspects::empty()
                        },
                        mip_levels: 0..1,
                        array_layers: 0..1,
                    },
                },
                last_layout_transition,
            )
        };
        let mut image_memory_barriers = SmallVec::from_vec(vec![ImageMemoryBarrier {
            source_stages: PipelineStages {
                transfer: true,
                ..PipelineStages::empty()
            },
            source_access: AccessFlags::empty(),
            destination_stages: PipelineStages {
                transfer: true,
                ..PipelineStages::empty()
            },
            destination_access: AccessFlags {
                transfer_write: true,
                ..AccessFlags::empty()
            },
            old_layout: ImageLayout::Undefined,
            new_layout: ImageLayout::TransferDstOptimal,
            // No need for ownership transfer, because we don't care about the content.
            queue_family_transfer: None,
            subresource_range: ImageSubresourceRange {
                aspects: ImageAspects {
                    color: true,
                    ..ImageAspects::empty()
                },
                mip_levels: 0..1,
                array_layers: 0..1,
            },
            ..ImageMemoryBarrier::image(Arc::clone(swapchain_image.inner().image))
        }]);
        if !matches!(
            image_access.initial_layout_requirement(),
            ImageLayout::TransferSrcOptimal
        ) {
            image_memory_barriers.push(ImageMemoryBarrier {
                source_stages: PipelineStages {
                    transfer: true,
                    ..PipelineStages::empty()
                },
                source_access: AccessFlags {
                    transfer_read: true,
                    ..AccessFlags::empty()
                },
                destination_stages: PipelineStages {
                    transfer: true,
                    ..PipelineStages::empty()
                },
                destination_access: AccessFlags {
                    transfer_read: true,
                    ..AccessFlags::empty()
                },
                old_layout: image_access.initial_layout_requirement(),
                new_layout: ImageLayout::TransferSrcOptimal,
                queue_family_transfer: None,
                subresource_range: ImageSubresourceRange {
                    aspects: ImageAspects {
                        color: true,
                        ..ImageAspects::empty()
                    },
                    mip_levels: 0..1,
                    array_layers: 0..1,
                },
                ..ImageMemoryBarrier::image(Arc::clone(image_access.inner().image))
            });
        }
        // SAFETY: Safe because the image in image_access (which is eventually converted back to
        // post_image where it still lives) outlives the command buffer.
        unsafe {
            command_buffer_builder.pipeline_barrier(&DependencyInfo {
                image_memory_barriers,
                ..Default::default()
            });
        }
        let image_access = Arc::new(image_access);
        // SAFETY: Safe because the image in image_access (which is eventually converted back to
        // post_image where it still lives) outlives the command buffer, and because
        // swapchain_image lives until the end of this function, thus outliving the command buffer.
        unsafe {
            command_buffer_builder.blit_image(&BlitImageInfo::images(
                Arc::clone(&image_access) as Arc<_>,
                Arc::clone(&swapchain_image) as Arc<_>,
            ));
        }
        let queue_family_transfer =
            if graphics_queue.queue_family_index() == present_queue.queue_family_index() {
                None
            } else {
                Some(QueueFamilyTransfer {
                    source_index: graphics_queue.queue_family_index(),
                    destination_index: present_queue.queue_family_index(),
                })
            };
        let mut image_memory_barriers = SmallVec::from_vec(vec![ImageMemoryBarrier {
            source_stages: PipelineStages {
                transfer: true,
                ..PipelineStages::empty()
            },
            source_access: AccessFlags {
                transfer_write: true,
                ..AccessFlags::empty()
            },
            destination_stages: PipelineStages::empty(),
            destination_access: AccessFlags::empty(),
            old_layout: ImageLayout::TransferDstOptimal,
            new_layout: ImageLayout::PresentSrc,
            queue_family_transfer,
            subresource_range: ImageSubresourceRange {
                aspects: ImageAspects {
                    color: true,
                    ..ImageAspects::empty()
                },
                mip_levels: 0..1,
                array_layers: 0..1,
            },
            ..ImageMemoryBarrier::image(Arc::clone(swapchain_image.inner().image))
        }]);
        if !matches!(
            image_access.final_layout_requirement(),
            ImageLayout::TransferSrcOptimal
        ) {
            image_memory_barriers.push(ImageMemoryBarrier {
                source_stages: PipelineStages {
                    transfer: true,
                    ..PipelineStages::empty()
                },
                source_access: AccessFlags {
                    transfer_read: true,
                    ..AccessFlags::empty()
                },
                destination_stages: PipelineStages {
                    transfer: true,
                    ..PipelineStages::empty()
                },
                destination_access: AccessFlags {
                    transfer_read: true,
                    ..AccessFlags::empty()
                },
                old_layout: ImageLayout::TransferSrcOptimal,
                new_layout: image_access.final_layout_requirement(),
                queue_family_transfer: None,
                subresource_range: ImageSubresourceRange {
                    aspects: ImageAspects {
                        color: true,
                        ..ImageAspects::empty()
                    },
                    mip_levels: 0..1,
                    array_layers: 0..1,
                },
                ..ImageMemoryBarrier::image(Arc::clone(image_access.inner().image))
            });
        }
        // SAFETY: Safe because the image in image_access (which is eventually converted back to
        // post_image where it still lives) outlives the command buffer.
        unsafe {
            command_buffer_builder.pipeline_barrier(&DependencyInfo {
                image_memory_barriers,
                ..Default::default()
            });
        }
        let image_access = Arc::try_unwrap(image_access).expect("should be the sole owner");
        // SAFETY: Safe because the image in post_image outlives the command buffer.
        let post_image = unsafe {
            image_access.release(
                &mut command_buffer_builder,
                ReleaseImageMemoryBarrier {
                    source_stages: PipelineStages {
                        transfer: true,
                        ..PipelineStages::empty()
                    },
                    source_access: AccessFlags {
                        transfer_read: true,
                        ..AccessFlags::empty()
                    },
                    destination_stages: PipelineStages {
                        transfer: true,
                        ..PipelineStages::empty()
                    },
                    new_layout: post_image_old_layout,
                    source_queue_family_index: graphics_queue.queue_family_index(),
                },
            )
        };
        let command_buffer = command_buffer_builder
            .build()
            .unwrap_or_else(|e| panic!("Failed to end the command buffer recording: {:#}", e));

        assert!(self
            .command_complete_fence
            .is_signaled()
            .unwrap_or_else(|e| panic!("Failed to query the status of the fence: {:?}", e)));
        self.command_complete_fence.reset().unwrap_or_else(|e| {
            panic!("Failed to reset the fence for the post resources: {:?}", e)
        });
        {
            // The first values are not used, because they are not binary semaphores.
            let mut wait_semaphore_values = vec![0];
            let signal_semaphore_values = [0, post_image_release_timepoint.value];
            let mut wait_semaphores =
                vec![self.acquire_swapchain_image_semaphore.internal_object()];
            let mut wait_dst_stage_mask = vec![vk::PipelineStageFlags::TRANSFER];
            let command_buffers = [command_buffer.internal_object()];
            let signal_semaphores = [
                self.command_complete_semaphore.internal_object(),
                post_image_release_timepoint.semaphore.internal_object(),
            ];

            if let Some(post_image_acquire_timepoint) = post_image_acquire_timepoint {
                wait_semaphore_values.push(post_image_acquire_timepoint.value);
                wait_semaphores.push(post_image_acquire_timepoint.semaphore.internal_object());
                wait_dst_stage_mask.push(vk::PipelineStageFlags::TRANSFER);
            }

            let mut timeline_semaphore_submit_info = vk::TimelineSemaphoreSubmitInfo::builder()
                .wait_semaphore_values(&wait_semaphore_values)
                .signal_semaphore_values(&signal_semaphore_values)
                .build();
            let submit_info = vk::SubmitInfo::builder()
                .wait_semaphores(&wait_semaphores)
                .wait_dst_stage_mask(&wait_dst_stage_mask)
                .command_buffers(&command_buffers)
                .signal_semaphores(&signal_semaphores)
                .push_next(&mut timeline_semaphore_submit_info)
                .build();

            // SAFETY: Safe because the contents of submit_info and all the things it points to
            // outlive this function call.
            unsafe {
                ash_device.queue_submit(
                    *graphics_queue.internal_object_guard(),
                    &[submit_info],
                    self.command_complete_fence.internal_object(),
                )
            }
            .unwrap_or_else(|e| panic!("Failed to submit the command: {:?}", e));
        }
        post_image
    }
}

/// PostWorker owns the vulkan surface and swapchain, and can post images to it.
pub struct PostWorker {
    physical_device: Arc<PhysicalDevice>,
    ash_device: Arc<ash::Device>,
    device: Arc<Device>,
    window: Arc<dyn Window>,
    swapchain: Arc<Swapchain>,
    swapchain_images: Vec<Arc<SwapchainImage>>,
    graphics_queue: Arc<Queue>,
    present_queue: Arc<Queue>,
    post_resources: Vec<PostResource>,
    _command_pool: Arc<StandardCommandPool>,
    rng: ThreadRng,
    // Mark Worker as !Sync and !Send
    _marker: PhantomData<Rc<()>>,
}

impl PostWorker {
    /// Initialize the post worker which does the following:
    ///   - Create the VkInstance
    ///   - Create the VkDevice and VkQueue
    ///   - Create the Swapchain
    ///   - Create a PostResource for each swapchain image
    pub(crate) fn new(
        vulkan_library: Arc<VulkanLibrary>,
        device_uuid: &[u8; UUID_SIZE],
        driver_uuid: &[u8; UUID_SIZE],
        window: Arc<dyn Window>,
    ) -> Result<Self> {
        // Create the Vulkan instance.
        let api_version = vulkan_library.api_version();
        if api_version < Version::V1_1 {
            bail!("Vulkan instance version too low: {:?}", api_version);
        }
        let instance = Instance::new(
            vulkan_library,
            InstanceCreateInfo {
                application_name: Some("vulkan_display_host".to_owned()),
                enabled_extensions: InstanceExtensions {
                    khr_external_memory_capabilities: true,
                    khr_get_physical_device_properties2: true,
                    khr_surface: true,
                    khr_win32_surface: true,
                    ..InstanceExtensions::empty()
                },
                ..Default::default()
            },
        )
        .context("create VkInstance")?;
        assert!(instance.api_version() >= Version::V1_1);

        // Choose the Vulkan physical device.
        let mut physical_devices = instance
            .enumerate_physical_devices()
            .context("enumerate physical devices")?;
        let physical_device = physical_devices.find(|physical_device| {
            let properties = physical_device.properties();
            if let (Some(current_device_uuid), Some(current_driver_uuid)) = (
                properties.device_uuid.as_ref(),
                properties.driver_uuid.as_ref(),
            ) {
                current_device_uuid == device_uuid && current_driver_uuid == driver_uuid
            } else {
                false
            }
        });
        let physical_device = if let Some(physical_device) = physical_device {
            physical_device
        } else {
            bail!("Failed to find the target physical device.");
        };
        {
            let properties = physical_device.properties();
            info!(
                "The post worker chooses the device: name: {}, vendor_id: {}",
                properties.device_name, properties.vendor_id
            );
        }
        let api_version = physical_device.api_version();
        if api_version < Version::V1_1 {
            bail!(
                "The physical device Vulkan version is too low: {:#}",
                api_version
            );
        }
        ensure!(
            physical_device.supported_features().timeline_semaphore,
            "The physical device doesn't support timeline semaphore."
        );

        let surface = Arc::clone(&window)
            .create_vulkan_surface(Arc::clone(&instance))
            .context("Failed to create the surface.")?;

        let queue_family_properties = physical_device.queue_family_properties();
        let queue_family_indices = (0u32..queue_family_properties
            .len()
            .try_into()
            .expect("queue family index too large"))
            .collect::<Vec<_>>();
        // Find the present queue.
        let mut present_queue_family_index = None;
        for queue_family_index in queue_family_indices.iter().copied() {
            let supported = physical_device
                .surface_support(queue_family_index, surface.borrow())
                .with_context(|| {
                    format!(
                        "query if queue family index {} supports the present",
                        queue_family_index
                    )
                })?;
            if supported {
                present_queue_family_index = Some(queue_family_index);
                break;
            }
        }
        let present_queue_family_index = match present_queue_family_index {
            Some(queue_index) => queue_index,
            None => bail!("No queue supports presentation."),
        };

        // Find the graphics queue.
        let graphics_queue_family_index = if queue_family_properties
            [usize::try_from(present_queue_family_index).expect("queue family index too large")]
        .queue_flags
        .graphics
        {
            Some(present_queue_family_index)
        } else {
            queue_family_indices
                .iter()
                .copied()
                .find(|queue_family_index| {
                    queue_family_properties[usize::try_from(*queue_family_index)
                        .expect("queue family index too large")]
                    .queue_flags
                    .graphics
                })
        };
        let graphics_queue_family_index = match graphics_queue_family_index {
            Some(queue_index) => queue_index,
            None => bail!("No queue supports graphics"),
        };

        // Create VkDevice.
        let queue_create_infos =
            BTreeSet::from([present_queue_family_index, graphics_queue_family_index])
                .iter()
                .copied()
                .map(|queue_family_index| QueueCreateInfo {
                    queue_family_index,
                    ..Default::default()
                })
                .collect();
        let (device, queues) = Device::new(
            Arc::clone(&physical_device),
            DeviceCreateInfo {
                enabled_extensions: DeviceExtensions {
                    khr_external_fence: true,
                    khr_external_fence_win32: true,
                    khr_external_semaphore: true,
                    khr_external_semaphore_win32: true,
                    khr_external_memory: true,
                    khr_external_memory_win32: true,
                    khr_swapchain: true,
                    khr_timeline_semaphore: true,
                    ..DeviceExtensions::empty()
                },
                enabled_features: Features {
                    timeline_semaphore: true,
                    ..Features::empty()
                },
                queue_create_infos,
                ..Default::default()
            },
        )
        .context("create VkDevice")?;

        // Create the swapchain.
        let (swapchain, swapchain_images) = Swapchain::new(
            Arc::clone(&device),
            Arc::clone(&surface),
            create_swapchain_create_info(
                physical_device.borrow(),
                surface.borrow(),
                &window
                    .get_inner_size()
                    .context("get the window size to create the swapchain")?,
            )
            .context("create the swapchain create info")?,
        )
        .context("create Vulkan swapchain")?;
        let queues = queues.collect::<Vec<_>>();
        let graphics_queue = queues
            .iter()
            .find(|queue| queue.queue_family_index() == graphics_queue_family_index)
            .cloned()
            .expect("Graphics queue not found.");
        let present_queue = queues
            .iter()
            .find(|queue| queue.queue_family_index() == present_queue_family_index)
            .cloned()
            .expect("Present queue not found.");

        let ash_device =
        // SAFETY: Safe because instance_fn comes from an instance we created and know is valid and
        // we also created device which is valid.
            unsafe { ash::Device::load(&instance.fns().v1_0, device.internal_object()) };

        // TODO (b/327677792): StandardCommandPool must be put inside an Arc, it's intended to work
        // that way. We need move to a newer version of vulkano to fix this.
        #[allow(clippy::arc_with_non_send_sync)]
        let command_pool = Arc::new(
            StandardCommandPool::new(Arc::clone(&device), graphics_queue_family_index)
                .context("create command pool")?,
        );
        let command_buffer_allocs = command_pool
            .allocate(
                CommandBufferLevel::Primary,
                (swapchain_images.len() + 1)
                    .try_into()
                    .expect("too many swapchain images"),
            )
            .context("allocate command buffers")?
            .map(CommandPoolBuilderAlloc::into_alloc);
        let post_resources: Vec<PostResource> = command_buffer_allocs
            .map(|command_buffer| {
                PostResource::new(&device, command_buffer)
                    .context("create resources for posting one frame")
            })
            .collect::<Result<_>>()?;

        Ok(Self {
            physical_device,
            ash_device: Arc::new(ash_device),
            device,
            window,
            swapchain,
            swapchain_images,
            graphics_queue,
            present_queue,
            post_resources,
            _command_pool: command_pool,
            rng: rand::thread_rng(),
            _marker: Default::default(),
        })
    }

    fn drain_queues(&self) -> Result<()> {
        self.graphics_queue
            .wait()
            .context("wait for the graphics queue to become idle")?;
        self.present_queue
            .wait()
            .context("wait for the present queue to become idle")?;
        Ok(())
    }

    pub fn recreate_swapchain(&mut self) -> Result<()> {
        let swapchain_create_info = create_swapchain_create_info(
            self.physical_device.borrow(),
            self.swapchain.surface(),
            &self
                .window
                .get_inner_size()
                .context("get the window size when recreating the swapchain")?,
        )
        .context("create swapchain create info")?;
        self.drain_queues()
            .context("wait for queues to become idel")?;
        (self.swapchain, self.swapchain_images) = self
            .swapchain
            .recreate(swapchain_create_info)
            .context("recreate swapchain")?;
        Ok(())
    }

    /// Acquire a swapchain image and call the supplied function with the swapchain's PostResource,
    /// SwapchainImage, and the generic `userdata`. Userdata is likely to be the source image(s)
    /// that are being presented to the swapchain image and the userdata is returned to the caller
    /// for reuse. After `f` is called, this function will submit a present call for that swapchain
    /// image.
    ///
    /// Note: It is the responsibility of `f` to make sure that the swapchain image has been
    /// transferred to the PresentSrc layout.
    fn with_swapchain_image<T>(
        &mut self,
        mut f: impl FnMut(&mut PostResource, Arc<SwapchainImage>, T) -> T,
        mut userdata: T,
    ) -> Result<T> {
        let mut attempts = 0;
        const MAX_ATTEMPTS: i32 = 5;
        loop {
            if attempts > 0 {
                info!("Recreate the swapchain: attempt {}", attempts);
                self.recreate_swapchain()
                    .context("recreate the swapchain")?;
            }
            if attempts > MAX_ATTEMPTS {
                bail!(
                    "The swapchain is always suboptimal or out of date with {} attempts.",
                    attempts
                );
            }
            attempts += 1;

            let post_resource_index = (0..self.post_resources.len()).find(|i| {
                self.post_resources[*i]
                    .command_complete_fence
                    .is_signaled()
                    .unwrap_or_else(|e| panic!("Failed to retrieve the fence status: {}", e))
            });
            let post_resource = match post_resource_index {
                Some(i) => &mut self.post_resources[i],
                None => {
                    let post_resource = self
                        .post_resources
                        .iter_mut()
                        .choose(&mut self.rng)
                        .expect("post resources shouldn't be empty");
                    post_resource
                        .command_complete_fence
                        .wait(Some(Duration::from_secs(5)))
                        .unwrap_or_else(|e| {
                            panic!("Failed to wait for one recource to be available: {:?}.", e)
                        });
                    post_resource
                }
            };

            // SAFETY: Safe because self.swapchain and
            // post_resource.acquire_swapchain_image_semaphore contain no pointers and outlive this
            //  call.
            let (index, present_wait_semaphore) = match unsafe {
                acquire_next_image_raw(
                    self.swapchain.borrow(),
                    None,
                    Some(&post_resource.acquire_swapchain_image_semaphore),
                    None,
                )
            } {
                Ok(AcquiredImage {
                    suboptimal: true, ..
                })
                | Err(AcquireError::OutOfDate) => continue,
                Ok(AcquiredImage {
                    id: index,
                    suboptimal: false,
                }) => {
                    userdata = f(
                        post_resource,
                        Arc::clone(&self.swapchain_images[index]),
                        userdata,
                    );
                    (index, &post_resource.command_complete_semaphore)
                }
                Err(err) => return Err(err).context("acquire next image"),
            };
            let present_info = PresentInfo {
                index,
                ..PresentInfo::swapchain(Arc::clone(&self.swapchain))
            };
            let mut submit_present_builder = SubmitPresentBuilder::new();
            // SAFETY: Safe because before destroying the swapchain, we always wait for the queues
            // to be idle. Hence the swapchain must outlive this presenting.
            unsafe { submit_present_builder.add_swapchain(&present_info) };
            // SAFETY: Safe because of the safety requirement of this function.
            unsafe { submit_present_builder.add_wait_semaphore(present_wait_semaphore) }
            match submit_present_builder.submit(self.present_queue.borrow()) {
                Ok(()) => return Ok(userdata),
                Err(SubmitPresentError::OutOfDate) => continue,
                Err(err) => return Err(err).context("submit the present request"),
            }
        }
    }

    pub fn post(
        &mut self,
        image: ExternalImage,
        last_layout_transition: (ImageLayout, ImageLayout),
        acquire_timepoint: Option<Timepoint>,
        release_timepoint: Timepoint,
    ) -> ExternalImage {
        let device = Arc::clone(&self.device);
        let ash_device = Arc::clone(&self.ash_device);
        let graphics_queue = Arc::clone(&self.graphics_queue);
        let present_queue = Arc::clone(&self.present_queue);
        self.with_swapchain_image(
            |post_resource, swapchain_image, image| {
                let out_image = post_resource.record_and_submit_post_command(
                    device.borrow(),
                    ash_device.borrow(),
                    image,
                    last_layout_transition,
                    swapchain_image,
                    graphics_queue.borrow(),
                    present_queue.borrow(),
                    acquire_timepoint.as_ref(),
                    &release_timepoint,
                );
                out_image
            },
            image,
        )
        .unwrap_or_else(|err| panic!("Failed when posting a frame: {:?}", err))
    }

    pub fn device(&self) -> Arc<Device> {
        Arc::clone(&self.device)
    }
}

impl Drop for PostWorker {
    fn drop(&mut self) {
        if let Err(err) = self.drain_queues() {
            error!(
                "Failed to wait for queues to become idle when destroying the post worker: {:?}",
                err
            );
        }
    }
}

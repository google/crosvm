// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg_attr(unix, allow(dead_code))]

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::mpsc::channel;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::ensure;
use anyhow::format_err;
use anyhow::Context;
use anyhow::Result;
use ash::vk::UUID_SIZE;
use ash::vk::{self};
use base::error;
use base::warn;
use base::AsRawDescriptor;
use euclid::Box2D;
use euclid::Size2D;
use euclid::UnknownUnit;
use smallvec::SmallVec;

mod external_image;
mod post_worker;
mod sys;

pub use external_image::AcquireImageMemoryBarrier;
pub use external_image::ExternalImage;
pub use external_image::ExternalImageAccess;
pub use external_image::ReleaseImageMemoryBarrier;
use post_worker::PostWorker;
use post_worker::Timepoint;
use sync::create_promise_and_waitable;
use sync::Promise;
use sync::Waitable;
use vulkano::device::Device;
use vulkano::image::sys::UnsafeImageCreateInfo;
use vulkano::image::ImageCreateFlags;
use vulkano::image::ImageDimensions;
use vulkano::image::ImageLayout;
use vulkano::image::ImageUsage;
use vulkano::memory::ExternalMemoryHandleTypes;
use vulkano::memory::MemoryAllocateInfo;
use vulkano::sync::ExternalSemaphoreHandleTypes;
use vulkano::sync::Semaphore;
use vulkano::sync::SemaphoreCreateInfo;
use vulkano::sync::Sharing;
use vulkano::VulkanLibrary;
use vulkano::VulkanObject;

use self::sys::platform::create_post_image_external_memory_handle_types;
use self::sys::platform::create_post_image_memory_import_info;
use self::sys::platform::import_semaphore_from_descriptor;
use self::sys::platform::NativeWindowType;
use self::sys::ApplicationState;
use self::sys::ApplicationStateBuilder;
pub(crate) use self::sys::PlatformWindowEventLoop;
use self::sys::Window;
use self::sys::WindowEvent;
use self::sys::WindowEventLoop;
use crate::SemaphoreTimepoint;
use crate::VulkanDisplayImageImportMetadata;

/// Vulkan Safety Notes:
/// Most vulkan APIs are unsafe, but even the wrapper APIs like ash and vulkano will mark their
/// APIs as unsafe when they cannot ensure that they are 100% obeying the vulkan spec. For the
/// purposes of VulkanDisplay, however, we do not consider disobeying the vulkan spec to be unsafe
/// in terms of memory safety. Safety comments in these cases will say:
/// "Safe irrespective of vulkan spec conformance"
///
/// If the function is unsafe for any other reason we will still note why it's safe.

pub type SemaphoreId = u32;
pub type ImageId = u32;

pub enum UserEvent {
    GetVulkanDevice(Sender<Arc<Device>>),
    PostCommand {
        image: ExternalImage,
        last_layout_transition: (ImageLayout, ImageLayout),
        acquire_timepoint: Option<Timepoint>,
        release_timepoint: Timepoint,
        image_return: Sender<ExternalImage>,
        promise: Promise,
    },
}

pub struct VulkanState {
    // Post worker submits renders and posts to vulkan. It needs to be in a RefCell because
    // process_event cannot take a mutable reference to ApplicationState.
    post_worker: RefCell<PostWorker>,
}

impl ApplicationState for VulkanState {
    type UserEvent = UserEvent;

    /// Process events coming from the Window.
    fn process_event(&self, event: WindowEvent<Self::UserEvent>) {
        match event {
            WindowEvent::User(UserEvent::GetVulkanDevice(sender)) => {
                sender
                    .send(self.post_worker.borrow().device())
                    .expect("Should send VkDevice back to the caller successfully.");
            }
            WindowEvent::User(UserEvent::PostCommand {
                image,
                last_layout_transition,
                acquire_timepoint,
                release_timepoint,
                image_return,
                promise,
            }) => {
                // If this post triggers a resize event then the recursive wndproc call will
                // call into this function again and trigger another borrow which will panic.
                // TODO (b/314379499): figure out a way to avoid this
                let image = self.post_worker.borrow_mut().post(
                    image,
                    last_layout_transition,
                    acquire_timepoint,
                    release_timepoint,
                );
                promise.signal();
                image_return
                    .send(image)
                    .expect("Should send ExternalImage back to the caller successfully.");
            }
            WindowEvent::Resized => {
                // If this resize event triggers another resize event then this will fail.
                // TODO (b/314379499): figure out a way to avoid this
                if let Err(err) = self.post_worker.borrow_mut().recreate_swapchain() {
                    panic!(
                        concat!(
                            "Failed to recreate the swapchain when handling the Resized window ",
                            "event: {:?}."
                        ),
                        err
                    );
                }
            }
        }
    }
}

struct VulkanStateBuilder {
    vulkan_library: Arc<VulkanLibrary>,
    device_uuid: [u8; vk::UUID_SIZE],
    driver_uuid: [u8; vk::UUID_SIZE],
}

impl ApplicationStateBuilder for VulkanStateBuilder {
    type Target = VulkanState;

    fn build<T: Window>(self, window: Arc<T>) -> Result<VulkanState> {
        let post_worker = PostWorker::new(
            self.vulkan_library,
            &self.device_uuid,
            &self.driver_uuid,
            Arc::clone(&window) as _,
        )
        .context("creating the post worker")?;
        Ok(VulkanState {
            post_worker: RefCell::new(post_worker),
        })
    }
}

pub struct VulkanDisplayImpl<T: WindowEventLoop<VulkanState>> {
    ash_device: ash::Device,
    device: Arc<Device>,
    window_event_loop: T,
    imported_semaphores: HashMap<SemaphoreId, Arc<Semaphore>>,
    imported_images: HashMap<ImageId, ExternalImage>,
    used_image_receivers: HashMap<ImageId, Receiver<ExternalImage>>,
}

impl<T: WindowEventLoop<VulkanState>> VulkanDisplayImpl<T> {
    /// # Safety
    /// The parent window must outlive the lifetime of this object.
    #[deny(unsafe_op_in_unsafe_fn)]
    pub unsafe fn new(
        vulkan_library: Arc<VulkanLibrary>,
        parent: NativeWindowType,
        initial_window_size: &Size2D<i32, UnknownUnit>,
        device_uuid: [u8; UUID_SIZE],
        driver_uuid: [u8; UUID_SIZE],
    ) -> Result<Self> {
        let vulkan_state_builder = VulkanStateBuilder {
            vulkan_library,
            device_uuid,
            driver_uuid,
        };
        // SAFETY: Safe because it is guaranteed by the safety requirement of this function that
        // the parent window outlives the event loop object.
        let window_event_loop = unsafe {
            T::create(parent, initial_window_size, vulkan_state_builder)
                .context("create window and event loop")?
        };
        let (vk_device_tx, vk_device_rx) = channel();
        window_event_loop
            .send_event(UserEvent::GetVulkanDevice(vk_device_tx))
            .context("retrieve VkDevice from the window event loop")?;
        let device = loop {
            const TIMEOUT: Duration = Duration::from_secs(60);
            match vk_device_rx.recv_timeout(TIMEOUT) {
                Ok(value) => break value,

                Err(RecvTimeoutError::Timeout) => {
                    warn!(
                        "Didn't receive the VkDevice from the event loop for {:?}. Retry.",
                        TIMEOUT
                    );
                    continue;
                }
                Err(e) => {
                    return Err(format_err!(
                        "Failed to receive VkDevice from the event loop: {:?}.",
                        e
                    ));
                }
            }
        };
        let ash_device =
        // SAFETY: Safe because we trust the vulkan device we get from the window event loop and
        // the instance_fn comes from an instance we know is valid because the device was created
        // with it.
            unsafe { ash::Device::load(&device.instance().fns().v1_0, device.internal_object()) };
        Ok(Self {
            ash_device,
            device,
            window_event_loop,
            imported_semaphores: Default::default(),
            imported_images: Default::default(),
            used_image_receivers: Default::default(),
        })
    }

    pub fn move_window(&self, pos: &Box2D<i32, UnknownUnit>) -> Result<()> {
        self.window_event_loop.move_window(pos)
    }

    pub fn import_semaphore(
        &mut self,
        semaphore_id: SemaphoreId,
        descriptor: &dyn AsRawDescriptor,
    ) -> Result<()> {
        let mut type_create_info = vk::SemaphoreTypeCreateInfo::builder()
            .semaphore_type(vk::SemaphoreType::TIMELINE)
            .initial_value(0)
            .build();
        let create_info = vk::SemaphoreCreateInfo::builder()
            .push_next(&mut type_create_info)
            .build();
        // SAFETY: Safe because create_info and it's fields are local to this function and outlive
        // this function call.
        let semaphore = unsafe { self.ash_device.create_semaphore(&create_info, None) }
            .context("create timeline semaphore")?;

        let res = import_semaphore_from_descriptor(&self.device, semaphore, descriptor);
        ensure!(
            res == vk::Result::SUCCESS,
            "Failed to import the external handle to the semaphore: {}.",
            res
        );

        // SAFETY: Safe irrespective of vulkan spec conformance
        let res = unsafe {
            Semaphore::from_handle(
                Arc::clone(&self.device),
                semaphore,
                SemaphoreCreateInfo {
                    // Note that as of vulkano version 0.34.1, this
                    // export_handle_types field is only used to validate which
                    // export APIs can be used in the future. We do not export
                    // this semaphore so we do not need to specify any export
                    // handle types.
                    export_handle_types: ExternalSemaphoreHandleTypes::empty(),
                    ..Default::default()
                },
            )
        };

        if self
            .imported_semaphores
            .insert(semaphore_id, Arc::new(res))
            .is_some()
        {
            warn!("Reused semaphore_id {}", semaphore_id);
        }

        Ok(())
    }

    pub fn import_image(
        &mut self,
        image_id: ImageId,
        descriptor: &dyn AsRawDescriptor,
        metadata: VulkanDisplayImageImportMetadata,
    ) -> Result<()> {
        let image_create_flags = metadata.flags;
        let ImageCreateFlags {
            sparse_binding,
            sparse_residency,
            sparse_aliased,
            mutable_format,
            cube_compatible,
            array_2d_compatible,
            block_texel_view_compatible,
            _ne: _,
        } = vk::ImageCreateFlags::from_raw(image_create_flags)
            .try_into()
            .map_err(|_| {
                format_err!(
                    "Failed to convert flags {} to an image create flags.",
                    image_create_flags
                )
            })?;
        assert!(
            !(sparse_binding || sparse_residency || sparse_aliased),
            "unsupported image create flags {:#x}",
            image_create_flags
        );
        let image_type = vk::ImageType::from_raw(metadata.image_type);
        let image_extent = metadata.extent;
        let image_dimensions = match image_type {
            vk::ImageType::TYPE_2D => ImageDimensions::Dim2d {
                width: image_extent.width,
                height: image_extent.height,
                array_layers: metadata.array_layers,
            },
            _ => unimplemented!(),
        };
        let format = {
            let format = metadata.format;
            vk::Format::from_raw(format)
                .try_into()
                .map_err(|_| format_err!("Failed to convert {:#x} to format.", format))?
        };
        let image_samples = {
            let samples = metadata.samples;
            vk::SampleCountFlags::from_raw(samples)
                .try_into()
                .map_err(|_| {
                    format_err!("Failed to convert {:#x} to sample count flag.", samples)
                })?
        };
        let image_tiling = {
            let tiling = metadata.tiling;
            vk::ImageTiling::from_raw(tiling)
                .try_into()
                .map_err(|_| format_err!("Failed to convert {:#x} to image tiling enum.", tiling))?
        };
        let image_usage = {
            let usage = metadata.usage;
            vk::ImageUsageFlags::from_raw(usage)
                .try_into()
                .map_err(|_| format_err!("Failed to convert {:#x} to image usage.", usage))?
        };
        let image_sharing = {
            let sharing_mode = metadata.sharing_mode;
            match vk::SharingMode::from_raw(sharing_mode) {
                vk::SharingMode::EXCLUSIVE => Sharing::Exclusive,
                vk::SharingMode::CONCURRENT => {
                    let mut queue_family_indices = SmallVec::new();
                    queue_family_indices.copy_from_slice(&metadata.queue_family_indices);
                    Sharing::Concurrent(queue_family_indices)
                }
                _ => return Err(format_err!("Invalid sharing mode {:#x}.", sharing_mode)),
            }
        };
        let image_initial_layout = {
            let initial_layout = metadata.initial_layout;
            vk::ImageLayout::from_raw(initial_layout)
                .try_into()
                .map_err(|_| {
                    format_err!(
                        "Failed to convert the initial layout {:#x} to an image layout.",
                        initial_layout
                    )
                })?
        };

        let image = ExternalImage::import(
            &self.device,
            UnsafeImageCreateInfo {
                dimensions: image_dimensions,
                format: Some(format),
                mip_levels: metadata.mip_levels,
                samples: image_samples,
                tiling: image_tiling,
                usage: image_usage,
                stencil_usage: ImageUsage::empty(),
                sharing: image_sharing,
                initial_layout: image_initial_layout,
                external_memory_handle_types: create_post_image_external_memory_handle_types(),
                mutable_format,
                cube_compatible,
                array_2d_compatible,
                block_texel_view_compatible,
                ..Default::default()
            },
            MemoryAllocateInfo {
                allocation_size: metadata.allocation_size,
                memory_type_index: metadata.memory_type_index,
                export_handle_types: ExternalMemoryHandleTypes::empty(),
                ..Default::default()
            },
            create_post_image_memory_import_info(descriptor),
            metadata.dedicated_allocation,
            0,
        )
        .context("import the composition result image")?;

        if self.imported_images.insert(image_id, image).is_some() {
            warn!("Reused image_id {}", image_id);
        }
        Ok(())
    }

    pub fn delete_imported_image_or_semaphore(&mut self, import_id: u32) {
        // Import ids are shared between images and semaphores, so first try to remove from
        // self.imported_sempahores, and if that returns none then try to remove from images.
        if self.imported_semaphores.remove(&import_id).is_none() {
            if let Some(receiver) = self.used_image_receivers.remove(&import_id) {
                if let Err(e) = receiver.recv() {
                    error!("Failed to receive used image from post worker: {}", e);
                }
            } else if self.imported_images.remove(&import_id).is_none() {
                error!("Import id {} has not been imported", import_id);
            }
        }
    }

    pub fn post(
        &mut self,
        image_id: ImageId,
        last_layout_transition: (i32, i32),
        acquire_semaphore: Option<SemaphoreTimepoint>,
        release_semaphore: SemaphoreTimepoint,
    ) -> Result<Waitable> {
        let image = if let Some(receiver) = self.used_image_receivers.remove(&image_id) {
            receiver
                .recv()
                .context("failed to receive used image from post worker")?
        } else {
            self.imported_images
                .remove(&image_id)
                .ok_or(anyhow!("Image id {} has not been imported", image_id))?
        };

        let acquire_timepoint =
            if let Some(SemaphoreTimepoint { import_id, value }) = acquire_semaphore {
                let semaphore = self
                    .imported_semaphores
                    .get(&import_id)
                    .ok_or(anyhow!("Semaphore id {} has not been imported", import_id))?;
                Some(Timepoint {
                    semaphore: semaphore.clone(),
                    value,
                })
            } else {
                None
            };

        let release_timepoint = {
            let semaphore = self
                .imported_semaphores
                .get(&release_semaphore.import_id)
                .ok_or(anyhow!(
                    "Semaphore id {} has not been imported",
                    release_semaphore.import_id
                ))?;
            Timepoint {
                semaphore: semaphore.clone(),
                value: release_semaphore.value,
            }
        };

        let last_layout_transition: (ImageLayout, ImageLayout) = (
            ash::vk::ImageLayout::from_raw(last_layout_transition.0)
                .try_into()
                .map_err(|_| {
                    anyhow!(
                        "Failed to convert {:#x} to a valid image layout.",
                        last_layout_transition.0
                    )
                })?,
            ash::vk::ImageLayout::from_raw(last_layout_transition.1)
                .try_into()
                .map_err(|_| {
                    anyhow!(
                        "Failed to convert {:#x} to a valid image layout.",
                        last_layout_transition.1
                    )
                })?,
        );

        let (promise, waitable) = create_promise_and_waitable();

        let (image_return_tx, image_return_rx) = channel();
        self.used_image_receivers.insert(image_id, image_return_rx);

        self.window_event_loop
            .send_event(UserEvent::PostCommand {
                image,
                last_layout_transition,
                acquire_timepoint,
                release_timepoint,
                image_return: image_return_tx,
                promise,
            })
            .context("send user defined message to the window event loop")?;
        Ok(waitable)
    }
}

pub(crate) type VulkanDisplay = VulkanDisplayImpl<PlatformWindowEventLoop<VulkanState>>;

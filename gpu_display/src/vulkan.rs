// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(dead_code)]

use std::sync::mpsc::Sender;
use std::sync::Arc;

use anyhow::Result;
use ash::vk::Extent3D;
use ash::vk::{self};
use base::SafeDescriptor;

mod external_image;
mod post_worker;
mod sys;

pub use external_image::AcquireImageMemoryBarrier;
pub use external_image::ExternalImage;
pub use external_image::ExternalImageAccess;
pub use external_image::ReleaseImageMemoryBarrier;
pub use post_worker::Timepoint;
use sync::Promise;
use sync::Waitable;
use vulkano::image::ImageLayout;
use vulkano::VulkanLibrary;

use self::sys::ApplicationState;
use self::sys::ApplicationStateBuilder;
use self::sys::PlatformWindowEventLoop;
use self::sys::Window;
use self::sys::WindowEvent;
use self::sys::WindowEventLoop;

pub struct VulkanDisplayImageImportMetadata {
    // These fields go into a VkImageCreateInfo
    pub flags: u32,
    pub image_type: i32,
    pub format: i32,
    pub extent: Extent3D,
    pub mip_levels: u32,
    pub array_layers: u32,
    pub samples: u32,
    pub tiling: i32,
    pub usage: u32,
    pub sharing_mode: i32,
    pub queue_family_indices: Vec<u32>,
    pub initial_layout: i32,

    // These fields go into a VkMemoryAllocateInfo
    pub allocation_size: u64,
    pub memory_type_index: u32,

    // Additional information
    pub dedicated_allocation: bool,
}

pub type SemaphoreId = u32;
pub type ImageId = u32;

pub(crate) enum UserEvent {
    PostCommand {
        image: ExternalImage,
        last_layout_transition: (ImageLayout, ImageLayout),
        acquire_timepoint: Option<Timepoint>,
        release_timepoint: Timepoint,
        image_return: Sender<ExternalImage>,
        promise: Promise,
    },
}

pub(crate) struct VulkanState {}

impl ApplicationState for VulkanState {
    type UserEvent = UserEvent;

    /// Process events coming from the Window.
    fn process_event(&self, _event: WindowEvent<Self::UserEvent>) {
        unimplemented!()
    }
}

struct VulkanStateBuilder {
    vulkan_library: Arc<VulkanLibrary>,
    device_uuid: [u8; vk::UUID_SIZE],
    driver_uuid: [u8; vk::UUID_SIZE],
}

impl ApplicationStateBuilder for VulkanStateBuilder {
    type Target = VulkanState;

    fn build<T: Window>(self, _window: Arc<T>) -> Result<VulkanState> {
        unimplemented!()
    }
}

pub(crate) struct VulkanDisplayImpl<T: WindowEventLoop<VulkanState>> {
    window_event_loop: T,
}

impl<T: WindowEventLoop<VulkanState>> VulkanDisplayImpl<T> {
    pub fn import_semaphore(
        &mut self,
        _semaphore_id: SemaphoreId,
        _descriptor: SafeDescriptor,
    ) -> Result<()> {
        unimplemented!()
    }

    pub fn import_image(
        &mut self,
        _image_id: ImageId,
        _descriptor: SafeDescriptor,
        _metadata: VulkanDisplayImageImportMetadata,
    ) -> Result<()> {
        unimplemented!()
    }

    pub fn post(
        &mut self,
        _image_id: ImageId,
        _last_layout_transition: (i32, i32),
        _acquire_semaphore: Option<(SemaphoreId, u64)>,
        _release_semaphore: (SemaphoreId, u64),
    ) -> Result<Waitable> {
        unimplemented!()
    }
}

pub(crate) type VulkanDisplay = VulkanDisplayImpl<PlatformWindowEventLoop<VulkanState>>;

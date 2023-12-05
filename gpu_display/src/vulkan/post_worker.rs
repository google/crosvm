// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::any::Any;
use std::sync::Arc;

use anyhow::Result;
use ash::vk::UUID_SIZE;
use vulkano::device::Device;
use vulkano::image::ImageLayout;
use vulkano::image::{self};
use vulkano::swapchain::{self};
use vulkano::sync::Semaphore;
use vulkano::VulkanLibrary;

use super::sys::Window;
use super::ExternalImage;

type VulkanoWindow = Arc<dyn Any + Send + Sync>;
type Surface = swapchain::Surface<VulkanoWindow>;
type Swapchain = swapchain::Swapchain<VulkanoWindow>;
type SwapchainImage = image::swapchain::SwapchainImage<VulkanoWindow>;

#[derive(Clone)]
pub struct Timepoint {
    pub semaphore: Arc<Semaphore>,
    pub value: u64,
}

/// PostResource contains the required structures and information for posting to an individual
/// swapchain image.
pub struct PostResource {}

/// PostWorker owns the vulkan surface and swapchain, and can post images to it.
pub struct PostWorker {
    device: Arc<Device>,
}

impl PostWorker {
    pub(crate) fn new(
        _vulkan_library: Arc<VulkanLibrary>,
        _device_uuid: &[u8; UUID_SIZE],
        _driver_uuid: &[u8; UUID_SIZE],
        _window: Arc<dyn Window>,
    ) -> Result<Self> {
        unimplemented!()
    }

    pub fn recreate_swapchain(&mut self) -> Result<()> {
        unimplemented!()
    }

    pub fn post(
        &mut self,
        _image: ExternalImage,
        _last_layout_transition: (ImageLayout, ImageLayout),
        _acquire_timepoint: Option<Timepoint>,
        _release_timepoint: Timepoint,
    ) -> ExternalImage {
        unimplemented!()
    }

    pub fn device(&self) -> Arc<Device> {
        Arc::clone(&self.device)
    }
}

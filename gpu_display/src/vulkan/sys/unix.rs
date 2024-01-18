// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::c_void;
use std::marker::PhantomData;
use std::sync::Arc;

use anyhow::Result;
use ash::vk;
use base::AsRawDescriptor;
use euclid::Size2D;
use euclid::UnknownUnit;
use vulkano::device::Device;
use vulkano::instance::Instance;
use vulkano::memory::ExternalMemoryHandleTypes;
use vulkano::memory::MemoryImportInfo;

use super::ApplicationState;
use super::ApplicationStateBuilder;
use super::Surface;
use super::Window;
use super::WindowEventLoop;

pub type NativeWindowType = *mut c_void;

pub(crate) struct StubWindow;

impl Window for StubWindow {
    fn create_vulkan_surface(self: Arc<Self>, _instance: Arc<Instance>) -> Result<Arc<Surface>> {
        unimplemented!();
    }

    fn get_inner_size(&self) -> Result<Size2D<u32, UnknownUnit>> {
        unimplemented!()
    }
}

pub struct StubWindowEventLoop<AppState: ApplicationState>(PhantomData<AppState>);

impl<AppState: ApplicationState> WindowEventLoop<AppState> for StubWindowEventLoop<AppState> {
    type WindowType = StubWindow;

    unsafe fn create<Builder>(
        _parent: NativeWindowType,
        _initial_window_size: &Size2D<i32, UnknownUnit>,
        _application_state_builder: Builder,
    ) -> Result<Self>
    where
        Builder: ApplicationStateBuilder<Target = AppState>,
    {
        unimplemented!()
    }

    fn move_window(&self, _pos: &euclid::Box2D<i32, UnknownUnit>) -> Result<()> {
        unimplemented!()
    }

    fn send_event(&self, _event: AppState::UserEvent) -> Result<()> {
        unimplemented!()
    }
}

pub(crate) fn create_post_image_external_memory_handle_types() -> ExternalMemoryHandleTypes {
    unimplemented!()
}

// The ownership of the descriptor is transferred to the returned MemoryImportInfo.
pub(crate) fn create_post_image_memory_import_info(
    _memory_descriptor: &dyn AsRawDescriptor,
) -> MemoryImportInfo {
    unimplemented!()
}

pub(crate) fn import_semaphore_from_descriptor(
    _device: &Arc<Device>,
    _semaphore: vk::Semaphore,
    _descriptor: &dyn AsRawDescriptor,
) -> vk::Result {
    unimplemented!()
}

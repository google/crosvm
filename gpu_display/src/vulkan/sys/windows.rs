// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::marker::PhantomData;
use std::sync::Arc;

use anyhow::Result;
use ash::vk;
use base::AsRawDescriptor;
use euclid::Box2D;
use euclid::Size2D;
use euclid::UnknownUnit;
use vulkano::device::Device;
use vulkano::instance::Instance;
use vulkano::memory::ExternalMemoryHandleTypes;
use vulkano::memory::MemoryImportInfo;
use winapi::shared::windef::HWND;

use super::ApplicationState;
use super::ApplicationStateBuilder;
use super::Surface;
use super::Window as WindowT;
use super::WindowEventLoop;

pub type NativeWindowType = HWND;

pub(crate) struct Window {}

impl WindowT for Window {
    fn get_inner_size(&self) -> Result<Size2D<u32, euclid::UnknownUnit>> {
        unimplemented!()
    }

    fn create_vulkan_surface(self: Arc<Self>, _instance: Arc<Instance>) -> Result<Arc<Surface>> {
        unimplemented!()
    }
}

struct WindowState<AppState: ApplicationState> {
    app_state: AppState,
    window: Arc<Window>,
}

pub(crate) struct WindowsWindowEventLoop<AppState: ApplicationState>(PhantomData<AppState>);

impl<AppState: ApplicationState> WindowEventLoop<AppState> for WindowsWindowEventLoop<AppState> {
    type WindowType = Window;

    /// # Safety
    /// The parent window must outlive the lifetime of this object.
    #[deny(unsafe_op_in_unsafe_fn)]
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

    fn move_window(&self, _pos: &Box2D<i32, UnknownUnit>) -> Result<()> {
        unimplemented!()
    }

    fn send_event(&self, _event: AppState::UserEvent) -> Result<()> {
        unimplemented!()
    }
}

pub(crate) fn create_post_image_external_memory_handle_types() -> ExternalMemoryHandleTypes {
    ExternalMemoryHandleTypes {
        opaque_win32: true,
        ..ExternalMemoryHandleTypes::empty()
    }
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

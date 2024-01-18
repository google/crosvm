// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub mod unix;
        pub use unix as platform;
        pub(crate) use self::unix::StubWindowEventLoop as PlatformWindowEventLoop;
    } else if #[cfg(windows)] {
        pub mod windows;
        pub use windows as platform;
        pub(crate) use self::windows::WindowsWindowEventLoop as PlatformWindowEventLoop;
    }
}

use std::any::Any;
use std::sync::Arc;

use anyhow::Result;
use euclid::Box2D;
use euclid::Size2D;
use euclid::UnknownUnit;
use vulkano::instance::Instance;
use vulkano::swapchain;

type Surface = swapchain::Surface<Arc<dyn Any + Send + Sync>>;

pub trait Window: Any + Send + Sync {
    fn get_inner_size(&self) -> Result<Size2D<u32, UnknownUnit>>;
    fn create_vulkan_surface(self: Arc<Self>, instance: Arc<Instance>) -> Result<Arc<Surface>>;
}

pub trait ApplicationState {
    type UserEvent: Send + 'static;

    fn process_event(&self, event: WindowEvent<Self::UserEvent>);
}

pub trait ApplicationStateBuilder: Send + 'static {
    type Target: ApplicationState;

    fn build<T: Window>(self, window: Arc<T>) -> Result<Self::Target>;
}

// Some platform may not support all the events.
#[allow(dead_code)]
pub enum WindowEvent<T: Send> {
    Resized,
    User(T),
}

pub trait WindowEventLoop<State: ApplicationState>: Sized + Send {
    type WindowType: Window;

    /// # Safety
    /// The parent window must outlive the lifetime of this object.
    unsafe fn create<Builder>(
        parent: platform::NativeWindowType,
        initial_window_size: &Size2D<i32, UnknownUnit>,
        application_state_builder: Builder,
    ) -> Result<Self>
    where
        Builder: ApplicationStateBuilder<Target = State>;

    fn send_event(&self, event: State::UserEvent) -> Result<()>;

    fn move_window(&self, pos: &Box2D<i32, UnknownUnit>) -> Result<()>;
}

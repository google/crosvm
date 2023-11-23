// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ops::ControlFlow;

use anyhow::Result;
use euclid::Size2D;
use euclid::Transform2D;
use winapi::shared::minwindef::LRESULT;

use super::window::GuiWindow;
use super::window_message_dispatcher::DisplayEventDispatcher;
use super::window_message_processor::WindowMessage;
use super::HostWindowSpace;
use super::VirtualDisplaySpace;
use crate::GpuDisplayError;

/// Responsible for capturing input from a HWND and forwarding it to the guest.
pub(crate) struct NoopMouseInputManager {}

impl NoopMouseInputManager {
    pub fn new(
        _window: &GuiWindow,
        _transform: Transform2D<f64, HostWindowSpace, VirtualDisplaySpace>,
        _virtual_display_size: Size2D<u32, VirtualDisplaySpace>,
        _display_event_dispatcher: DisplayEventDispatcher,
    ) -> Result<Self, GpuDisplayError> {
        Ok(Self {})
    }

    pub fn update_host_to_guest_transform(
        &mut self,
        _transform: Transform2D<f64, HostWindowSpace, VirtualDisplaySpace>,
    ) {
    }

    /// Possible return values:
    /// 1. `ControlFlow::Continue`, should continue invoking other modules, such as the window
    ///    manager, to perform more processing.
    /// 2. `ControlFlow::Break(Some)`, should skip any other processing and return the value.
    /// 3. `ControlFlow::Break(None)`, should immediately perform default processing.
    pub fn handle_window_message(
        &mut self,
        _window: &GuiWindow,
        _message: &WindowMessage,
    ) -> ControlFlow<Option<LRESULT>> {
        ControlFlow::Continue(())
    }
}

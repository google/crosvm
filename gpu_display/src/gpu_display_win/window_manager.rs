// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::rc::Rc;

use anyhow::Result;
use base::Tube;

use super::math_util::Size;
use super::window::GuiWindow;
use super::window_message_processor::WindowPosMessage;
use super::DisplayProperties;

pub(crate) struct NoopWindowManager {}

impl NoopWindowManager {
    /// If initialized in fullscreen mode, we would use 16:9 aspect ratio when switching to windowed
    /// mode. Note that the caller should call `set_initial_window_pos()` after window messages can
    /// be routed to `WindowManager`.
    pub fn new(
        _window: &GuiWindow,
        _display_properties: &DisplayProperties,
        _initial_host_viewport_size: Size,
        _gpu_main_display_tube: Option<Rc<Tube>>,
    ) -> Result<Self> {
        Ok(Self {})
    }

    /// This should be called only after window messages can be routed to `WindowManager`, since we
    /// rely on them to properly set the host viewport size after resizing the window.
    pub fn set_initial_window_pos(&mut self, _window: &GuiWindow) -> Result<()> {
        Ok(())
    }

    pub fn handle_display_change(&mut self, _window: &GuiWindow) {}

    pub fn handle_window_pos_message(&mut self, _window: &GuiWindow, _message: &WindowPosMessage) {}
}

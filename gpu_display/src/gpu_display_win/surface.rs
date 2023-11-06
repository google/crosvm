// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Weak;

use anyhow::Result;
use euclid::Size2D;
use linux_input_sys::virtio_input_event;
use metrics::sys::windows::Metrics;
use winapi::shared::minwindef::LRESULT;

use super::window::GuiWindow;
use super::window_message_processor::SurfaceResources;
use super::window_message_processor::WindowMessage;
use super::DisplayProperties;
use super::VirtualDisplaySpace;
use crate::EventDeviceKind;

pub struct NoopSurface {}

impl NoopSurface {
    pub fn create(
        _window: &GuiWindow,
        _virtual_display_size: &Size2D<i32, VirtualDisplaySpace>,
        _metrics: Option<Weak<Metrics>>,
        _display_properties: &DisplayProperties,
        _resources: SurfaceResources,
    ) -> Result<Self> {
        Ok(Self {})
    }

    /// Called once when it is safe to assume all future messages targeting `window` will be
    /// dispatched to this `Surface`.
    pub fn on_message_dispatcher_attached(&mut self, _window: &GuiWindow) {}

    /// Called whenever any window message is retrieved. Returns None if `DefWindowProcW()` should
    /// be called after our processing.
    pub fn handle_window_message(
        &mut self,
        _window: &GuiWindow,
        _message: WindowMessage,
    ) -> Option<LRESULT> {
        None
    }

    pub fn handle_event_device(
        &mut self,
        _window: &GuiWindow,
        _event_device_kind: EventDeviceKind,
        _event: virtio_input_event,
    ) {
    }
}

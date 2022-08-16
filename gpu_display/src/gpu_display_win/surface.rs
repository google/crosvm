// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Weak;

use anyhow::Result;
use euclid::Size2D;
use metrics::Metrics;

use super::window::Window;
use super::window_message_dispatcher::DisplayEventDispatcher;
use super::window_message_processor::HandleWindowMessage;
use super::DisplayProperties;
use super::VirtualDisplaySpace;

pub struct NoopSurface {}

impl NoopSurface {
    pub fn create(
        _window: &Window,
        _virtual_display_size: &Size2D<i32, VirtualDisplaySpace>,
        _metrics: Option<Weak<Metrics>>,
        _display_properties: &DisplayProperties,
        _display_event_dispatcher: DisplayEventDispatcher,
    ) -> Result<Self> {
        Ok(Self {})
    }
}

impl HandleWindowMessage for NoopSurface {}

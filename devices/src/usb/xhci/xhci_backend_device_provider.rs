// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use base::RawDescriptor;

use super::usb_hub::UsbHub;
use crate::usb::backend::error::Result;
use crate::utils::EventLoop;
use crate::utils::FailHandle;

/// Xhci backend provider will run on an EventLoop and connect new devices to usb ports.
pub trait XhciBackendDeviceProvider: Send + Sync {
    /// Start the provider on EventLoop.
    fn start(
        &mut self,
        fail_handle: Arc<dyn FailHandle>,
        event_loop: Arc<EventLoop>,
        hub: Arc<UsbHub>,
    ) -> Result<()>;

    /// Keep raw descriptors that should be kept open.
    fn keep_rds(&self) -> Vec<RawDescriptor>;
}

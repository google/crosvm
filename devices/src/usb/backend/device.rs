// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use usb_util::Transfer;
use usb_util::TransferBuffer;

use super::error::*;
use super::transfer::BackendTransferHandle;

use crate::utils::EventLoop;

/// Backend device trait is the interface to a generic backend usb device.
pub trait BackendDevice: Sync + Send {
    fn submit_backend_transfer(&mut self, transfer: Transfer) -> Result<BackendTransferHandle>;
    /// This is called by a generic backend provider when a USB detach message is received from the
    /// vm control socket. It detaches the backend device from the backend provider event loop.
    fn detach_event_handler(&self, event_loop: &Arc<EventLoop>) -> Result<()>;
    /// Get a buffer used for data transfer between the host and this device. The buffer returned
    /// by this function must be consumed by `submit_backend_transfer()`.
    fn request_transfer_buffer(&mut self, size: usize) -> TransferBuffer;
}

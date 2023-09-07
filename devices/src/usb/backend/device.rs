// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use usb_util::Transfer;

use super::error::*;
use super::transfer::BackendTransferHandle;

/// Backend device trait is the interface to a generic backend usb device.
pub trait BackendDevice {
    fn submit_backend_transfer(&mut self, transfer: Transfer) -> Result<BackendTransferHandle>;
}

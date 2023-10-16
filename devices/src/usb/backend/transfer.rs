// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use usb_util::UsbRequestSetup;

use crate::usb::backend::endpoint::ControlEndpointState;
use crate::usb::backend::error::Result;

/// BackendTransferHandle is a wrapper structure around a generic transfer handle whose
/// implementation depends on the backend type that is being used.
pub struct BackendTransferHandle {
    handle: Box<dyn GenericTransferHandle>,
}

impl BackendTransferHandle {
    pub fn new(handle: impl GenericTransferHandle + 'static) -> Self {
        BackendTransferHandle {
            handle: Box::new(handle),
        }
    }

    pub fn cancel(&self) -> Result<()> {
        self.handle.cancel()
    }
}

/// Generic transfer handle is a generic handle that allows for cancellation of in-flight
/// transfers. It should be implemented by all backends that need to be plugged into a generic
/// BackendTransferHandle structure.
pub trait GenericTransferHandle: Send {
    /// All objects that implement this method need to make sure `cancel()` is safe to call
    /// multiple times as its invocation should be idempotent. A transfer that has already been
    /// canceled ought not to error if it gets canceled again.
    fn cancel(&self) -> Result<()>;
}

#[derive(Copy, Clone)]
pub struct ControlTransferState {
    pub ctl_ep_state: ControlEndpointState,
    pub control_request_setup: UsbRequestSetup,
    pub executed: bool,
}

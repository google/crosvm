// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use usb_util::Transfer;
use usb_util::TransferBuffer;
use usb_util::TransferStatus;
use usb_util::UsbRequestSetup;

use crate::usb::backend::endpoint::ControlEndpointState;
use crate::usb::backend::error::Result;
use crate::usb::backend::fido_backend::transfer::FidoTransfer;

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

pub enum BackendTransferType {
    HostDevice(Transfer),
    FidoDevice(FidoTransfer),
}

/// The backend transfer trait implemention is the interface of a generic transfer structure that
/// each backend type should implement to be compatible with the generic backend device provider
/// logic.
pub trait BackendTransfer {
    /// Returns the status of the transfer in a `TransferStatus` enum
    fn status(&self) -> TransferStatus;
    /// Returns the actual amount of data transferred, which may be less than the original length.
    fn actual_length(&self) -> usize;
    /// Returns a reference to the `TransferBuffer` object.
    fn buffer(&self) -> &TransferBuffer;
    /// Sets an optional callback on the transfer to be called when the transfer completes.
    fn set_callback<C: 'static + Fn(BackendTransferType) + Send + Sync>(&mut self, cb: C);
}

// TODO(morg): refactor with multi_dispatch
impl BackendTransfer for BackendTransferType {
    fn status(&self) -> TransferStatus {
        match self {
            BackendTransferType::HostDevice(transfer) => BackendTransfer::status(transfer),
            BackendTransferType::FidoDevice(transfer) => BackendTransfer::status(transfer),
        }
    }

    fn actual_length(&self) -> usize {
        match self {
            BackendTransferType::HostDevice(transfer) => BackendTransfer::actual_length(transfer),
            BackendTransferType::FidoDevice(transfer) => BackendTransfer::actual_length(transfer),
        }
    }

    fn buffer(&self) -> &TransferBuffer {
        match self {
            BackendTransferType::HostDevice(transfer) => BackendTransfer::buffer(transfer),
            BackendTransferType::FidoDevice(transfer) => BackendTransfer::buffer(transfer),
        }
    }

    fn set_callback<C: 'static + Fn(BackendTransferType) + Send + Sync>(&mut self, cb: C) {
        match self {
            BackendTransferType::HostDevice(transfer) => {
                BackendTransfer::set_callback(transfer, cb)
            }
            BackendTransferType::FidoDevice(transfer) => {
                BackendTransfer::set_callback(transfer, cb)
            }
        }
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

// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Weak;
use std::time::Instant;

use base::error;
use base::Clock;
use sync::Mutex;
use usb_util::TransferBuffer;
use usb_util::TransferStatus;

use crate::usb::backend::error::Error as BackendError;
use crate::usb::backend::error::Result as BackendResult;
use crate::usb::backend::fido_backend::constants::USB_TRANSFER_TIMEOUT_MILLIS;
use crate::usb::backend::transfer::BackendTransfer;
use crate::usb::backend::transfer::BackendTransferType;
use crate::usb::backend::transfer::GenericTransferHandle;

/// Implementation of a generic USB transfer for the FIDO backend. It implements common USB
/// transfer functionality since it cannot rely on the transfer structures provided by the
/// usb_utils crate as the FIDO backend does not use usbdevfs to communicate with the host.
pub struct FidoTransfer {
    /// TransferBuffer structure with either a request or response data from the guest/host.
    pub buffer: TransferBuffer,
    /// Status of the transfer, used by the xhci layer for a successful completion.
    status: TransferStatus,
    /// Actual length of the transfer, as per USB specs.
    pub actual_length: usize,
    /// USB endpoint associated with this transfer.
    pub endpoint: u8,
    /// Timestamp of the transfer submission time.
    submission_time: Instant,
    /// Callback to be executed once the transfer has completed, to signal the xhci layer.
    pub callback: Option<Box<dyn Fn(FidoTransfer) + Send + Sync>>,
}

impl FidoTransfer {
    pub fn new(endpoint: u8, buffer: TransferBuffer) -> FidoTransfer {
        let clock = Clock::new();
        FidoTransfer {
            buffer,
            status: TransferStatus::Error, // Default to error
            actual_length: 0,
            endpoint,
            submission_time: clock.now(),
            callback: None,
        }
    }

    /// Called when the device is lost and we need to signal to the xhci layer that the transfer
    /// cannot continue and the device should be detached.
    pub fn signal_device_lost(&mut self) {
        self.status = TransferStatus::NoDevice;
    }

    /// Checks if the current transfer should time out or not
    pub fn timeout_expired(&self) -> bool {
        self.submission_time.elapsed().as_millis() >= USB_TRANSFER_TIMEOUT_MILLIS.into()
    }

    /// Finalizes the transfer by setting the right status and then calling the callback to signal
    /// the xhci layer.
    pub fn complete_transfer(mut self) {
        // The default status is "Error". Unless it was explicitly set to Cancel or NoDevice,
        // we can just transition it to Completed instead.
        if self.status == TransferStatus::Error {
            self.status = TransferStatus::Completed;
        }

        if let Some(cb) = self.callback.take() {
            cb(self);
        }
    }
}

impl BackendTransfer for FidoTransfer {
    fn status(&self) -> TransferStatus {
        self.status
    }

    fn actual_length(&self) -> usize {
        self.actual_length
    }

    fn buffer(&self) -> &TransferBuffer {
        &self.buffer
    }

    fn set_callback<C: 'static + Fn(BackendTransferType) + Send + Sync>(&mut self, cb: C) {
        let callback = move |t: FidoTransfer| cb(BackendTransferType::FidoDevice(t));
        self.callback = Some(Box::new(callback));
    }
}

/// Implementation of a cancel handler for `FidoTransfer`
pub struct FidoTransferHandle {
    pub weak_transfer: Weak<Mutex<Option<FidoTransfer>>>,
}

impl GenericTransferHandle for FidoTransferHandle {
    fn cancel(&self) -> BackendResult<()> {
        let rc_transfer = match self.weak_transfer.upgrade() {
            None => {
                return Err(BackendError::TransferHandleAlreadyComplete);
            }
            Some(rc_transfer) => rc_transfer,
        };

        let mut lock = rc_transfer.lock();

        let mut transfer = match lock.take() {
            Some(t) => t,
            None => {
                error!("Transfer has already been lost while being cancelled. Ignore");
                return Err(BackendError::TransferHandleAlreadyComplete);
            }
        };
        transfer.status = TransferStatus::Cancelled;
        *lock = Some(transfer);
        Ok(())
    }
}

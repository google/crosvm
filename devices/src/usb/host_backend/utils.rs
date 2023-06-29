// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem;
use std::sync::Arc;

use base::debug;
use base::error;
use base::warn;
use usb_util::Device;
use usb_util::Transfer;
use usb_util::TransferStatus;

use super::error::*;
use crate::usb::xhci::xhci_transfer::XhciTransfer;
use crate::usb::xhci::xhci_transfer::XhciTransferState;
use crate::utils::AsyncJobQueue;
use crate::utils::FailHandle;

/// Helper function to update xhci_transfer state.
pub fn update_transfer_state(
    xhci_transfer: &Arc<XhciTransfer>,
    usb_transfer: &Transfer,
) -> Result<()> {
    let status = usb_transfer.status();
    let mut state = xhci_transfer.state().lock();

    if status == TransferStatus::Cancelled {
        *state = XhciTransferState::Cancelled;
        return Ok(());
    }

    match *state {
        XhciTransferState::Cancelling => {
            *state = XhciTransferState::Cancelled;
        }
        XhciTransferState::Submitted { .. } => {
            *state = XhciTransferState::Completed;
        }
        _ => {
            error!("xhci trasfer state is invalid");
            *state = XhciTransferState::Completed;
            return Err(Error::BadXhciTransferState);
        }
    }
    Ok(())
}

/// Helper function to submit usb_transfer to device handle.
pub fn submit_transfer(
    fail_handle: Arc<dyn FailHandle>,
    job_queue: &Arc<AsyncJobQueue>,
    xhci_transfer: Arc<XhciTransfer>,
    device: &mut Device,
    usb_transfer: Transfer,
) -> Result<()> {
    let transfer_status = {
        // We need to hold the lock to avoid race condition.
        // While we are trying to submit the transfer, another thread might want to cancel the same
        // transfer. Holding the lock here makes sure one of them is cancelled.
        let mut state = xhci_transfer.state().lock();
        match mem::replace(&mut *state, XhciTransferState::Cancelled) {
            XhciTransferState::Created => {
                match device.submit_transfer(usb_transfer) {
                    Err(e) => {
                        error!("fail to submit transfer {:?}", e);
                        *state = XhciTransferState::Completed;
                        TransferStatus::NoDevice
                    }
                    // If it's submitted, we don't need to send on_transfer_complete now.
                    Ok(canceller) => {
                        let cancel_callback = Box::new(move || match canceller.cancel() {
                            Ok(()) => {
                                debug!("cancel issued to kernel");
                            }
                            Err(e) => {
                                error!("failed to cancel XhciTransfer: {}", e);
                            }
                        });
                        *state = XhciTransferState::Submitted { cancel_callback };
                        return Ok(());
                    }
                }
            }
            XhciTransferState::Cancelled => {
                warn!("Transfer is already cancelled");
                TransferStatus::Cancelled
            }
            _ => {
                // The transfer could not be in the following states:
                // Submitted: A transfer should only be submitted once.
                // Cancelling: Transfer is cancelling only when it's submitted and someone is
                // trying to cancel it.
                // Completed: A completed transfer should not be submitted again.
                error!("xhci trasfer state is invalid");
                return Err(Error::BadXhciTransferState);
            }
        }
    };
    // We are holding locks to of backends, we want to call on_transfer_complete
    // without any lock.
    job_queue
        .queue_job(
            move || match xhci_transfer.on_transfer_complete(&transfer_status, 0) {
                Ok(_) => {}
                Err(e) => {
                    error!("transfer complete failed: {:?}", e);
                    fail_handle.fail();
                }
            },
        )
        .map_err(Error::QueueAsyncJob)
}

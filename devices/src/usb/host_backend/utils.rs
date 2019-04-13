// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem;
use std::sync::Arc;
use sync::Mutex;

use super::error::*;
use crate::usb::xhci::xhci_transfer::{XhciTransfer, XhciTransferState};
use crate::utils::AsyncJobQueue;
use crate::utils::FailHandle;
use sys_util::{error, warn};
use usb_util::device_handle::DeviceHandle;
use usb_util::usb_transfer::{TransferStatus, UsbTransfer, UsbTransferBuffer};

/// Helper function to update xhci_transfer state.
pub fn update_transfer_state<T: UsbTransferBuffer>(
    xhci_transfer: &Arc<XhciTransfer>,
    usb_transfer: &UsbTransfer<T>,
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
pub fn submit_transfer<T: UsbTransferBuffer>(
    fail_handle: Arc<dyn FailHandle>,
    job_queue: &Arc<AsyncJobQueue>,
    xhci_transfer: Arc<XhciTransfer>,
    device_handle: &Arc<Mutex<DeviceHandle>>,
    usb_transfer: UsbTransfer<T>,
) -> Result<()> {
    let transfer_status = {
        // We need to hold the lock to avoid race condition.
        // While we are trying to submit the transfer, another thread might want to cancel the same
        // transfer. Holding the lock here makes sure one of them is cancelled.
        let mut state = xhci_transfer.state().lock();
        match mem::replace(&mut *state, XhciTransferState::Cancelled) {
            XhciTransferState::Created => {
                let canceller = usb_transfer.get_canceller();
                // TODO(jkwang) refactor canceller to return Cancel::Ok or Cancel::Err.
                let cancel_callback = Box::new(move || match canceller.try_cancel() {
                    true => {
                        usb_debug!("cancel issued to libusb backend");
                    }
                    false => {
                        usb_debug!("fail to cancel");
                    }
                });
                *state = XhciTransferState::Submitted { cancel_callback };
                match device_handle.lock().submit_async_transfer(usb_transfer) {
                    Err(e) => {
                        error!("fail to submit transfer {:?}", e);
                        *state = XhciTransferState::Completed;
                        TransferStatus::NoDevice
                    }
                    // If it's submitted, we don't need to send on_transfer_complete now.
                    Ok(_) => return Ok(()),
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

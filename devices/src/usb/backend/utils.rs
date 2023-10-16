// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use anyhow::Context;
use base::error;
use sync::Mutex;
use usb_util::Transfer;
use usb_util::TransferStatus;

use crate::usb::backend::device::BackendDeviceType;
use crate::usb::backend::error::Error;
use crate::usb::backend::error::Result;
use crate::usb::xhci::xhci_transfer::XhciTransfer;
use crate::usb::xhci::xhci_transfer::XhciTransferState;
use crate::utils::EventHandler;

pub struct UsbUtilEventHandler {
    pub device: Arc<Mutex<BackendDeviceType>>,
}

impl EventHandler for UsbUtilEventHandler {
    fn on_event(&self) -> anyhow::Result<()> {
        match &mut *self.device.lock() {
            BackendDeviceType::HostDevice(host_device) => host_device
                .device
                .lock()
                .poll_transfers()
                .context("UsbUtilEventHandler poll_transfers failed"),
        }
    }
}

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

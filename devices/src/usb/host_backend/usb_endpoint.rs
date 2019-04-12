// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp;
use std::sync::Arc;
use sync::Mutex;

use super::error::*;
use super::utils::{submit_transfer, update_transfer_state};
use crate::usb::xhci::scatter_gather_buffer::ScatterGatherBuffer;
use crate::usb::xhci::xhci_transfer::{
    TransferDirection, XhciTransfer, XhciTransferState, XhciTransferType,
};
use crate::utils::AsyncJobQueue;
use crate::utils::FailHandle;
use sys_util::error;
use usb_util::device_handle::DeviceHandle;
use usb_util::types::{EndpointDirection, EndpointType, ENDPOINT_DIRECTION_OFFSET};
use usb_util::usb_transfer::{
    bulk_transfer, interrupt_transfer, BulkTransferBuffer, TransferStatus, UsbTransfer,
};

/// Isochronous, Bulk or Interrupt endpoint.
pub struct UsbEndpoint {
    fail_handle: Arc<dyn FailHandle>,
    job_queue: Arc<AsyncJobQueue>,
    device_handle: Arc<Mutex<DeviceHandle>>,
    endpoint_number: u8,
    direction: EndpointDirection,
    ty: EndpointType,
}

impl UsbEndpoint {
    /// Create new endpoint. This function will panic if endpoint type is control.
    pub fn new(
        fail_handle: Arc<dyn FailHandle>,
        job_queue: Arc<AsyncJobQueue>,
        device_handle: Arc<Mutex<DeviceHandle>>,
        endpoint_number: u8,
        direction: EndpointDirection,
        ty: EndpointType,
    ) -> UsbEndpoint {
        assert!(ty != EndpointType::Control);
        UsbEndpoint {
            fail_handle,
            job_queue,
            device_handle,
            endpoint_number,
            direction,
            ty,
        }
    }

    fn ep_addr(&self) -> u8 {
        self.endpoint_number | ((self.direction as u8) << ENDPOINT_DIRECTION_OFFSET)
    }

    /// Returns true is this endpoint matches number and direction.
    pub fn match_ep(&self, endpoint_number: u8, dir: TransferDirection) -> bool {
        let self_dir = match self.direction {
            EndpointDirection::HostToDevice => TransferDirection::Out,
            EndpointDirection::DeviceToHost => TransferDirection::In,
        };
        self.endpoint_number == endpoint_number && self_dir == dir
    }

    /// Handle a xhci transfer.
    pub fn handle_transfer(&self, transfer: XhciTransfer) -> Result<()> {
        let buffer = match transfer
            .get_transfer_type()
            .map_err(Error::GetXhciTransferType)?
        {
            XhciTransferType::Normal(buffer) => buffer,
            XhciTransferType::Noop => {
                return transfer
                    .on_transfer_complete(&TransferStatus::Completed, 0)
                    .map_err(Error::TransferComplete);
            }
            _ => {
                error!("unhandled xhci transfer type by usb endpoint");
                return transfer
                    .on_transfer_complete(&TransferStatus::Error, 0)
                    .map_err(Error::TransferComplete);
            }
        };

        match self.ty {
            EndpointType::Bulk => {
                self.handle_bulk_transfer(transfer, buffer)?;
            }
            EndpointType::Interrupt => {
                self.handle_interrupt_transfer(transfer, buffer)?;
            }
            _ => {
                return transfer
                    .on_transfer_complete(&TransferStatus::Error, 0)
                    .map_err(Error::TransferComplete);
            }
        }
        Ok(())
    }

    fn handle_bulk_transfer(
        &self,
        xhci_transfer: XhciTransfer,
        buffer: ScatterGatherBuffer,
    ) -> Result<()> {
        let usb_transfer =
            bulk_transfer(self.ep_addr(), 0, buffer.len().map_err(Error::BufferLen)?);
        self.do_handle_transfer(xhci_transfer, usb_transfer, buffer)
    }

    fn handle_interrupt_transfer(
        &self,
        xhci_transfer: XhciTransfer,
        buffer: ScatterGatherBuffer,
    ) -> Result<()> {
        let usb_transfer =
            interrupt_transfer(self.ep_addr(), 0, buffer.len().map_err(Error::BufferLen)?);
        self.do_handle_transfer(xhci_transfer, usb_transfer, buffer)
    }

    fn do_handle_transfer(
        &self,
        xhci_transfer: XhciTransfer,
        mut usb_transfer: UsbTransfer<BulkTransferBuffer>,
        buffer: ScatterGatherBuffer,
    ) -> Result<()> {
        let xhci_transfer = Arc::new(xhci_transfer);
        let tmp_transfer = xhci_transfer.clone();
        match self.direction {
            EndpointDirection::HostToDevice => {
                // Read data from ScatterGatherBuffer to a continuous memory.
                buffer
                    .read(usb_transfer.buffer_mut().as_mut_slice())
                    .map_err(Error::ReadBuffer)?;
                usb_debug!(
                    "out transfer ep_addr {:#x}, buffer len {:?}, data {:#x?}",
                    self.ep_addr(),
                    buffer.len(),
                    usb_transfer.buffer_mut().as_mut_slice()
                );
                let callback = move |t: UsbTransfer<BulkTransferBuffer>| {
                    usb_debug!("out transfer callback");
                    update_transfer_state(&xhci_transfer, &t)?;
                    let state = xhci_transfer.state().lock();
                    match *state {
                        XhciTransferState::Cancelled => {
                            usb_debug!("transfer has been cancelled");
                            drop(state);
                            xhci_transfer
                                .on_transfer_complete(&TransferStatus::Cancelled, 0)
                                .map_err(Error::TransferComplete)
                        }
                        XhciTransferState::Completed => {
                            let status = t.status();
                            let actual_length = t.actual_length();
                            drop(state);
                            xhci_transfer
                                .on_transfer_complete(&status, actual_length as u32)
                                .map_err(Error::TransferComplete)
                        }
                        _ => {
                            error!("xhci trasfer state (host to device) is invalid");
                            Err(Error::BadXhciTransferState)
                        }
                    }
                };
                let fail_handle = self.fail_handle.clone();
                usb_transfer.set_callback(
                    move |t: UsbTransfer<BulkTransferBuffer>| match callback(t) {
                        Ok(_) => {}
                        Err(e) => {
                            error!("bulk transfer callback failed: {:?}", e);
                            fail_handle.fail();
                        }
                    },
                );
                submit_transfer(
                    self.fail_handle.clone(),
                    &self.job_queue,
                    tmp_transfer,
                    &self.device_handle,
                    usb_transfer,
                )?;
            }
            EndpointDirection::DeviceToHost => {
                usb_debug!(
                    "in transfer ep_addr {:#x}, buffer len {:?}",
                    self.ep_addr(),
                    buffer.len()
                );
                let _addr = self.ep_addr();
                let callback = move |t: UsbTransfer<BulkTransferBuffer>| {
                    usb_debug!(
                        "ep {:#x} in transfer data {:?}",
                        _addr,
                        t.buffer().as_slice()
                    );
                    update_transfer_state(&xhci_transfer, &t)?;
                    let state = xhci_transfer.state().lock();
                    match *state {
                        XhciTransferState::Cancelled => {
                            usb_debug!("transfer has been cancelled");
                            drop(state);
                            xhci_transfer
                                .on_transfer_complete(&TransferStatus::Cancelled, 0)
                                .map_err(Error::TransferComplete)
                        }
                        XhciTransferState::Completed => {
                            let status = t.status();
                            let actual_length = t.actual_length() as usize;
                            let copied_length = buffer
                                .write(t.buffer().as_slice())
                                .map_err(Error::WriteBuffer)?;
                            let actual_length = cmp::min(actual_length, copied_length);
                            drop(state);
                            xhci_transfer
                                .on_transfer_complete(&status, actual_length as u32)
                                .map_err(Error::TransferComplete)
                        }
                        _ => {
                            // update state is already invoked. This match should not be in any
                            // other state.
                            error!("xhci trasfer state (device to host) is invalid");
                            Err(Error::BadXhciTransferState)
                        }
                    }
                };
                let fail_handle = self.fail_handle.clone();

                usb_transfer.set_callback(
                    move |t: UsbTransfer<BulkTransferBuffer>| match callback(t) {
                        Ok(_) => {}
                        Err(e) => {
                            error!("bulk transfer callback {:?}", e);
                            fail_handle.fail();
                        }
                    },
                );

                submit_transfer(
                    self.fail_handle.clone(),
                    &self.job_queue,
                    tmp_transfer,
                    &self.device_handle,
                    usb_transfer,
                )?;
            }
        }
        Ok(())
    }
}

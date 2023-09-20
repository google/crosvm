// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp;
use std::sync::Arc;

use base::debug;
use base::error;
use usb_util::EndpointDirection;
use usb_util::EndpointType;
use usb_util::Transfer;
use usb_util::TransferBuffer;
use usb_util::TransferStatus;
use usb_util::ENDPOINT_DIRECTION_OFFSET;

use crate::usb::backend::device::BackendDevice;
use crate::usb::backend::error::*;
use crate::usb::backend::utils::submit_transfer;
use crate::usb::backend::utils::update_transfer_state;
use crate::usb::xhci::scatter_gather_buffer::ScatterGatherBuffer;
use crate::usb::xhci::xhci_transfer::TransferDirection;
use crate::usb::xhci::xhci_transfer::XhciTransfer;
use crate::usb::xhci::xhci_transfer::XhciTransferState;
use crate::usb::xhci::xhci_transfer::XhciTransferType;
use crate::utils::AsyncJobQueue;
use crate::utils::FailHandle;

/// Isochronous, Bulk or Interrupt endpoint.
pub struct UsbEndpoint {
    fail_handle: Arc<dyn FailHandle>,
    job_queue: Arc<AsyncJobQueue>,
    endpoint_number: u8,
    direction: EndpointDirection,
    ty: EndpointType,
}

impl UsbEndpoint {
    /// Create new endpoint. This function will panic if endpoint type is control.
    pub fn new(
        fail_handle: Arc<dyn FailHandle>,
        job_queue: Arc<AsyncJobQueue>,
        endpoint_number: u8,
        direction: EndpointDirection,
        ty: EndpointType,
    ) -> UsbEndpoint {
        assert!(ty != EndpointType::Control);
        UsbEndpoint {
            fail_handle,
            job_queue,
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
    pub fn handle_transfer(
        &self,
        device: &mut impl BackendDevice,
        transfer: XhciTransfer,
    ) -> Result<()> {
        let buffer = match transfer
            .get_transfer_type()
            .map_err(Error::GetXhciTransferType)?
        {
            XhciTransferType::Normal => transfer.create_buffer().map_err(Error::CreateBuffer)?,
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
                self.handle_bulk_transfer(device, transfer, buffer)?;
            }
            EndpointType::Interrupt => {
                self.handle_interrupt_transfer(device, transfer, buffer)?;
            }
            _ => {
                return transfer
                    .on_transfer_complete(&TransferStatus::Error, 0)
                    .map_err(Error::TransferComplete);
            }
        }
        Ok(())
    }

    fn get_transfer_buffer(
        &self,
        buffer: &ScatterGatherBuffer,
        device: &mut impl BackendDevice,
    ) -> Result<TransferBuffer> {
        let len = buffer.len().map_err(Error::BufferLen)?;
        let mut buf = device.request_transfer_buffer(len);
        if self.direction == EndpointDirection::HostToDevice {
            // Read data from ScatterGatherBuffer to a continuous memory.
            match &mut buf {
                TransferBuffer::Dma(dmabuf) => {
                    if let Some(buf) = dmabuf.upgrade() {
                        buffer
                            .read(buf.lock().as_mut_slice())
                            .map_err(Error::ReadBuffer)?;
                    } else {
                        return Err(Error::GetDmaBuffer);
                    }
                }
                TransferBuffer::Vector(v) => {
                    buffer.read(v.as_mut_slice()).map_err(Error::ReadBuffer)?;
                }
            }
        }
        Ok(buf)
    }

    fn handle_bulk_transfer(
        &self,
        device: &mut impl BackendDevice,
        xhci_transfer: XhciTransfer,
        buffer: ScatterGatherBuffer,
    ) -> Result<()> {
        let transfer_buffer = self.get_transfer_buffer(&buffer, device)?;
        let usb_transfer = Transfer::new_bulk(
            self.ep_addr(),
            transfer_buffer,
            xhci_transfer.get_stream_id(),
        )
        .map_err(Error::CreateTransfer)?;
        self.do_handle_transfer(device, xhci_transfer, usb_transfer, buffer)
    }

    fn handle_interrupt_transfer(
        &self,
        device: &mut impl BackendDevice,
        xhci_transfer: XhciTransfer,
        buffer: ScatterGatherBuffer,
    ) -> Result<()> {
        let transfer_buffer = self.get_transfer_buffer(&buffer, device)?;
        let usb_transfer = Transfer::new_interrupt(self.ep_addr(), transfer_buffer)
            .map_err(Error::CreateTransfer)?;
        self.do_handle_transfer(device, xhci_transfer, usb_transfer, buffer)
    }

    fn do_handle_transfer(
        &self,
        device: &mut impl BackendDevice,
        xhci_transfer: XhciTransfer,
        mut usb_transfer: Transfer,
        buffer: ScatterGatherBuffer,
    ) -> Result<()> {
        let xhci_transfer = Arc::new(xhci_transfer);
        let tmp_transfer = xhci_transfer.clone();
        match self.direction {
            EndpointDirection::HostToDevice => {
                let _trace = cros_tracing::trace_event!(
                    USB,
                    "Endpoint out transfer",
                    self.ep_addr(),
                    buffer.len()
                );
                let callback = move |t: Transfer| {
                    update_transfer_state(&xhci_transfer, &t)?;
                    let state = xhci_transfer.state().lock();
                    match *state {
                        XhciTransferState::Cancelled => {
                            debug!("Xhci transfer has been cancelled");
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
                usb_transfer.set_callback(move |t: Transfer| match callback(t) {
                    Ok(_) => {}
                    Err(e) => {
                        error!("bulk transfer callback failed: {:?}", e);
                        fail_handle.fail();
                    }
                });
                submit_transfer(
                    self.fail_handle.clone(),
                    &self.job_queue,
                    tmp_transfer,
                    device,
                    usb_transfer,
                )?;
            }
            EndpointDirection::DeviceToHost => {
                let _trace = cros_tracing::trace_event!(
                    USB,
                    "Endpoint in transfer",
                    self.ep_addr(),
                    buffer.len()
                );
                let _addr = self.ep_addr();
                let callback = move |t: Transfer| {
                    update_transfer_state(&xhci_transfer, &t)?;
                    let state = xhci_transfer.state().lock();
                    match *state {
                        XhciTransferState::Cancelled => {
                            debug!("Xhci transfer has been cancelled");
                            drop(state);
                            xhci_transfer
                                .on_transfer_complete(&TransferStatus::Cancelled, 0)
                                .map_err(Error::TransferComplete)
                        }
                        XhciTransferState::Completed => {
                            let status = t.status();
                            let actual_length = t.actual_length();
                            let copied_length = match t.buffer {
                                TransferBuffer::Vector(v) => {
                                    buffer.write(v.as_slice()).map_err(Error::WriteBuffer)?
                                }
                                TransferBuffer::Dma(buf) => {
                                    if let Some(buf) = buf.upgrade() {
                                        buffer
                                            .write(buf.lock().as_slice())
                                            .map_err(Error::WriteBuffer)?
                                    } else {
                                        return Err(Error::GetDmaBuffer);
                                    }
                                }
                            };
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

                usb_transfer.set_callback(move |t: Transfer| match callback(t) {
                    Ok(_) => {}
                    Err(e) => {
                        error!("bulk transfer callback {:?}", e);
                        fail_handle.fail();
                    }
                });

                submit_transfer(
                    self.fail_handle.clone(),
                    &self.job_queue,
                    tmp_transfer,
                    device,
                    usb_transfer,
                )?;
            }
        }
        Ok(())
    }
}

// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::interrupter::{Error as InterrupterError, Interrupter};
use super::scatter_gather_buffer::{Error as BufferError, ScatterGatherBuffer};
use super::usb_hub::{Error as HubError, UsbPort};
use super::xhci_abi::{
    AddressedTrb, Error as TrbError, EventDataTrb, SetupStageTrb, TransferDescriptor, TrbCast,
    TrbCompletionCode, TrbType,
};
use super::xhci_regs::MAX_INTERRUPTER;
use bit_field::Error as BitFieldError;
use std::cmp::min;
use std::fmt::{self, Display};
use std::mem;
use std::sync::{Arc, Weak};
use sync::Mutex;
use sys_util::{error, Error as SysError, EventFd, GuestMemory};
use usb_util::types::UsbRequestSetup;
use usb_util::usb_transfer::TransferStatus;

#[derive(Debug)]
pub enum Error {
    TrbType(BitFieldError),
    CastTrb(TrbError),
    TransferLength(TrbError),
    BadTrbType(TrbType),
    WriteCompletionEvent(SysError),
    CreateBuffer(BufferError),
    DetachPort(HubError),
    SendInterrupt(InterrupterError),
    SubmitTransfer,
}

type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            TrbType(e) => write!(f, "cannot get trb type: {}", e),
            CastTrb(e) => write!(f, "cannot cast trb: {}", e),
            TransferLength(e) => write!(f, "cannot get transfer length: {}", e),
            BadTrbType(t) => write!(f, "unexpected trb type: {:?}", t),
            WriteCompletionEvent(e) => write!(f, "cannot write completion event: {}", e),
            CreateBuffer(e) => write!(f, "cannot create transfer buffer: {}", e),
            DetachPort(e) => write!(f, "cannot detach from port: {}", e),
            SendInterrupt(e) => write!(f, "cannot send interrupter: {}", e),
            SubmitTransfer => write!(f, "failed to submit transfer to backend"),
        }
    }
}

/// Type of usb endpoints.
#[derive(PartialEq, Clone, Copy, Debug)]
pub enum TransferDirection {
    In,
    Out,
    Control,
}

/// Current state of xhci transfer.
pub enum XhciTransferState {
    Created,
    /// When transfer is submitted, it will contain a transfer callback, which should be invoked
    /// when the transfer is cancelled.
    Submitted {
        cancel_callback: Box<dyn FnMut() + Send>,
    },
    Cancelling,
    Cancelled,
    Completed,
}

impl XhciTransferState {
    /// Try to cancel this transfer, if it's possible.
    pub fn try_cancel(&mut self) {
        match mem::replace(self, XhciTransferState::Created) {
            XhciTransferState::Submitted {
                mut cancel_callback,
            } => {
                *self = XhciTransferState::Cancelling;
                cancel_callback();
            }
            XhciTransferState::Cancelling => {
                error!("Another cancellation is already issued.");
            }
            _ => {
                *self = XhciTransferState::Cancelled;
            }
        }
    }
}

/// Type of a transfer received handled by transfer ring.
pub enum XhciTransferType {
    // Normal means bulk transfer or interrupt transfer, depending on endpoint type.
    // See spec 4.11.2.1.
    Normal(ScatterGatherBuffer),
    // See usb spec for setup stage, data stage and status stage,
    // see xHCI spec 4.11.2.2 for corresponding trbs.
    SetupStage(UsbRequestSetup),
    DataStage(ScatterGatherBuffer),
    StatusStage,
    // See xHCI spec 4.11.2.3.
    Isochronous(ScatterGatherBuffer),
    // See xHCI spec 6.4.1.4.
    Noop,
}

impl XhciTransferType {
    /// Analyze transfer descriptor and return transfer type.
    pub fn new(mem: GuestMemory, td: TransferDescriptor) -> Result<XhciTransferType> {
        // We can figure out transfer type from the first trb.
        // See transfer descriptor description in xhci spec for more details.
        match td[0].trb.get_trb_type().map_err(Error::TrbType)? {
            TrbType::Normal => {
                let buffer = ScatterGatherBuffer::new(mem, td).map_err(Error::CreateBuffer)?;
                Ok(XhciTransferType::Normal(buffer))
            }
            TrbType::SetupStage => {
                let trb = td[0].trb.cast::<SetupStageTrb>().map_err(Error::CastTrb)?;
                Ok(XhciTransferType::SetupStage(UsbRequestSetup::new(
                    trb.get_request_type(),
                    trb.get_request(),
                    trb.get_value(),
                    trb.get_index(),
                    trb.get_length(),
                )))
            }
            TrbType::DataStage => {
                let buffer = ScatterGatherBuffer::new(mem, td).map_err(Error::CreateBuffer)?;
                Ok(XhciTransferType::DataStage(buffer))
            }
            TrbType::StatusStage => Ok(XhciTransferType::StatusStage),
            TrbType::Isoch => {
                let buffer = ScatterGatherBuffer::new(mem, td).map_err(Error::CreateBuffer)?;
                Ok(XhciTransferType::Isochronous(buffer))
            }
            TrbType::Noop => Ok(XhciTransferType::Noop),
            t => Err(Error::BadTrbType(t)),
        }
    }
}

/// Xhci Transfer manager holds reference to all ongoing transfers. Can cancel them all if
/// needed.
#[derive(Clone)]
pub struct XhciTransferManager {
    transfers: Arc<Mutex<Vec<Weak<Mutex<XhciTransferState>>>>>,
}

impl XhciTransferManager {
    /// Create a new manager.
    pub fn new() -> XhciTransferManager {
        XhciTransferManager {
            transfers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Build a new XhciTransfer. Endpoint id is the id in xHCI device slot.
    pub fn create_transfer(
        &self,
        mem: GuestMemory,
        port: Arc<UsbPort>,
        interrupter: Arc<Mutex<Interrupter>>,
        slot_id: u8,
        endpoint_id: u8,
        transfer_trbs: TransferDescriptor,
        completion_event: EventFd,
    ) -> XhciTransfer {
        assert!(!transfer_trbs.is_empty());
        let transfer_dir = {
            if endpoint_id == 0 {
                TransferDirection::Control
            } else if (endpoint_id % 2) == 0 {
                TransferDirection::Out
            } else {
                TransferDirection::In
            }
        };
        let t = XhciTransfer {
            manager: self.clone(),
            state: Arc::new(Mutex::new(XhciTransferState::Created)),
            mem,
            port,
            interrupter,
            transfer_completion_event: completion_event,
            slot_id,
            endpoint_id,
            transfer_dir,
            transfer_trbs,
        };
        self.transfers.lock().push(Arc::downgrade(&t.state));
        t
    }

    /// Cancel all current transfers.
    pub fn cancel_all(&self) {
        self.transfers.lock().iter().for_each(|t| {
            let state = match t.upgrade() {
                Some(state) => state,
                None => {
                    error!("transfer is already cancelled or finished");
                    return;
                }
            };
            state.lock().try_cancel();
        });
    }

    fn remove_transfer(&self, t: &Arc<Mutex<XhciTransferState>>) {
        let mut transfers = self.transfers.lock();
        match transfers.iter().position(|wt| match wt.upgrade() {
            Some(wt) => Arc::ptr_eq(&wt, t),
            None => false,
        }) {
            None => error!("attempted to remove unknow transfer"),
            Some(i) => {
                transfers.swap_remove(i);
            }
        }
    }
}

/// Xhci transfer denotes a transfer initiated by guest os driver. It will be submitted to a
/// XhciBackendDevice.
pub struct XhciTransfer {
    manager: XhciTransferManager,
    state: Arc<Mutex<XhciTransferState>>,
    mem: GuestMemory,
    port: Arc<UsbPort>,
    interrupter: Arc<Mutex<Interrupter>>,
    slot_id: u8,
    // id of endpoint in device slot.
    endpoint_id: u8,
    transfer_dir: TransferDirection,
    transfer_trbs: TransferDescriptor,
    transfer_completion_event: EventFd,
}

impl Drop for XhciTransfer {
    fn drop(&mut self) {
        self.manager.remove_transfer(&self.state);
    }
}

impl fmt::Debug for XhciTransfer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "xhci_transfer slot id: {}, endpoint id {}, transfer_dir {:?}, transfer_trbs {:?}",
            self.slot_id, self.endpoint_id, self.transfer_dir, self.transfer_trbs
        )
    }
}

impl XhciTransfer {
    /// Get state of this transfer.
    pub fn state(&self) -> &Arc<Mutex<XhciTransferState>> {
        &self.state
    }

    /// Get transfer type.
    pub fn get_transfer_type(&self) -> Result<XhciTransferType> {
        XhciTransferType::new(self.mem.clone(), self.transfer_trbs.clone())
    }

    /// Get endpoint number.
    pub fn get_endpoint_number(&self) -> u8 {
        // See spec 4.5.1 for dci.
        self.endpoint_id / 2
    }

    /// get transfer direction.
    pub fn get_transfer_dir(&self) -> TransferDirection {
        self.transfer_dir
    }

    /// This functions should be invoked when transfer is completed (or failed).
    pub fn on_transfer_complete(
        &self,
        status: &TransferStatus,
        bytes_transferred: u32,
    ) -> Result<()> {
        match status {
            TransferStatus::NoDevice => {
                usb_debug!("device disconnected, detaching from port");
                // If the device is gone, we don't need to send transfer completion event, cause we
                // are going to destroy everything related to this device anyway.
                self.port.detach().map_err(Error::DetachPort)?;
                return Ok(());
            }
            TransferStatus::Cancelled => {
                // TODO(jkwang) According to the spec, we should send a stopped event here. But
                // kernel driver does not do anything meaningful when it sees a stopped event.
                return self
                    .transfer_completion_event
                    .write(1)
                    .map_err(Error::WriteCompletionEvent);
            }
            TransferStatus::Completed => {
                self.transfer_completion_event
                    .write(1)
                    .map_err(Error::WriteCompletionEvent)?;
            }
            _ => {
                // Transfer failed, we are not handling this correctly yet. Guest kernel might see
                // short packets for in transfer and might think control transfer is successful. It
                // will eventually find out device is in a wrong state.
                self.transfer_completion_event
                    .write(1)
                    .map_err(Error::WriteCompletionEvent)?;
            }
        }

        let mut edtla: u32 = 0;
        // As noted in xHCI spec 4.11.3.1
        // Transfer Event TRB only occurs under the following conditions:
        //   1. If the Interrupt On Completion flag is set.
        //   2. When a short transfer occurs during the execution of a Transfer TRB and the
        //      Interrupt-on-Short Packet flag is set.
        //   3. If an error occurs during the execution of a Transfer TRB.
        // Errors are handled above, so just check for the two flags.
        for atrb in &self.transfer_trbs {
            edtla += atrb.trb.transfer_length().map_err(Error::TransferLength)?;
            if atrb.trb.interrupt_on_completion()
                || (atrb.trb.interrupt_on_short_packet() && edtla > bytes_transferred)
            {
                // For details about event data trb and EDTLA, see spec 4.11.5.2.
                if atrb.trb.get_trb_type().map_err(Error::TrbType)? == TrbType::EventData {
                    let tlength = min(edtla, bytes_transferred);
                    self.interrupter
                        .lock()
                        .send_transfer_event_trb(
                            TrbCompletionCode::Success,
                            atrb.trb
                                .cast::<EventDataTrb>()
                                .map_err(Error::CastTrb)?
                                .get_event_data(),
                            tlength,
                            true,
                            self.slot_id,
                            self.endpoint_id,
                        )
                        .map_err(Error::SendInterrupt)?;
                } else {
                    // For Short Transfer details, see xHCI spec 4.10.1.1.
                    if edtla > bytes_transferred {
                        usb_debug!("on transfer complete short packet");
                        let residual_transfer_length = edtla - bytes_transferred;
                        self.interrupter
                            .lock()
                            .send_transfer_event_trb(
                                TrbCompletionCode::ShortPacket,
                                atrb.gpa,
                                residual_transfer_length,
                                true,
                                self.slot_id,
                                self.endpoint_id,
                            )
                            .map_err(Error::SendInterrupt)?;
                    } else {
                        usb_debug!("on transfer complete success");
                        self.interrupter
                            .lock()
                            .send_transfer_event_trb(
                                TrbCompletionCode::Success,
                                atrb.gpa,
                                0, // transfer length
                                true,
                                self.slot_id,
                                self.endpoint_id,
                            )
                            .map_err(Error::SendInterrupt)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Send this transfer to backend if it's a valid transfer.
    pub fn send_to_backend_if_valid(self) -> Result<()> {
        if self.validate_transfer()? {
            // Backend should invoke on transfer complete when transfer is completed.
            let port = self.port.clone();
            let mut backend = port.get_backend_device();
            match &mut *backend {
                Some(backend) => backend
                    .submit_transfer(self)
                    .map_err(|_| Error::SubmitTransfer)?,
                None => {
                    error!("backend is already disconnected");
                    self.transfer_completion_event
                        .write(1)
                        .map_err(Error::WriteCompletionEvent)?;
                }
            }
        } else {
            error!("invalid td on transfer ring");
            self.transfer_completion_event
                .write(1)
                .map_err(Error::WriteCompletionEvent)?;
        }
        Ok(())
    }

    // Check each trb in the transfer descriptor for invalid or out of bounds
    // parameters. Returns true iff the transfer descriptor is valid.
    fn validate_transfer(&self) -> Result<bool> {
        let mut valid = true;
        for atrb in &self.transfer_trbs {
            if !trb_is_valid(&atrb) {
                self.interrupter
                    .lock()
                    .send_transfer_event_trb(
                        TrbCompletionCode::TrbError,
                        atrb.gpa,
                        0,
                        false,
                        self.slot_id,
                        self.endpoint_id,
                    )
                    .map_err(Error::SendInterrupt)?;
                valid = false;
            }
        }
        Ok(valid)
    }
}

fn trb_is_valid(atrb: &AddressedTrb) -> bool {
    let can_be_in_transfer_ring = match atrb.trb.can_be_in_transfer_ring() {
        Ok(v) => v,
        Err(e) => {
            error!("unknown error {:?}", e);
            return false;
        }
    };
    can_be_in_transfer_ring && (atrb.trb.interrupter_target() < MAX_INTERRUPTER)
}

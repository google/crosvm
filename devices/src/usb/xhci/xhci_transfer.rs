// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::min;
use std::fmt;
use std::fmt::Display;
use std::mem;
use std::sync::Arc;
use std::sync::Weak;

use base::debug;
use base::error;
use base::info;
use base::warn;
use base::Error as SysError;
use base::Event;
use bit_field::Error as BitFieldError;
use remain::sorted;
use sync::Mutex;
use thiserror::Error;
use usb_util::TransferStatus;
use usb_util::UsbRequestSetup;
use vm_memory::GuestMemory;
use vm_memory::GuestMemoryError;

use super::device_slot::DeviceSlot;
use super::interrupter::Error as InterrupterError;
use super::interrupter::Interrupter;
use super::scatter_gather_buffer::Error as BufferError;
use super::scatter_gather_buffer::ScatterGatherBuffer;
use super::usb_hub::Error as HubError;
use super::usb_hub::UsbPort;
use super::xhci_abi::AddressedTrb;
use super::xhci_abi::Error as TrbError;
use super::xhci_abi::EventDataTrb;
use super::xhci_abi::SetupStageTrb;
use super::xhci_abi::TransferDescriptor;
use super::xhci_abi::TrbCast;
use super::xhci_abi::TrbCompletionCode;
use super::xhci_abi::TrbType;
use super::xhci_regs::MAX_INTERRUPTER;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("unexpected trb type: {0:?}")]
    BadTrbType(TrbType),
    #[error("cannot cast trb: {0}")]
    CastTrb(TrbError),
    #[error("cannot create transfer buffer: {0}")]
    CreateBuffer(BufferError),
    #[error("cannot detach from port: {0}")]
    DetachPort(HubError),
    #[error("failed to halt the endpoint: {0}")]
    HaltEndpoint(u8),
    #[error("failed to read guest memory: {0}")]
    ReadGuestMemory(GuestMemoryError),
    #[error("cannot send interrupt: {0}")]
    SendInterrupt(InterrupterError),
    #[error("failed to submit transfer to backend")]
    SubmitTransfer,
    #[error("cannot get transfer length: {0}")]
    TransferLength(TrbError),
    #[error("cannot get trb type: {0}")]
    TrbType(BitFieldError),
    #[error("cannot write completion event: {0}")]
    WriteCompletionEvent(SysError),
    #[error("failed to write guest memory: {0}")]
    WriteGuestMemory(GuestMemoryError),
}

type Result<T> = std::result::Result<T, Error>;

/// Type of usb endpoints.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
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
        cancel_callback: Box<dyn FnOnce() + Send>,
    },
    Cancelling,
    Cancelled,
    Completed,
}

impl XhciTransferState {
    /// Try to cancel this transfer, if it's possible.
    pub fn try_cancel(&mut self) {
        match mem::replace(self, XhciTransferState::Created) {
            XhciTransferState::Submitted { cancel_callback } => {
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
    Normal,
    // See usb spec for setup stage, data stage and status stage,
    // see xHCI spec 4.11.2.2 for corresponding trbs.
    SetupStage,
    DataStage,
    StatusStage,
    // See xHCI spec 4.11.2.3.
    Isochronous,
    // See xHCI spec 6.4.1.4.
    Noop,
}

impl Display for XhciTransferType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::XhciTransferType::*;

        match self {
            Normal => write!(f, "Normal"),
            SetupStage => write!(f, "SetupStage"),
            DataStage => write!(f, "DataStage"),
            StatusStage => write!(f, "StatusStage"),
            Isochronous => write!(f, "Isochronous"),
            Noop => write!(f, "Noop"),
        }
    }
}

/// Xhci Transfer manager holds reference to all ongoing transfers. Can cancel them all if
/// needed.
#[derive(Clone)]
pub struct XhciTransferManager {
    transfers: Arc<Mutex<Vec<Weak<Mutex<XhciTransferState>>>>>,
    device_slot: Weak<DeviceSlot>,
}

impl XhciTransferManager {
    /// Create a new manager.
    pub fn new(device_slot: Weak<DeviceSlot>) -> XhciTransferManager {
        XhciTransferManager {
            transfers: Arc::new(Mutex::new(Vec::new())),
            device_slot,
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
        completion_event: Event,
        stream_id: Option<u16>,
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
            device_slot: self.device_slot.clone(),
            stream_id,
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

impl Default for XhciTransferManager {
    fn default() -> Self {
        Self::new(Weak::new())
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
    transfer_completion_event: Event,
    device_slot: Weak<DeviceSlot>,
    stream_id: Option<u16>,
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
        // We can figure out transfer type from the first trb.
        // See transfer descriptor description in xhci spec for more details.
        match self.transfer_trbs[0]
            .trb
            .get_trb_type()
            .map_err(Error::TrbType)?
        {
            TrbType::Normal => Ok(XhciTransferType::Normal),
            TrbType::SetupStage => Ok(XhciTransferType::SetupStage),
            TrbType::DataStage => Ok(XhciTransferType::DataStage),
            TrbType::StatusStage => Ok(XhciTransferType::StatusStage),
            TrbType::Isoch => Ok(XhciTransferType::Isochronous),
            TrbType::Noop => Ok(XhciTransferType::Noop),
            t => Err(Error::BadTrbType(t)),
        }
    }

    /// Create a scatter gather buffer for the given xhci transfer
    pub fn create_buffer(&self) -> Result<ScatterGatherBuffer> {
        ScatterGatherBuffer::new(self.mem.clone(), self.transfer_trbs.clone())
            .map_err(Error::CreateBuffer)
    }

    /// Create a usb request setup for the control transfer buffer
    pub fn create_usb_request_setup(&self) -> Result<UsbRequestSetup> {
        let trb = self.transfer_trbs[0]
            .trb
            .checked_cast::<SetupStageTrb>()
            .map_err(Error::CastTrb)?;
        Ok(UsbRequestSetup::new(
            trb.get_request_type(),
            trb.get_request(),
            trb.get_value(),
            trb.get_index(),
            trb.get_length(),
        ))
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

    /// get stream id.
    pub fn get_stream_id(&self) -> Option<u16> {
        self.stream_id
    }

    /// This functions should be invoked when transfer is completed (or failed).
    pub fn on_transfer_complete(
        &self,
        status: &TransferStatus,
        bytes_transferred: u32,
    ) -> Result<()> {
        match status {
            TransferStatus::NoDevice => {
                info!("xhci: device disconnected, detaching from port");
                // If the device is gone, we don't need to send transfer completion event, cause we
                // are going to destroy everything related to this device anyway.
                return match self.port.detach() {
                    Ok(()) => Ok(()),
                    // It's acceptable for the port to be already disconnected
                    // as asynchronous transfer completions are processed.
                    Err(HubError::AlreadyDetached(_e)) => Ok(()),
                    Err(e) => Err(Error::DetachPort(e)),
                };
            }
            TransferStatus::Cancelled => {
                // TODO(jkwang) According to the spec, we should send a stopped event here. But
                // kernel driver does not do anything meaningful when it sees a stopped event.
                return self
                    .transfer_completion_event
                    .signal()
                    .map_err(Error::WriteCompletionEvent);
            }
            TransferStatus::Completed => {
                self.transfer_completion_event
                    .signal()
                    .map_err(Error::WriteCompletionEvent)?;
            }
            TransferStatus::Stalled => {
                warn!("xhci: endpoint is stalled. set state to Halted");
                if let Some(device_slot) = self.device_slot.upgrade() {
                    device_slot
                        .halt_endpoint(self.endpoint_id)
                        .map_err(|_| Error::HaltEndpoint(self.endpoint_id))?;
                }
                self.transfer_completion_event
                    .signal()
                    .map_err(Error::WriteCompletionEvent)?;
            }
            _ => {
                // Transfer failed, we are not handling this correctly yet. Guest kernel might see
                // short packets for in transfer and might think control transfer is successful. It
                // will eventually find out device is in a wrong state.
                self.transfer_completion_event
                    .signal()
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
                } else if *status == TransferStatus::Stalled {
                    debug!("xhci: on transfer complete stalled");
                    let residual_transfer_length = edtla - bytes_transferred;
                    self.interrupter
                        .lock()
                        .send_transfer_event_trb(
                            TrbCompletionCode::StallError,
                            atrb.gpa,
                            residual_transfer_length,
                            true,
                            self.slot_id,
                            self.endpoint_id,
                        )
                        .map_err(Error::SendInterrupt)?;
                } else {
                    // For Short Transfer details, see xHCI spec 4.10.1.1.
                    if edtla > bytes_transferred {
                        debug!("xhci: on transfer complete short packet");
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
                        debug!("xhci: on transfer complete success");
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
                        .signal()
                        .map_err(Error::WriteCompletionEvent)?;
                }
            }
        } else {
            error!("invalid td on transfer ring");
            self.transfer_completion_event
                .signal()
                .map_err(Error::WriteCompletionEvent)?;
        }
        Ok(())
    }

    // Check each trb in the transfer descriptor for invalid or out of bounds
    // parameters. Returns true iff the transfer descriptor is valid.
    fn validate_transfer(&self) -> Result<bool> {
        let mut valid = true;
        for atrb in &self.transfer_trbs {
            if !trb_is_valid(atrb) {
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

// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::min;
use std::collections::VecDeque;
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
use super::ring_buffer_stop_cb::RingBufferStopCallback;
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
    #[error("failed to cancel transfer")]
    CancelTransfer,
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

type CancelCallback = Box<dyn FnOnce() -> Result<()> + Send>;

/// Current state of xhci transfer. The transfer in a Submitted or Cancelling state is owned by the
/// host and should always be reaped to prevent memory leak.
pub enum XhciTransferState {
    Created,
    /// When transfer is submitted, it will contain a transfer callback, which should be invoked
    /// when the transfer is cancelled.
    Submitted {
        cancel_callback: CancelCallback,
    },
    Cancelling,
    Cancelled,
    Completed,
}

impl XhciTransferState {
    /// Try to cancel this transfer, if it's possible.
    pub fn try_cancel(&mut self, force: bool) -> bool {
        let mut cancelled = true;
        match mem::replace(self, XhciTransferState::Created) {
            XhciTransferState::Submitted { cancel_callback } => {
                // If we fail to cancel, there are two cases: the URB has already completed
                // (EINVAL) or the device is gone (ENODEV). For both cases, we put back the state
                // to Submitted and check the URB status in the completion handler, to report the
                // already completed one properly to the guest. However, we can't do that once we
                // have cancelled a preceding request, because the request must be processed in the
                // order of submission.
                match cancel_callback() {
                    Ok(()) => {
                        *self = XhciTransferState::Cancelling;
                    }
                    Err(_e) => {
                        if force {
                            *self = XhciTransferState::Cancelling;
                        } else {
                            let error_callback = Box::new(move || Err(Error::CancelTransfer));
                            *self = XhciTransferState::Submitted {
                                cancel_callback: error_callback,
                            };
                            cancelled = false;
                        }
                    }
                }
            }
            XhciTransferState::Cancelling => {
                error!("Another cancellation is already issued.");
                *self = XhciTransferState::Cancelling;
            }
            _ => {
                *self = XhciTransferState::Cancelled;
            }
        }
        cancelled
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
    transfers: Arc<Mutex<VecDeque<Weak<Mutex<XhciTransferState>>>>>,
    device_slot: Weak<DeviceSlot>,
    stop_callback: Arc<Mutex<Vec<RingBufferStopCallback>>>,
}

impl XhciTransferManager {
    /// Create a new manager.
    pub fn new(device_slot: Weak<DeviceSlot>) -> XhciTransferManager {
        XhciTransferManager {
            transfers: Arc::new(Mutex::new(VecDeque::new())),
            device_slot,
            stop_callback: Arc::new(Mutex::new(Vec::new())),
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
        transfer_descriptor: TransferDescriptor,
        completion_event: Event,
        stream_id: Option<u16>,
    ) -> XhciTransfer {
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
            transfer_descriptor,
            device_slot: self.device_slot.clone(),
            stream_id,
        };
        self.transfers.lock().push_back(Arc::downgrade(&t.state));
        t
    }

    /// Cancel all current transfers and execute the callback once completed.
    pub fn cancel_all(&self, callback: RingBufferStopCallback) {
        let locked_transfers = self.transfers.lock();
        if !locked_transfers.is_empty() {
            self.stop_callback.lock().push(callback);
        }

        let mut force_cancel = false;
        locked_transfers.iter().for_each(|t| {
            let state = match t.upgrade() {
                Some(state) => state,
                None => {
                    error!("transfer is already cancelled or finished");
                    return;
                }
            };
            force_cancel |= state.lock().try_cancel(force_cancel);
        });
    }

    fn remove_transfer(&self, t: &Arc<Mutex<XhciTransferState>>) {
        let mut transfers = self.transfers.lock();
        match transfers.iter().position(|wt| match wt.upgrade() {
            Some(wt) => Arc::ptr_eq(&wt, t),
            None => false,
        }) {
            None => error!("attempted to remove unknown transfer"),
            Some(i) => {
                transfers.remove(i);
            }
        }
        if transfers.is_empty() {
            self.stop_callback.lock().clear();
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
    transfer_descriptor: TransferDescriptor,
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
            "xhci_transfer slot id: {}, endpoint id {}, transfer_dir {:?}, transfer_descriptor {:?}",
            self.slot_id, self.endpoint_id, self.transfer_dir, self.transfer_descriptor
        )
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum TransferAction {
    HaltEndpoint,
    SendEvent {
        code: TrbCompletionCode,
        gpa: u64,
        residual_or_edtla: u32,
        event_data: bool,
    },
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
        match self
            .transfer_descriptor
            .first_atrb()
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
        ScatterGatherBuffer::new(self.mem.clone(), self.transfer_descriptor.clone())
            .map_err(Error::CreateBuffer)
    }

    /// Create a usb request setup for the control transfer buffer
    pub fn create_usb_request_setup(&self) -> Result<UsbRequestSetup> {
        let first_atrb = self.transfer_descriptor.first_atrb();
        let trb = first_atrb
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

    fn process_td_results(
        &self,
        status: &TransferStatus,
        bytes_transferred: u32,
    ) -> Result<Vec<TransferAction>> {
        let mut actions = Vec::new();
        if *status == TransferStatus::Stalled {
            warn!("xhci: endpoint is stalled. set state to Halted");
            actions.push(TransferAction::HaltEndpoint);
        }

        let mut edtla: u32 = 0;
        let mut remaining_transferred = bytes_transferred;
        let mut retiring_on_short: bool = false;
        let mut residual_on_short: u32 = 0;
        let last_atrb_gpa = self.transfer_descriptor.last_atrb().gpa;

        // As noted in xHCI spec 4.11.3.1
        // Transfer Event TRB only occurs under the following conditions:
        //   1. If the Interrupt On Completion flag is set.
        //   2. When a short transfer occurs during the execution of a Transfer TRB and the
        //      Interrupt-on-Short Packet flag is set.
        //   3. If an error occurs during the execution of a Transfer TRB.
        for atrb in &self.transfer_descriptor {
            // For details about event data trb and EDTLA, see spec 4.11.5.2.
            if atrb.trb.get_trb_type().map_err(Error::TrbType)? == TrbType::EventData {
                let code = if retiring_on_short {
                    TrbCompletionCode::ShortPacket
                } else {
                    TrbCompletionCode::Success
                };
                actions.push(TransferAction::SendEvent {
                    code,
                    gpa: atrb
                        .trb
                        .cast::<EventDataTrb>()
                        .map_err(Error::CastTrb)?
                        .get_event_data(),
                    residual_or_edtla: edtla,
                    event_data: true,
                });
                edtla = 0;
                self.report_completion(atrb);
                continue;
            }

            let length = atrb.trb.transfer_length().map_err(Error::TransferLength)?;
            let transferred = min(length, remaining_transferred);
            remaining_transferred -= transferred;

            let residual = length - transferred;
            edtla += transferred;

            // Report StallError for the TRB with residual data or the last TRB of the TD.
            // The latter condition covers a stall on the Status Stage. The TRB that caused the
            // stall is considered as not completed.
            if *status == TransferStatus::Stalled && (residual > 0 || atrb.gpa == last_atrb_gpa) {
                debug!("xhci: on transfer complete stalled");
                actions.push(TransferAction::SendEvent {
                    code: TrbCompletionCode::StallError,
                    gpa: atrb.gpa,
                    residual_or_edtla: residual,
                    event_data: false,
                });
                break;
            }

            // If Short Packet is detected, the rest of the TRBs in the same TD are not executed.
            // However, events are still generated for the EventData TRBs (handled above) or other
            // TRBs with IOC (handled below).
            if retiring_on_short {
                if atrb.trb.interrupt_on_completion() {
                    actions.push(TransferAction::SendEvent {
                        code: TrbCompletionCode::ShortPacket,
                        gpa: atrb.gpa,
                        residual_or_edtla: residual_on_short,
                        event_data: false,
                    });
                }
            } else if residual > 0 {
                retiring_on_short = true;
                residual_on_short = residual;
                if atrb.trb.interrupt_on_completion() || atrb.trb.interrupt_on_short_packet() {
                    debug!("xhci: on transfer complete short packet");
                    actions.push(TransferAction::SendEvent {
                        code: TrbCompletionCode::ShortPacket,
                        gpa: atrb.gpa,
                        residual_or_edtla: residual,
                        event_data: false,
                    });
                }
            } else if atrb.trb.interrupt_on_completion() {
                debug!("xhci: on transfer complete success");
                actions.push(TransferAction::SendEvent {
                    code: TrbCompletionCode::Success,
                    gpa: atrb.gpa,
                    residual_or_edtla: 0,
                    event_data: false,
                });
            }

            // The dequeue pointer still needs to be advanced after a Short Packet.
            self.report_completion(atrb);
        }
        Ok(actions)
    }

    fn report_completion(&self, trb: &AddressedTrb) {
        if let Some(device_slot) = self.device_slot.upgrade() {
            device_slot.report_trb_completion(self.endpoint_id, self.stream_id, trb);
        }
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
                // Actual port detachment is handled by the UsbUtilEventHandler.
                return self
                    .transfer_completion_event
                    .signal()
                    .map_err(Error::WriteCompletionEvent);
            }
            TransferStatus::Cancelled => {
                return self
                    .transfer_completion_event
                    .signal()
                    .map_err(Error::WriteCompletionEvent);
            }
            TransferStatus::Completed => {}
            TransferStatus::Stalled => {
                // This is not a critical error, especially during the enumeration. Some devices
                // takes time to become ready and may return StallError until then. A mass storage
                // may also return StallError on checking write-protection.
            }
            TransferStatus::Error => {
                // Transfer failed, we are not handling this correctly yet. Guest kernel might see
                // short packets for in transfer and might think control transfer is successful. It
                // will eventually find out device is in a wrong state.
            }
        }

        let mut halted = false;
        let actions = self.process_td_results(status, bytes_transferred)?;
        for action in actions {
            match action {
                TransferAction::SendEvent {
                    code,
                    gpa,
                    residual_or_edtla,
                    event_data,
                } => {
                    self.interrupter
                        .lock()
                        .send_transfer_event_trb(
                            code,
                            gpa,
                            residual_or_edtla,
                            event_data,
                            self.slot_id,
                            self.endpoint_id,
                        )
                        .map_err(Error::SendInterrupt)?;
                }
                TransferAction::HaltEndpoint => {
                    if let Some(device_slot) = self.device_slot.upgrade() {
                        device_slot
                            .halt_endpoint(self.endpoint_id)
                            .map_err(|_| Error::HaltEndpoint(self.endpoint_id))?;
                        halted = true;
                    }
                }
            }
        }

        // Since the event loop is single threaded, there's no need to trigger it early. We delay
        // it to the end so that its error, if it ever occurs, won't cause the above transfer
        // events to be omitted.
        if !halted {
            self.transfer_completion_event
                .signal()
                .map_err(Error::WriteCompletionEvent)
        } else {
            Ok(())
        }
    }

    /// Send this transfer to backend if it's a valid transfer.
    pub fn send_to_backend_if_valid(self) -> Result<()> {
        if self.validate_transfer()? {
            // Backend should invoke on transfer complete when transfer is completed.
            let port = self.port.clone();
            let mut backend = port.backend_device();
            match &mut *backend {
                Some(backend) => backend
                    .lock()
                    .submit_xhci_transfer(self)
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
        for atrb in &self.transfer_descriptor {
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

#[cfg(test)]
mod tests {
    use base::pagesize;
    use vm_memory::GuestAddress;

    use super::*;
    use crate::usb::xhci::xhci_abi::NormalTrb;
    use crate::usb::xhci::xhci_abi::StatusStageTrb;
    use crate::usb::xhci::xhci_abi::Trb;
    use crate::usb::xhci::xhci_backend_device::BackendType;
    use crate::usb::xhci::XhciRegs;

    fn create_test_transfer(trbs: Vec<Trb>) -> XhciTransfer {
        let mem = GuestMemory::new(&[(GuestAddress(0), pagesize() as u64)]).unwrap();
        let mut gpa = 0x100;
        let mut atrbs = Vec::new();
        for trb in trbs {
            mem.write_obj_at_addr(trb, GuestAddress(gpa)).unwrap();
            atrbs.push(AddressedTrb { trb, gpa });
            gpa += 16;
        }

        let td = TransferDescriptor::new(atrbs).unwrap();
        let manager = XhciTransferManager::new(Weak::new());

        let test_reg32 = register!(
            name: "test",
            ty: u32,
            offset: 0x0,
            reset_value: 0,
            guest_writeable_mask: 0x0,
            guest_write_1_to_clear_mask: 0,
        );
        let test_reg64 = register!(
            name: "test",
            ty: u64,
            offset: 0x0,
            reset_value: 0,
            guest_writeable_mask: 0x0,
            guest_write_1_to_clear_mask: 0,
        );
        let xhci_regs = XhciRegs {
            usbcmd: test_reg32.clone(),
            usbsts: test_reg32.clone(),
            dnctrl: test_reg32.clone(),
            crcr: test_reg64.clone(),
            dcbaap: test_reg64.clone(),
            config: test_reg64.clone(),
            portsc: vec![test_reg32.clone(); 16],
            doorbells: Vec::new(),
            iman: test_reg32.clone(),
            imod: test_reg32.clone(),
            erstsz: test_reg32.clone(),
            erstba: test_reg64.clone(),
            erdp: test_reg64.clone(),
        };

        XhciTransfer {
            manager,
            state: Arc::new(Mutex::new(XhciTransferState::Created)),
            mem,
            port: Arc::new(UsbPort::new(
                BackendType::Usb2,
                1,
                test_reg32.clone(),
                test_reg32.clone(),
                Arc::new(Mutex::new(Interrupter::new(
                    GuestMemory::new(&[]).unwrap(),
                    Event::new().unwrap(),
                    &xhci_regs,
                ))),
            )),
            interrupter: Arc::new(Mutex::new(Interrupter::new(
                GuestMemory::new(&[]).unwrap(),
                Event::new().unwrap(),
                &xhci_regs,
            ))),
            transfer_completion_event: Event::new().unwrap(),
            slot_id: 1,
            endpoint_id: 2,
            transfer_dir: TransferDirection::Out,
            transfer_descriptor: td,
            device_slot: Weak::new(),
            stream_id: None,
        }
    }

    #[test]
    fn test_bulk_success() {
        let mut trb = Trb::new();
        let normal_trb = trb.cast_mut::<NormalTrb>().unwrap();
        normal_trb.set_trb_type(TrbType::Normal);
        normal_trb.set_trb_transfer_length(100);
        normal_trb.set_interrupt_on_completion(1);
        let transfer = create_test_transfer(vec![trb]);

        let actions = transfer
            .process_td_results(&TransferStatus::Completed, 100)
            .unwrap();
        assert_eq!(
            actions,
            vec![TransferAction::SendEvent {
                code: TrbCompletionCode::Success,
                gpa: 0x100,
                residual_or_edtla: 0,
                event_data: false,
            }]
        );
    }

    #[test]
    fn test_bulk_short_with_isp() {
        // xHCI 4.10.1.1 Short Transfers states that an event should be generated if ISP or IOC is
        // set to 1.
        let mut trb = Trb::new();
        let normal_trb = trb.cast_mut::<NormalTrb>().unwrap();
        normal_trb.set_trb_type(TrbType::Normal);
        normal_trb.set_trb_transfer_length(100);
        normal_trb.set_interrupt_on_short_packet(1);
        let transfer = create_test_transfer(vec![trb]);

        let actions = transfer
            .process_td_results(&TransferStatus::Completed, 40)
            .unwrap();
        assert_eq!(
            actions,
            vec![TransferAction::SendEvent {
                code: TrbCompletionCode::ShortPacket,
                gpa: 0x100,
                residual_or_edtla: 60,
                event_data: false,
            }]
        );
    }

    #[test]
    fn test_bulk_short_with_ioc() {
        // xHCI 4.10.1.1 Short Transfers states that an event should be generated if ISP or IOC is
        // set to 1.
        let mut trb = Trb::new();
        let normal_trb = trb.cast_mut::<NormalTrb>().unwrap();
        normal_trb.set_trb_type(TrbType::Normal);
        normal_trb.set_trb_transfer_length(100);
        normal_trb.set_interrupt_on_completion(1);
        let transfer = create_test_transfer(vec![trb]);

        let actions = transfer
            .process_td_results(&TransferStatus::Completed, 40)
            .unwrap();
        assert_eq!(
            actions,
            vec![TransferAction::SendEvent {
                code: TrbCompletionCode::ShortPacket,
                gpa: 0x100,
                residual_or_edtla: 60,
                event_data: false,
            }]
        );
    }

    #[test]
    fn test_bulk_without_evendata_retiring_after_short() {
        // xHCI 4.9.1 Transfer Descriptors states that the TD should retire after detecting a short
        // packet condition, but xHCI 4.10.1.1 Short Transfers states it should still generate an
        // event for a TRB with IOC.
        let mut trb1 = Trb::new();
        let normal_trb1 = trb1.cast_mut::<NormalTrb>().unwrap();
        normal_trb1.set_trb_type(TrbType::Normal);
        normal_trb1.set_trb_transfer_length(100);
        normal_trb1.set_interrupt_on_short_packet(1);

        let mut trb2 = Trb::new();
        let normal_trb2 = trb2.cast_mut::<NormalTrb>().unwrap();
        normal_trb2.set_trb_type(TrbType::Normal);
        normal_trb2.set_trb_transfer_length(100);
        normal_trb2.set_interrupt_on_completion(1);

        let mut trb3 = Trb::new();
        let normal_trb3 = trb3.cast_mut::<NormalTrb>().unwrap();
        normal_trb3.set_trb_type(TrbType::Normal);
        normal_trb3.set_trb_transfer_length(100);
        normal_trb3.set_interrupt_on_completion(1);

        let transfer = create_test_transfer(vec![trb1, trb2, trb3]);

        let actions = transfer
            .process_td_results(&TransferStatus::Completed, 40)
            .unwrap();
        assert_eq!(
            actions,
            vec![
                TransferAction::SendEvent {
                    code: TrbCompletionCode::ShortPacket,
                    gpa: 0x100,
                    residual_or_edtla: 60,
                    event_data: false,
                },
                TransferAction::SendEvent {
                    code: TrbCompletionCode::ShortPacket,
                    gpa: 0x110,
                    residual_or_edtla: 60,
                    event_data: false,
                },
                TransferAction::SendEvent {
                    code: TrbCompletionCode::ShortPacket,
                    gpa: 0x120,
                    residual_or_edtla: 60,
                    event_data: false,
                },
            ]
        );
    }

    #[test]
    fn test_bulk_with_evendata_retiring_after_short() {
        // xHCI 4.9.1 Transfer Descriptors states that the TD should retire after detecting a short
        // packet condition, but xHCI 4.10.1.1 Short Transfers states it should still generate an
        // event for EventData TRB. This test assumes that we have PAE=1 in HCCPARAMS1 that forces
        // all the EventData TRBs to generate an event even after the Short Packet.
        let mut trb1 = Trb::new();
        let normal_trb1 = trb1.cast_mut::<NormalTrb>().unwrap();
        normal_trb1.set_trb_type(TrbType::Normal);
        normal_trb1.set_trb_transfer_length(100);
        normal_trb1.set_interrupt_on_short_packet(1);

        let mut trb2 = Trb::new();
        let event_trb = trb2.cast_mut::<EventDataTrb>().unwrap();
        event_trb.set_trb_type(TrbType::EventData);
        event_trb.set_event_data(0x12345678abcdef0);
        event_trb.set_interrupt_on_completion(1);

        let mut trb3 = Trb::new();
        let event_trb = trb3.cast_mut::<EventDataTrb>().unwrap();
        event_trb.set_trb_type(TrbType::EventData);
        event_trb.set_event_data(0x12345678abcdef1);
        event_trb.set_interrupt_on_completion(1);

        let transfer = create_test_transfer(vec![trb1, trb2, trb3]);

        let actions = transfer
            .process_td_results(&TransferStatus::Completed, 40)
            .unwrap();
        assert_eq!(
            actions,
            vec![
                TransferAction::SendEvent {
                    code: TrbCompletionCode::ShortPacket,
                    gpa: 0x100,
                    residual_or_edtla: 60,
                    event_data: false,
                },
                TransferAction::SendEvent {
                    code: TrbCompletionCode::ShortPacket,
                    gpa: 0x12345678abcdef0,
                    residual_or_edtla: 40, // EDTLA
                    event_data: true,
                },
                TransferAction::SendEvent {
                    code: TrbCompletionCode::ShortPacket,
                    gpa: 0x12345678abcdef1,
                    residual_or_edtla: 0, // EDTLA
                    event_data: true,
                },
            ]
        );
    }

    #[test]
    fn test_bulk_stall_partial() {
        // xHCI 4.10.2 Errors state that an error during a transfer shall always generate an event,
        // irrespective of whether ISP or IOC is set to 1. Also, 4.10.2.1 Stall Error states that
        // the endpoint state should transition to Halted.
        let mut trb = Trb::new();
        let normal_trb = trb.cast_mut::<NormalTrb>().unwrap();
        normal_trb.set_trb_type(TrbType::Normal);
        normal_trb.set_trb_transfer_length(100);
        let transfer = create_test_transfer(vec![trb]);

        // Stall at 40 bytes.
        let actions = transfer
            .process_td_results(&TransferStatus::Stalled, 40)
            .unwrap();
        assert_eq!(
            actions,
            vec![
                TransferAction::HaltEndpoint,
                TransferAction::SendEvent {
                    code: TrbCompletionCode::StallError,
                    gpa: 0x100,
                    residual_or_edtla: 60,
                    event_data: false,
                }
            ]
        );
    }

    #[test]
    fn test_control_stall_no_data_stage() {
        let mut trb = Trb::new();
        let status_trb = trb.cast_mut::<StatusStageTrb>().unwrap();
        status_trb.set_trb_type(TrbType::StatusStage);
        status_trb.set_interrupt_on_completion(1);

        let transfer = create_test_transfer(vec![trb]);

        // Stall at Status Stage (length 0). bytes_transferred = 0.
        let actions = transfer
            .process_td_results(&TransferStatus::Stalled, 0)
            .unwrap();

        assert_eq!(
            actions,
            vec![
                TransferAction::HaltEndpoint,
                TransferAction::SendEvent {
                    code: TrbCompletionCode::StallError,
                    gpa: 0x100,
                    residual_or_edtla: 0,
                    event_data: false,
                }
            ]
        );
    }

    #[test]
    fn test_bulk_stall_at_trb_start() {
        // xHCI 6.4.2.1 Transfer Event TRB states that if an error occurs during a transfer TRB,
        // the event TRB shall point to the offending TRB.
        let mut trb1 = Trb::new();
        let normal_trb1 = trb1.cast_mut::<NormalTrb>().unwrap();
        normal_trb1.set_trb_type(TrbType::Normal);
        normal_trb1.set_trb_transfer_length(100);

        let mut trb2 = Trb::new();
        let normal_trb2 = trb2.cast_mut::<NormalTrb>().unwrap();
        normal_trb2.set_trb_type(TrbType::Normal);
        normal_trb2.set_trb_transfer_length(100);

        let transfer = create_test_transfer(vec![trb1, trb2]);

        // Stall after 100 bytes (immediately when the second TRB is started).
        let actions = transfer
            .process_td_results(&TransferStatus::Stalled, 100)
            .unwrap();

        assert_eq!(
            actions,
            vec![
                TransferAction::HaltEndpoint,
                TransferAction::SendEvent {
                    code: TrbCompletionCode::StallError,
                    gpa: 0x110, // Second TRB GPA
                    residual_or_edtla: 100,
                    event_data: false,
                }
            ]
        );
    }

    #[test]
    fn test_event_data_single() {
        // xHCI 4.11.5.2 Event Data TRB states that the event should report EDTLA and set Event
        // Data (ED) field to 1.
        let mut trb1 = Trb::new();
        let normal_trb = trb1.cast_mut::<NormalTrb>().unwrap();
        normal_trb.set_trb_type(TrbType::Normal);
        normal_trb.set_trb_transfer_length(100);

        let mut trb2 = Trb::new();
        let event_trb = trb2.cast_mut::<EventDataTrb>().unwrap();
        event_trb.set_trb_type(TrbType::EventData);
        event_trb.set_event_data(0x12345678abcdef0);
        event_trb.set_interrupt_on_completion(1);

        let transfer = create_test_transfer(vec![trb1, trb2]);

        // Successful transfer.
        let actions = transfer
            .process_td_results(&TransferStatus::Completed, 100)
            .unwrap();
        assert_eq!(
            actions,
            vec![TransferAction::SendEvent {
                code: TrbCompletionCode::Success,
                gpa: 0x12345678abcdef0,
                residual_or_edtla: 100,
                event_data: true,
            }]
        );

        // Short packet.
        let actions = transfer
            .process_td_results(&TransferStatus::Completed, 40)
            .unwrap();
        assert_eq!(
            actions,
            vec![TransferAction::SendEvent {
                code: TrbCompletionCode::ShortPacket,
                gpa: 0x12345678abcdef0,
                residual_or_edtla: 40,
                event_data: true,
            }]
        );
    }

    #[test]
    fn test_event_data_multiple() {
        // xHCI 4.11.5.2 Event Data TRB states that EDTLA should be cleared to 0 when an EventData
        // TRB is encountered.
        let mut trb1 = Trb::new();
        let normal_trb = trb1.cast_mut::<NormalTrb>().unwrap();
        normal_trb.set_trb_type(TrbType::Normal);
        normal_trb.set_trb_transfer_length(100);
        normal_trb.set_interrupt_on_short_packet(1);

        let mut trb2 = Trb::new();
        let event_trb = trb2.cast_mut::<EventDataTrb>().unwrap();
        event_trb.set_trb_type(TrbType::EventData);
        event_trb.set_event_data(0x12345678abcdef0);
        event_trb.set_interrupt_on_completion(1);

        let transfer = create_test_transfer(vec![trb1, trb2, trb1, trb2]);

        // Successful transfer.
        let actions = transfer
            .process_td_results(&TransferStatus::Completed, 200)
            .unwrap();
        assert_eq!(
            actions,
            vec![
                TransferAction::SendEvent {
                    code: TrbCompletionCode::Success,
                    gpa: 0x12345678abcdef0,
                    residual_or_edtla: 100, // EDTLA
                    event_data: true,
                },
                TransferAction::SendEvent {
                    code: TrbCompletionCode::Success,
                    gpa: 0x12345678abcdef0,
                    residual_or_edtla: 100, // EDTLA
                    event_data: true,
                },
            ]
        );

        // Short packet. xHCI 5.3.6 Capability Parameters 1 (HCCPARAMS1) states that if Parse All
        // Event Data (PAE) field is 1, then it should parse all the EventData TRBs while advancing
        // to the next TD after a Short Packet. See also 4.10.1.1 Short Transfers.
        let actions = transfer
            .process_td_results(&TransferStatus::Completed, 40)
            .unwrap();
        assert_eq!(
            actions,
            vec![
                TransferAction::SendEvent {
                    code: TrbCompletionCode::ShortPacket,
                    gpa: 0x100,
                    residual_or_edtla: 60, // residual
                    event_data: false,
                },
                TransferAction::SendEvent {
                    code: TrbCompletionCode::ShortPacket,
                    gpa: 0x12345678abcdef0,
                    residual_or_edtla: 40, // EDTLA
                    event_data: true,
                },
                TransferAction::SendEvent {
                    code: TrbCompletionCode::ShortPacket,
                    gpa: 0x12345678abcdef0,
                    residual_or_edtla: 0, // EDTLA (from last Event)
                    event_data: true,
                },
            ]
        );
    }
}

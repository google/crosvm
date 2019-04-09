// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::device_slot::{DeviceSlot, DeviceSlots, Error as DeviceSlotError};
use super::interrupter::{Error as InterrupterError, Interrupter};
use super::ring_buffer_controller::{
    Error as RingBufferControllerError, RingBufferController, TransferDescriptorHandler,
};
use super::xhci_abi::{
    AddressDeviceCommandTrb, AddressedTrb, ConfigureEndpointCommandTrb, DisableSlotCommandTrb,
    Error as TrbError, EvaluateContextCommandTrb, ResetDeviceCommandTrb,
    SetTRDequeuePointerCommandTrb, StopEndpointCommandTrb, TransferDescriptor, TrbCast,
    TrbCompletionCode, TrbType,
};
use super::xhci_regs::{valid_slot_id, MAX_SLOTS};
use crate::utils::EventLoop;
use std::fmt::{self, Display};
use std::sync::Arc;
use sync::Mutex;
use sys_util::{error, warn, Error as SysError, EventFd, GuestAddress, GuestMemory};

#[derive(Debug)]
pub enum Error {
    WriteEventFd(SysError),
    SendInterrupt(InterrupterError),
    CastTrb(TrbError),
    BadSlotId(u8),
    StopEndpoint(DeviceSlotError),
    ConfigEndpoint(DeviceSlotError),
    SetAddress(DeviceSlotError),
    SetDequeuePointer(DeviceSlotError),
    EvaluateContext(DeviceSlotError),
    DisableSlot(DeviceSlotError),
    ResetSlot(DeviceSlotError),
}

type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            WriteEventFd(e) => write!(f, "failed to write event fd: {}", e),
            SendInterrupt(e) => write!(f, "failed to send interrupt: {}", e),
            CastTrb(e) => write!(f, "failed to cast trb: {}", e),
            BadSlotId(id) => write!(f, "bad slot id: {}", id),
            StopEndpoint(e) => write!(f, "failed to stop endpoint: {}", e),
            ConfigEndpoint(e) => write!(f, "failed to config endpoint: {}", e),
            SetAddress(e) => write!(f, "failed to set address: {}", e),
            SetDequeuePointer(e) => write!(f, "failed to set dequeue pointer: {}", e),
            EvaluateContext(e) => write!(f, "failed to evaluate context: {}", e),
            DisableSlot(e) => write!(f, "failed to disable slot: {}", e),
            ResetSlot(e) => write!(f, "failed to reset slot: {}", e),
        }
    }
}

pub type CommandRingController = RingBufferController<CommandRingTrbHandler>;
pub type CommandRingControllerError = RingBufferControllerError;

impl CommandRingController {
    pub fn new(
        mem: GuestMemory,
        event_loop: Arc<EventLoop>,
        slots: DeviceSlots,
        interrupter: Arc<Mutex<Interrupter>>,
    ) -> std::result::Result<Arc<CommandRingController>, RingBufferControllerError> {
        RingBufferController::new_with_handler(
            String::from("command ring"),
            mem,
            event_loop,
            CommandRingTrbHandler::new(slots, interrupter),
        )
    }
}

pub struct CommandRingTrbHandler {
    slots: DeviceSlots,
    interrupter: Arc<Mutex<Interrupter>>,
}

impl CommandRingTrbHandler {
    fn new(slots: DeviceSlots, interrupter: Arc<Mutex<Interrupter>>) -> Self {
        CommandRingTrbHandler { slots, interrupter }
    }

    fn slot(&self, slot_id: u8) -> Result<Arc<DeviceSlot>> {
        self.slots.slot(slot_id).ok_or(Error::BadSlotId(slot_id))
    }

    fn command_completion_callback(
        interrupter: &Arc<Mutex<Interrupter>>,
        completion_code: TrbCompletionCode,
        slot_id: u8,
        trb_addr: u64,
        event_fd: &EventFd,
    ) -> Result<()> {
        interrupter
            .lock()
            .send_command_completion_trb(completion_code, slot_id, GuestAddress(trb_addr))
            .map_err(Error::SendInterrupt)?;
        event_fd.write(1).map_err(Error::WriteEventFd)
    }

    fn enable_slot(&self, atrb: &AddressedTrb, event_fd: EventFd) -> Result<()> {
        for slot_id in 1..=MAX_SLOTS {
            if self.slot(slot_id)?.enable() {
                return CommandRingTrbHandler::command_completion_callback(
                    &self.interrupter,
                    TrbCompletionCode::Success,
                    slot_id,
                    atrb.gpa,
                    &event_fd,
                );
            }
        }

        CommandRingTrbHandler::command_completion_callback(
            &self.interrupter,
            TrbCompletionCode::NoSlotsAvailableError,
            0,
            atrb.gpa,
            &event_fd,
        )
    }

    fn disable_slot(&self, atrb: &AddressedTrb, event_fd: EventFd) -> Result<()> {
        let trb = atrb
            .trb
            .cast::<DisableSlotCommandTrb>()
            .map_err(Error::CastTrb)?;
        let slot_id = trb.get_slot_id();
        if valid_slot_id(slot_id) {
            let gpa = atrb.gpa;
            let interrupter = self.interrupter.clone();
            self.slots
                .disable_slot(slot_id, move |completion_code| {
                    CommandRingTrbHandler::command_completion_callback(
                        &interrupter,
                        completion_code,
                        slot_id,
                        gpa,
                        &event_fd,
                    )
                    .map_err(|e| {
                        error!("failed to run command completion callback: {}", e);
                    })
                })
                .map_err(Error::DisableSlot)
        } else {
            CommandRingTrbHandler::command_completion_callback(
                &self.interrupter,
                TrbCompletionCode::TrbError,
                slot_id,
                atrb.gpa,
                &event_fd,
            )
        }
    }

    fn address_device(&self, atrb: &AddressedTrb, event_fd: EventFd) -> Result<()> {
        let trb = atrb
            .trb
            .cast::<AddressDeviceCommandTrb>()
            .map_err(Error::CastTrb)?;
        let slot_id = trb.get_slot_id();
        let completion_code = {
            if valid_slot_id(slot_id) {
                self.slot(slot_id)?
                    .set_address(trb)
                    .map_err(Error::SetAddress)?
            } else {
                TrbCompletionCode::TrbError
            }
        };
        CommandRingTrbHandler::command_completion_callback(
            &self.interrupter,
            completion_code,
            slot_id,
            atrb.gpa,
            &event_fd,
        )
    }

    fn configure_endpoint(&self, atrb: &AddressedTrb, event_fd: EventFd) -> Result<()> {
        let trb = atrb
            .trb
            .cast::<ConfigureEndpointCommandTrb>()
            .map_err(Error::CastTrb)?;
        let slot_id = trb.get_slot_id();
        let completion_code = {
            if valid_slot_id(slot_id) {
                self.slot(slot_id)?
                    .configure_endpoint(trb)
                    .map_err(Error::ConfigEndpoint)?
            } else {
                TrbCompletionCode::TrbError
            }
        };
        CommandRingTrbHandler::command_completion_callback(
            &self.interrupter,
            completion_code,
            slot_id,
            atrb.gpa,
            &event_fd,
        )
    }

    fn evaluate_context(&self, atrb: &AddressedTrb, event_fd: EventFd) -> Result<()> {
        let trb = atrb
            .trb
            .cast::<EvaluateContextCommandTrb>()
            .map_err(Error::CastTrb)?;
        let slot_id = trb.get_slot_id();
        let completion_code = {
            if valid_slot_id(slot_id) {
                self.slot(slot_id)?
                    .evaluate_context(trb)
                    .map_err(Error::EvaluateContext)?
            } else {
                TrbCompletionCode::TrbError
            }
        };
        CommandRingTrbHandler::command_completion_callback(
            &self.interrupter,
            completion_code,
            slot_id,
            atrb.gpa,
            &event_fd,
        )
    }

    fn reset_device(&self, atrb: &AddressedTrb, event_fd: EventFd) -> Result<()> {
        let trb = atrb
            .trb
            .cast::<ResetDeviceCommandTrb>()
            .map_err(Error::CastTrb)?;
        let slot_id = trb.get_slot_id();
        if valid_slot_id(slot_id) {
            let gpa = atrb.gpa;
            let interrupter = self.interrupter.clone();
            self.slots
                .reset_slot(slot_id, move |completion_code| {
                    CommandRingTrbHandler::command_completion_callback(
                        &interrupter,
                        completion_code,
                        slot_id,
                        gpa,
                        &event_fd,
                    )
                    .map_err(|e| {
                        error!("command completion callback failed: {}", e);
                    })
                })
                .map_err(Error::ResetSlot)
        } else {
            CommandRingTrbHandler::command_completion_callback(
                &self.interrupter,
                TrbCompletionCode::TrbError,
                slot_id,
                atrb.gpa,
                &event_fd,
            )
        }
    }

    fn stop_endpoint(&self, atrb: &AddressedTrb, event_fd: EventFd) -> Result<()> {
        let trb = atrb
            .trb
            .cast::<StopEndpointCommandTrb>()
            .map_err(Error::CastTrb)?;
        let slot_id = trb.get_slot_id();
        let endpoint_id = trb.get_endpoint_id();
        if valid_slot_id(slot_id) {
            let gpa = atrb.gpa;
            let interrupter = self.interrupter.clone();
            self.slots
                .stop_endpoint(slot_id, endpoint_id, move |completion_code| {
                    CommandRingTrbHandler::command_completion_callback(
                        &interrupter,
                        completion_code,
                        slot_id,
                        gpa,
                        &event_fd,
                    )
                    .map_err(|e| {
                        error!("command completion callback failed: {}", e);
                    })
                })
                .map_err(Error::StopEndpoint)?;
            Ok(())
        } else {
            error!("stop endpoint trb has invalid slot id {}", slot_id);
            CommandRingTrbHandler::command_completion_callback(
                &self.interrupter,
                TrbCompletionCode::TrbError,
                slot_id,
                atrb.gpa,
                &event_fd,
            )
        }
    }

    fn set_tr_dequeue_ptr(&self, atrb: &AddressedTrb, event_fd: EventFd) -> Result<()> {
        let trb = atrb
            .trb
            .cast::<SetTRDequeuePointerCommandTrb>()
            .map_err(Error::CastTrb)?;
        let slot_id = trb.get_slot_id();
        let endpoint_id = trb.get_endpoint_id();
        // See Set TR Dequeue Pointer Trb in spec.
        let dequeue_ptr = trb.get_dequeue_ptr().get_gpa().offset();
        let completion_code = {
            if valid_slot_id(slot_id) {
                self.slot(slot_id)?
                    .set_tr_dequeue_ptr(endpoint_id, dequeue_ptr)
                    .map_err(Error::SetDequeuePointer)?
            } else {
                error!("stop endpoint trb has invalid slot id {}", slot_id);
                TrbCompletionCode::TrbError
            }
        };
        CommandRingTrbHandler::command_completion_callback(
            &self.interrupter,
            completion_code,
            slot_id,
            atrb.gpa,
            &event_fd,
        )
    }
}

impl TransferDescriptorHandler for CommandRingTrbHandler {
    fn handle_transfer_descriptor(
        &self,
        descriptor: TransferDescriptor,
        complete_event: EventFd,
    ) -> std::result::Result<(), ()> {
        // Command descriptor always consist of a single TRB.
        assert_eq!(descriptor.len(), 1);
        let atrb = &descriptor[0];
        let command_result = match atrb.trb.get_trb_type() {
            Ok(TrbType::EnableSlotCommand) => self.enable_slot(atrb, complete_event),
            Ok(TrbType::DisableSlotCommand) => self.disable_slot(atrb, complete_event),
            Ok(TrbType::AddressDeviceCommand) => self.address_device(atrb, complete_event),
            Ok(TrbType::ConfigureEndpointCommand) => self.configure_endpoint(atrb, complete_event),
            Ok(TrbType::EvaluateContextCommand) => self.evaluate_context(atrb, complete_event),
            Ok(TrbType::ResetDeviceCommand) => self.reset_device(atrb, complete_event),
            Ok(TrbType::NoopCommand) => CommandRingTrbHandler::command_completion_callback(
                &self.interrupter,
                TrbCompletionCode::Success,
                0,
                atrb.gpa,
                &complete_event,
            ),
            Ok(TrbType::ResetEndpointCommand) => {
                error!(
                    "Receiving reset endpoint command. \
                     It should only happen when cmd ring stall"
                );
                CommandRingTrbHandler::command_completion_callback(
                    &self.interrupter,
                    TrbCompletionCode::TrbError,
                    0,
                    atrb.gpa,
                    &complete_event,
                )
            }
            Ok(TrbType::StopEndpointCommand) => self.stop_endpoint(atrb, complete_event),
            Ok(TrbType::SetTRDequeuePointerCommand) => {
                self.set_tr_dequeue_ptr(atrb, complete_event)
            }
            _ => {
                warn!(
                    // We are not handling type 14,15,16. See table 6.4.6.
                    "Unexpected command ring trb type: {}",
                    atrb.trb
                );
                match self.interrupter.lock().send_command_completion_trb(
                    TrbCompletionCode::TrbError,
                    0,
                    GuestAddress(atrb.gpa),
                ) {
                    Err(e) => Err(Error::SendInterrupt(e)),
                    Ok(_) => complete_event.write(1).map_err(Error::WriteEventFd),
                }
            }
        };
        command_result.map_err(|e| {
            error!("command failed: {}", e);
        })
    }
}

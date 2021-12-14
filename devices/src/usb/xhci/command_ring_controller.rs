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

use anyhow::Context;
use base::{error, warn, Error as SysError, Event};
use remain::sorted;
use std::sync::Arc;
use sync::Mutex;
use thiserror::Error;
use vm_memory::{GuestAddress, GuestMemory};

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("bad slot id: {0}")]
    BadSlotId(u8),
    #[error("failed to cast trb: {0}")]
    CastTrb(TrbError),
    #[error("failed to config endpoint: {0}")]
    ConfigEndpoint(DeviceSlotError),
    #[error("failed to disable slot: {0}")]
    DisableSlot(DeviceSlotError),
    #[error("failed to evaluate context: {0}")]
    EvaluateContext(DeviceSlotError),
    #[error("failed to reset slot: {0}")]
    ResetSlot(DeviceSlotError),
    #[error("failed to send interrupt: {0}")]
    SendInterrupt(InterrupterError),
    #[error("failed to set address: {0}")]
    SetAddress(DeviceSlotError),
    #[error("failed to set dequeue pointer: {0}")]
    SetDequeuePointer(DeviceSlotError),
    #[error("failed to stop endpoint: {0}")]
    StopEndpoint(DeviceSlotError),
    #[error("failed to write event: {0}")]
    WriteEvent(SysError),
}

type Result<T> = std::result::Result<T, Error>;

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
        event: &Event,
    ) -> Result<()> {
        interrupter
            .lock()
            .send_command_completion_trb(completion_code, slot_id, GuestAddress(trb_addr))
            .map_err(Error::SendInterrupt)?;
        event.write(1).map_err(Error::WriteEvent)
    }

    fn enable_slot(&self, atrb: &AddressedTrb, event: Event) -> Result<()> {
        for slot_id in 1..=MAX_SLOTS {
            if self.slot(slot_id)?.enable() {
                return CommandRingTrbHandler::command_completion_callback(
                    &self.interrupter,
                    TrbCompletionCode::Success,
                    slot_id,
                    atrb.gpa,
                    &event,
                );
            }
        }

        CommandRingTrbHandler::command_completion_callback(
            &self.interrupter,
            TrbCompletionCode::NoSlotsAvailableError,
            0,
            atrb.gpa,
            &event,
        )
    }

    fn disable_slot(&self, atrb: &AddressedTrb, event: Event) -> Result<()> {
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
                        &event,
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
                &event,
            )
        }
    }

    fn address_device(&self, atrb: &AddressedTrb, event: Event) -> Result<()> {
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
            &event,
        )
    }

    fn configure_endpoint(&self, atrb: &AddressedTrb, event: Event) -> Result<()> {
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
            &event,
        )
    }

    fn evaluate_context(&self, atrb: &AddressedTrb, event: Event) -> Result<()> {
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
            &event,
        )
    }

    fn reset_device(&self, atrb: &AddressedTrb, event: Event) -> Result<()> {
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
                        &event,
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
                &event,
            )
        }
    }

    fn stop_endpoint(&self, atrb: &AddressedTrb, event: Event) -> Result<()> {
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
                        &event,
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
                &event,
            )
        }
    }

    fn set_tr_dequeue_ptr(&self, atrb: &AddressedTrb, event: Event) -> Result<()> {
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
            &event,
        )
    }
}

impl TransferDescriptorHandler for CommandRingTrbHandler {
    fn handle_transfer_descriptor(
        &self,
        descriptor: TransferDescriptor,
        complete_event: Event,
    ) -> anyhow::Result<()> {
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
                    Ok(_) => complete_event.write(1).map_err(Error::WriteEvent),
                }
            }
        };
        command_result.context("command ring TRB failed")
    }
}

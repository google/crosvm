// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;
use std::sync::Weak;

use anyhow::Context;
use base::Event;
use sync::Mutex;
use vm_memory::GuestMemory;

use super::device_slot::DeviceSlot;
use super::interrupter::Interrupter;
use super::usb_hub::UsbPort;
use super::xhci_abi::TransferDescriptor;
use super::xhci_transfer::XhciTransferManager;
use crate::usb::xhci::ring_buffer_controller::Error as RingBufferControllerError;
use crate::usb::xhci::ring_buffer_controller::RingBufferController;
use crate::usb::xhci::ring_buffer_controller::TransferDescriptorHandler;
use crate::utils::EventLoop;

/// Transfer ring controller manages transfer ring.
pub type TransferRingController = RingBufferController<TransferRingTrbHandler>;

#[derive(Clone)]
pub enum TransferRingControllers {
    Endpoint(Arc<TransferRingController>),
    Stream(Vec<Arc<TransferRingController>>),
}

pub type TransferRingControllerError = RingBufferControllerError;

/// TransferRingTrbHandler handles trbs on transfer ring.
pub struct TransferRingTrbHandler {
    mem: GuestMemory,
    port: Arc<UsbPort>,
    interrupter: Arc<Mutex<Interrupter>>,
    slot_id: u8,
    endpoint_id: u8,
    transfer_manager: XhciTransferManager,
    stream_id: Option<u16>,
}

impl TransferDescriptorHandler for TransferRingTrbHandler {
    fn handle_transfer_descriptor(
        &self,
        descriptor: TransferDescriptor,
        completion_event: Event,
    ) -> anyhow::Result<()> {
        let xhci_transfer = self.transfer_manager.create_transfer(
            self.mem.clone(),
            self.port.clone(),
            self.interrupter.clone(),
            self.slot_id,
            self.endpoint_id,
            descriptor,
            completion_event,
            self.stream_id,
        );
        xhci_transfer
            .send_to_backend_if_valid()
            .context("failed to send transfer to backend")
    }

    fn stop(&self) -> bool {
        let backend = self.port.backend_device();
        if backend.is_some() {
            self.transfer_manager.cancel_all();
            true
        } else {
            false
        }
    }
}

impl TransferRingController {
    pub fn new(
        mem: GuestMemory,
        port: Arc<UsbPort>,
        event_loop: Arc<EventLoop>,
        interrupter: Arc<Mutex<Interrupter>>,
        slot_id: u8,
        endpoint_id: u8,
        device_slot: Weak<DeviceSlot>,
        stream_id: Option<u16>,
    ) -> Result<Arc<TransferRingController>, TransferRingControllerError> {
        RingBufferController::new_with_handler(
            format!("transfer ring slot_{} ep_{}", slot_id, endpoint_id),
            mem.clone(),
            event_loop,
            TransferRingTrbHandler {
                mem,
                port,
                interrupter,
                slot_id,
                endpoint_id,
                transfer_manager: XhciTransferManager::new(device_slot),
                stream_id,
            },
        )
    }
}

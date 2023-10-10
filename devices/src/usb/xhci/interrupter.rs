// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::Error as SysError;
use base::Event;
use remain::sorted;
use thiserror::Error;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

use super::event_ring::Error as EventRingError;
use super::event_ring::EventRing;
use super::xhci_abi::CommandCompletionEventTrb;
use super::xhci_abi::Error as TrbError;
use super::xhci_abi::PortStatusChangeEventTrb;
use super::xhci_abi::TransferEventTrb;
use super::xhci_abi::Trb;
use super::xhci_abi::TrbCast;
use super::xhci_abi::TrbCompletionCode;
use super::xhci_abi::TrbType;
use super::xhci_regs::XhciRegs;
use super::xhci_regs::ERDP_EVENT_HANDLER_BUSY;
use super::xhci_regs::IMAN_INTERRUPT_PENDING;
use super::xhci_regs::USB_STS_EVENT_INTERRUPT;
use crate::register_space::Register;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("cannot add event: {0}")]
    AddEvent(EventRingError),
    #[error("cannot cast trb: {0}")]
    CastTrb(TrbError),
    #[error("cannot send interrupt: {0}")]
    SendInterrupt(SysError),
    #[error("cannot set seg table base addr: {0}")]
    SetSegTableBaseAddr(EventRingError),
    #[error("cannot set seg table size: {0}")]
    SetSegTableSize(EventRingError),
}

type Result<T> = std::result::Result<T, Error>;

/// See spec 4.17 for interrupters. Controller can send an event back to guest kernel driver
/// through interrupter.
pub struct Interrupter {
    interrupt_evt: Event,
    usbsts: Register<u32>,
    iman: Register<u32>,
    erdp: Register<u64>,
    event_handler_busy: bool,
    enabled: bool,
    moderation_interval: u16,
    moderation_counter: u16,
    event_ring: EventRing,
}

impl Interrupter {
    /// Create a new interrupter.
    pub fn new(mem: GuestMemory, irq_evt: Event, regs: &XhciRegs) -> Self {
        Interrupter {
            interrupt_evt: irq_evt,
            usbsts: regs.usbsts.clone(),
            iman: regs.iman.clone(),
            erdp: regs.erdp.clone(),
            event_handler_busy: false,
            enabled: false,
            moderation_interval: 0,
            moderation_counter: 0,
            event_ring: EventRing::new(mem),
        }
    }

    /// Returns true if event ring is empty.
    pub fn event_ring_is_empty(&self) -> bool {
        self.event_ring.is_empty()
    }

    /// Add event to event ring.
    fn add_event(&mut self, trb: Trb) -> Result<()> {
        self.event_ring.add_event(trb).map_err(Error::AddEvent)?;
        self.interrupt_if_needed()
    }

    /// Send port status change trb for port.
    pub fn send_port_status_change_trb(&mut self, port_id: u8) -> Result<()> {
        let mut trb = Trb::new();
        let psctrb = trb
            .cast_mut::<PortStatusChangeEventTrb>()
            .map_err(Error::CastTrb)?;
        psctrb.set_port_id(port_id);
        psctrb.set_completion_code(TrbCompletionCode::Success);
        psctrb.set_trb_type(TrbType::PortStatusChangeEvent);
        self.add_event(trb)
    }

    /// Send command completion trb.
    pub fn send_command_completion_trb(
        &mut self,
        completion_code: TrbCompletionCode,
        slot_id: u8,
        trb_addr: GuestAddress,
    ) -> Result<()> {
        let mut trb = Trb::new();
        let ctrb = trb
            .cast_mut::<CommandCompletionEventTrb>()
            .map_err(Error::CastTrb)?;
        ctrb.set_trb_pointer(trb_addr.0);
        ctrb.set_command_completion_parameter(0);
        ctrb.set_completion_code(completion_code);
        ctrb.set_trb_type(TrbType::CommandCompletionEvent);
        ctrb.set_vf_id(0);
        ctrb.set_slot_id(slot_id);
        self.add_event(trb)
    }

    /// Send transfer event trb.
    pub fn send_transfer_event_trb(
        &mut self,
        completion_code: TrbCompletionCode,
        trb_pointer: u64,
        transfer_length: u32,
        event_data: bool,
        slot_id: u8,
        endpoint_id: u8,
    ) -> Result<()> {
        let mut trb = Trb::new();
        let event_trb = trb.cast_mut::<TransferEventTrb>().map_err(Error::CastTrb)?;
        event_trb.set_trb_pointer(trb_pointer);
        event_trb.set_trb_transfer_length(transfer_length);
        event_trb.set_completion_code(completion_code);
        event_trb.set_event_data(event_data.into());
        event_trb.set_trb_type(TrbType::TransferEvent);
        event_trb.set_endpoint_id(endpoint_id);
        event_trb.set_slot_id(slot_id);
        self.add_event(trb)
    }

    /// Enable/Disable this interrupter.
    pub fn set_enabled(&mut self, enabled: bool) -> Result<()> {
        xhci_trace!("interrupter set_enabled({})", enabled);
        self.enabled = enabled;
        self.interrupt_if_needed()
    }

    /// Set interrupt moderation.
    pub fn set_moderation(&mut self, interval: u16, counter: u16) -> Result<()> {
        // TODO(jkwang) Moderation is not implemented yet.
        self.moderation_interval = interval;
        self.moderation_counter = counter;
        self.interrupt_if_needed()
    }

    /// Set event ring seg table size.
    pub fn set_event_ring_seg_table_size(&mut self, size: u16) -> Result<()> {
        xhci_trace!("interrupter set_event_ring_seg_table_size({})", size);
        self.event_ring
            .set_seg_table_size(size)
            .map_err(Error::SetSegTableSize)
    }

    /// Set event ring segment table base address.
    pub fn set_event_ring_seg_table_base_addr(&mut self, addr: GuestAddress) -> Result<()> {
        xhci_trace!("interrupter set_table_base_addr({:#x})", addr.0);
        self.event_ring
            .set_seg_table_base_addr(addr)
            .map_err(Error::SetSegTableBaseAddr)
    }

    /// Set event ring dequeue pointer.
    pub fn set_event_ring_dequeue_pointer(&mut self, addr: GuestAddress) -> Result<()> {
        xhci_trace!("interrupter set_dequeue_pointer(addr = {:#x})", addr.0);
        self.event_ring.set_dequeue_pointer(addr);
        self.interrupt_if_needed()
    }

    /// Set event hander busy.
    pub fn set_event_handler_busy(&mut self, busy: bool) -> Result<()> {
        xhci_trace!("set_event_handler_busy({})", busy);
        self.event_handler_busy = busy;
        self.interrupt_if_needed()
    }

    /// Send and interrupt.
    pub fn interrupt(&mut self) -> Result<()> {
        self.event_handler_busy = true;
        self.usbsts.set_bits(USB_STS_EVENT_INTERRUPT);
        self.iman.set_bits(IMAN_INTERRUPT_PENDING);
        self.erdp.set_bits(ERDP_EVENT_HANDLER_BUSY);
        self.interrupt_evt.signal().map_err(Error::SendInterrupt)
    }

    fn interrupt_if_needed(&mut self) -> Result<()> {
        // TODO(dverkamp): re-add !self.event_handler_busy after solving https://crbug.com/1082930
        if self.enabled && !self.event_ring.is_empty() {
            self.interrupt()?;
        }
        Ok(())
    }
}

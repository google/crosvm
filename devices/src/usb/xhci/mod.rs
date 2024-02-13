// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(clippy::result_large_err)]

mod command_ring_controller;
mod device_slot;
mod event_ring;
mod interrupter;
mod intr_resample_handler;
mod ring_buffer;
mod ring_buffer_controller;
mod ring_buffer_stop_cb;
mod transfer_ring_controller;
#[allow(dead_code)]
mod xhci_abi;
#[allow(dead_code)]
mod xhci_regs;

pub mod scatter_gather_buffer;
pub mod usb_hub;
pub mod xhci_backend_device;
pub mod xhci_backend_device_provider;
pub mod xhci_controller;
pub mod xhci_transfer;

use std::sync::Arc;
use std::thread;

use base::debug;
use base::error;
use remain::sorted;
use sync::Mutex;
use thiserror::Error;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

use crate::usb::backend::error::Error as BackendProviderError;
use crate::usb::xhci::command_ring_controller::CommandRingController;
use crate::usb::xhci::command_ring_controller::CommandRingControllerError;
use crate::usb::xhci::device_slot::DeviceSlots;
use crate::usb::xhci::device_slot::Error as DeviceSlotError;
use crate::usb::xhci::interrupter::Error as InterrupterError;
use crate::usb::xhci::interrupter::Interrupter;
use crate::usb::xhci::intr_resample_handler::IntrResampleHandler;
use crate::usb::xhci::ring_buffer_stop_cb::RingBufferStopCallback;
use crate::usb::xhci::usb_hub::UsbHub;
use crate::usb::xhci::xhci_backend_device_provider::XhciBackendDeviceProvider;
use crate::usb::xhci::xhci_regs::*;
use crate::utils::Error as UtilsError;
use crate::utils::EventLoop;
use crate::utils::FailHandle;
use crate::IrqLevelEvent;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to clone irq event: {0}")]
    CloneIrqEvent(base::Error),
    #[error("failed to clone resample event: {0}")]
    CloneResampleEvent(base::Error),
    #[error("failed to create command ring controller: {0}")]
    CreateCommandRingController(CommandRingControllerError),
    #[error("failed to enable interrupter: {0}")]
    EnableInterrupter(InterrupterError),
    #[error("failed to get device slot: {0}")]
    GetDeviceSlot(u8),
    #[error("failed to reset port")]
    ResetPort,
    #[error("failed to ring doorbell: {0}")]
    RingDoorbell(DeviceSlotError),
    #[error("failed to send interrupt: {0}")]
    SendInterrupt(InterrupterError),
    #[error("failed to set interrupter moderation: {0}")]
    SetModeration(InterrupterError),
    #[error("failed to setup event ring and event handler busy: {0}")]
    SetupEventRing(InterrupterError),
    #[error("failed to start event loop: {0}")]
    StartEventLoop(UtilsError),
    #[error("failed to start backend provider: {0}")]
    StartProvider(BackendProviderError),
    #[error("failed to start resample handler")]
    StartResampleHandler,
}

type Result<T> = std::result::Result<T, Error>;

/// xHCI controller implementation.
pub struct Xhci {
    fail_handle: Arc<dyn FailHandle>,
    regs: XhciRegs,
    interrupter: Arc<Mutex<Interrupter>>,
    command_ring_controller: Arc<CommandRingController>,
    device_slots: DeviceSlots,
    event_loop: Arc<EventLoop>,
    event_loop_join_handle: Option<thread::JoinHandle<()>>,
    // resample handler and device provider only lives on EventLoop to handle corresponding events.
    // By design, event loop only hold weak reference. We need to keep a strong reference here to
    // keep it alive.
    #[allow(dead_code)]
    intr_resample_handler: Arc<IntrResampleHandler>,
    #[allow(dead_code)]
    device_provider: Box<dyn XhciBackendDeviceProvider>,
}

impl Xhci {
    /// Create a new xHCI controller.
    pub fn new(
        fail_handle: Arc<dyn FailHandle>,
        mem: GuestMemory,
        device_provider: Box<dyn XhciBackendDeviceProvider>,
        interrupt_evt: IrqLevelEvent,
        regs: XhciRegs,
    ) -> Result<Arc<Self>> {
        let (event_loop, join_handle) =
            EventLoop::start("xhci".to_string(), Some(fail_handle.clone()))
                .map_err(Error::StartEventLoop)?;
        let irq_evt = interrupt_evt
            .get_trigger()
            .try_clone()
            .map_err(Error::CloneIrqEvent)?;
        let interrupter = Arc::new(Mutex::new(Interrupter::new(mem.clone(), irq_evt, &regs)));
        let event_loop = Arc::new(event_loop);
        let irq_resample_evt = interrupt_evt
            .get_resample()
            .try_clone()
            .map_err(Error::CloneResampleEvent)?;
        let intr_resample_handler =
            IntrResampleHandler::start(&event_loop, interrupter.clone(), irq_resample_evt)
                .ok_or(Error::StartResampleHandler)?;
        let hub = Arc::new(UsbHub::new(&regs, interrupter.clone()));

        let mut device_provider = device_provider;
        device_provider
            .start(fail_handle.clone(), event_loop.clone(), hub.clone())
            .map_err(Error::StartProvider)?;

        let device_slots = DeviceSlots::new(
            fail_handle.clone(),
            regs.dcbaap.clone(),
            hub,
            interrupter.clone(),
            event_loop.clone(),
            mem.clone(),
        );
        let command_ring_controller = CommandRingController::new(
            mem,
            event_loop.clone(),
            device_slots.clone(),
            interrupter.clone(),
        )
        .map_err(Error::CreateCommandRingController)?;
        let xhci = Arc::new(Xhci {
            fail_handle,
            regs,
            intr_resample_handler,
            interrupter,
            command_ring_controller,
            device_slots,
            device_provider,
            event_loop,
            event_loop_join_handle: Some(join_handle),
        });
        Self::init_reg_callbacks(&xhci);
        Ok(xhci)
    }

    fn init_reg_callbacks(xhci: &Arc<Xhci>) {
        // All the callbacks will hold a weak reference to avoid memory leak. Thos weak upgrade
        // should never fail.
        let xhci_weak = Arc::downgrade(xhci);
        xhci.regs.usbcmd.set_write_cb(move |val: u32| {
            // All the weak reference upgrade should never fail. xhci hold reference to the
            // registers, callback won't be invoked if xhci is gone.
            let xhci = xhci_weak.upgrade().unwrap();
            let r = xhci.usbcmd_callback(val);
            xhci.handle_register_callback_result(r, 0)
        });

        let xhci_weak = Arc::downgrade(xhci);
        xhci.regs.crcr.set_write_cb(move |val: u64| {
            let xhci = xhci_weak.upgrade().unwrap();
            xhci.crcr_callback(val)
        });

        for i in 0..xhci.regs.portsc.len() {
            let xhci_weak = Arc::downgrade(xhci);
            xhci.regs.portsc[i].set_write_cb(move |val: u32| {
                let xhci = xhci_weak.upgrade().unwrap();
                let r = xhci.portsc_callback(i as u32, val);
                xhci.handle_register_callback_result(r, 0)
            });
        }

        for i in 0..xhci.regs.doorbells.len() {
            let xhci_weak = Arc::downgrade(xhci);
            xhci.regs.doorbells[i].set_write_cb(move |val: u32| {
                let xhci = xhci_weak.upgrade().unwrap();
                let r = xhci.doorbell_callback(i as u32, val);
                xhci.handle_register_callback_result(r, ());
                val
            });
        }

        let xhci_weak = Arc::downgrade(xhci);
        xhci.regs.iman.set_write_cb(move |val: u32| {
            let xhci = xhci_weak.upgrade().unwrap();
            let r = xhci.iman_callback(val);
            xhci.handle_register_callback_result(r, ());
            val
        });

        let xhci_weak = Arc::downgrade(xhci);
        xhci.regs.imod.set_write_cb(move |val: u32| {
            let xhci = xhci_weak.upgrade().unwrap();
            let r = xhci.imod_callback(val);
            xhci.handle_register_callback_result(r, ());
            val
        });

        let xhci_weak = Arc::downgrade(xhci);
        xhci.regs.erstsz.set_write_cb(move |val: u32| {
            let xhci = xhci_weak.upgrade().unwrap();
            let r = xhci.erstsz_callback(val);
            xhci.handle_register_callback_result(r, ());
            val
        });

        let xhci_weak = Arc::downgrade(xhci);
        xhci.regs.erstba.set_write_cb(move |val: u64| {
            let xhci = xhci_weak.upgrade().unwrap();
            let r = xhci.erstba_callback(val);
            xhci.handle_register_callback_result(r, ());
            val
        });

        let xhci_weak = Arc::downgrade(xhci);
        xhci.regs.erdp.set_write_cb(move |val: u64| {
            let xhci = xhci_weak.upgrade().unwrap();
            let r = xhci.erdp_callback(val);
            xhci.handle_register_callback_result(r, ());
            val
        });
    }

    fn handle_register_callback_result<T>(&self, r: Result<T>, t: T) -> T {
        match r {
            Ok(v) => v,
            Err(e) => {
                error!("xhci controller failed: {}", e);
                self.fail_handle.fail();
                t
            }
        }
    }

    // Callback for usbcmd register write.
    fn usbcmd_callback(&self, value: u32) -> Result<u32> {
        if (value & USB_CMD_RESET) > 0 {
            debug!("xhci_controller: reset controller");
            self.reset();
            return Ok(value & (!USB_CMD_RESET));
        }

        if (value & USB_CMD_RUNSTOP) > 0 {
            debug!("xhci_controller: clear halt bits");
            self.regs.usbsts.clear_bits(USB_STS_HALTED);
        } else {
            debug!("xhci_controller: halt device");
            self.halt();
            self.regs.crcr.clear_bits(CRCR_COMMAND_RING_RUNNING);
        }

        // Enable interrupter if needed.
        let enabled = (value & USB_CMD_INTERRUPTER_ENABLE) > 0
            && (self.regs.iman.get_value() & IMAN_INTERRUPT_ENABLE) > 0;
        debug!("xhci_controller: interrupter enable?: {}", enabled);
        self.interrupter
            .lock()
            .set_enabled(enabled)
            .map_err(Error::EnableInterrupter)?;
        Ok(value)
    }

    // Callback for crcr register write.
    fn crcr_callback(&self, value: u64) -> u64 {
        let _trace = cros_tracing::trace_event!(USB, "crcr_callback", value);
        if (self.regs.crcr.get_value() & CRCR_COMMAND_RING_RUNNING) == 0 {
            self.command_ring_controller
                .set_dequeue_pointer(GuestAddress(value & CRCR_COMMAND_RING_POINTER));
            self.command_ring_controller
                .set_consumer_cycle_state((value & CRCR_RING_CYCLE_STATE) > 0);
            value
        } else {
            error!("Write to crcr while command ring is running");
            self.regs.crcr.get_value()
        }
    }

    // Callback for portsc register write.
    fn portsc_callback(&self, index: u32, value: u32) -> Result<u32> {
        let _trace = cros_tracing::trace_event!(USB, "portsc_callback", index, value);
        let mut value = value;
        let port_id = (index + 1) as u8;
        // xHCI spec 4.19.5. Note: we might want to change this logic if we support USB 3.0.
        if (value & PORTSC_PORT_RESET) > 0 || (value & PORTSC_WARM_PORT_RESET) > 0 {
            self.device_slots
                .reset_port(port_id)
                .map_err(|_| Error::ResetPort)?;
            value &= !PORTSC_PORT_LINK_STATE_MASK;
            value &= !PORTSC_PORT_RESET;
            value |= PORTSC_PORT_ENABLED;
            value |= PORTSC_PORT_RESET_CHANGE;
            self.interrupter
                .lock()
                .send_port_status_change_trb(port_id)
                .map_err(Error::SendInterrupt)?;
        }
        Ok(value)
    }

    // Callback for doorbell register write.
    fn doorbell_callback(&self, index: u32, value: u32) -> Result<()> {
        let _trace = cros_tracing::trace_event!(USB, "doorbell_callback", index, value);
        let target = (value & DOORBELL_TARGET) as u8;
        let stream_id: u16 = (value >> DOORBELL_STREAM_ID_OFFSET) as u16;
        if (self.regs.usbcmd.get_value() & USB_CMD_RUNSTOP) > 0 {
            // First doorbell is for command ring.
            if index == 0 {
                if target != 0 || stream_id != 0 {
                    return Ok(());
                }
                self.regs.crcr.set_bits(CRCR_COMMAND_RING_RUNNING);
                self.command_ring_controller.start();
            } else {
                self.device_slots
                    .slot(index as u8)
                    .ok_or(Error::GetDeviceSlot(index as u8))?
                    .ring_doorbell(target, stream_id)
                    .map_err(Error::RingDoorbell)?;
            }
        }
        Ok(())
    }

    // Callback for iman register write.
    fn iman_callback(&self, value: u32) -> Result<()> {
        let _trace = cros_tracing::trace_event!(USB, "iman_callback", value);
        let enabled = ((value & IMAN_INTERRUPT_ENABLE) > 0)
            && ((self.regs.usbcmd.get_value() & USB_CMD_INTERRUPTER_ENABLE) > 0);
        self.interrupter
            .lock()
            .set_enabled(enabled)
            .map_err(Error::EnableInterrupter)
    }

    // Callback for imod register write.
    fn imod_callback(&self, value: u32) -> Result<()> {
        let _trace = cros_tracing::trace_event!(USB, "imod_callback", value);
        self.interrupter
            .lock()
            .set_moderation(
                (value & IMOD_INTERRUPT_MODERATION_INTERVAL) as u16,
                (value >> IMOD_INTERRUPT_MODERATION_COUNTER_OFFSET) as u16,
            )
            .map_err(Error::SetModeration)
    }

    // Callback for erstsz register write.
    fn erstsz_callback(&self, value: u32) -> Result<()> {
        let _trace = cros_tracing::trace_event!(USB, "erstsz_callback", value);
        self.interrupter
            .lock()
            .set_event_ring_seg_table_size((value & ERSTSZ_SEGMENT_TABLE_SIZE) as u16)
            .map_err(Error::SetupEventRing)
    }

    // Callback for erstba register write.
    fn erstba_callback(&self, value: u64) -> Result<()> {
        let _trace = cros_tracing::trace_event!(USB, "erstba_callback", value);
        self.interrupter
            .lock()
            .set_event_ring_seg_table_base_addr(GuestAddress(
                value & ERSTBA_SEGMENT_TABLE_BASE_ADDRESS,
            ))
            .map_err(Error::SetupEventRing)
    }

    // Callback for erdp register write.
    fn erdp_callback(&self, value: u64) -> Result<()> {
        let _trace = cros_tracing::trace_event!(USB, "erdp_callback", value);
        self.interrupter
            .lock()
            .set_event_ring_dequeue_pointer(
                GuestAddress(value & ERDP_EVENT_RING_DEQUEUE_POINTER),
                (value & ERDP_EVENT_HANDLER_BUSY) > 0,
            )
            .map_err(Error::SetupEventRing)
    }

    fn reset(&self) {
        self.regs.usbsts.set_bits(USB_STS_CONTROLLER_NOT_READY);
        let usbsts = self.regs.usbsts.clone();
        self.device_slots.stop_all_and_reset(move || {
            usbsts.clear_bits(USB_STS_CONTROLLER_NOT_READY);
        });
    }

    fn halt(&self) {
        let usbsts = self.regs.usbsts.clone();
        self.device_slots
            .stop_all(RingBufferStopCallback::new(move || {
                usbsts.set_bits(USB_STS_HALTED);
            }));
    }
}

impl Drop for Xhci {
    fn drop(&mut self) {
        self.event_loop.stop();
        if let Some(join_handle) = self.event_loop_join_handle.take() {
            let _ = join_handle.join();
        }
    }
}

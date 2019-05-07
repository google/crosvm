// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::command_ring_controller::{CommandRingController, CommandRingControllerError};
use super::device_slot::{DeviceSlots, Error as DeviceSlotError};
use super::interrupter::{Error as InterrupterError, Interrupter};
use super::intr_resample_handler::IntrResampleHandler;
use super::ring_buffer_stop_cb::RingBufferStopCallback;
use super::usb_hub::UsbHub;
use super::xhci_backend_device_provider::XhciBackendDeviceProvider;
use super::xhci_regs::*;
use crate::usb::host_backend::host_backend_device_provider::HostBackendDeviceProvider;
use crate::utils::{Error as UtilsError, EventLoop, FailHandle};
use std::fmt::{self, Display};
use std::sync::Arc;
use sync::Mutex;
use sys_util::{error, EventFd, GuestAddress, GuestMemory};

#[derive(Debug)]
pub enum Error {
    StartEventLoop(UtilsError),
    GetDeviceSlot(u8),
    StartResampleHandler,
    SendInterrupt(InterrupterError),
    EnableInterrupter(InterrupterError),
    SetModeration(InterrupterError),
    SetupEventRing(InterrupterError),
    SetEventHandlerBusy(InterrupterError),
    StartProvider,
    RingDoorbell(DeviceSlotError),
    CreateCommandRingController(CommandRingControllerError),
    ResetPort,
}

type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match self {
            StartEventLoop(e) => write!(f, "failed to start event loop: {}", e),
            GetDeviceSlot(i) => write!(f, "failed to get device slot: {}", i),
            StartResampleHandler => write!(f, "failed to start resample handler"),
            SendInterrupt(e) => write!(f, "failed to send interrupter: {}", e),
            EnableInterrupter(e) => write!(f, "failed to enable interrupter: {}", e),
            SetModeration(e) => write!(f, "failed to set interrupter moderation: {}", e),
            SetupEventRing(e) => write!(f, "failed to setup event ring: {}", e),
            SetEventHandlerBusy(e) => write!(f, "failed to set event handler busy: {}", e),
            StartProvider => write!(f, "failed to start backend provider"),
            RingDoorbell(e) => write!(f, "failed to ring doorbell: {}", e),
            CreateCommandRingController(e) => {
                write!(f, "failed to create command ring controller: {}", e)
            }
            ResetPort => write!(f, "failed to reset port"),
        }
    }
}

/// xHCI controller implementation.
pub struct Xhci {
    fail_handle: Arc<dyn FailHandle>,
    regs: XhciRegs,
    interrupter: Arc<Mutex<Interrupter>>,
    command_ring_controller: Arc<CommandRingController>,
    device_slots: DeviceSlots,
    // resample handler and device provider only lives on EventLoop to handle corresponding events.
    // By design, event loop only hold weak reference. We need to keep a strong reference here to
    // keep it alive.
    #[allow(dead_code)]
    intr_resample_handler: Arc<IntrResampleHandler>,
    #[allow(dead_code)]
    device_provider: HostBackendDeviceProvider,
}

impl Xhci {
    /// Create a new xHCI controller.
    pub fn new(
        fail_handle: Arc<dyn FailHandle>,
        mem: GuestMemory,
        device_provider: HostBackendDeviceProvider,
        irq_evt: EventFd,
        irq_resample_evt: EventFd,
        regs: XhciRegs,
    ) -> Result<Arc<Self>> {
        let (event_loop, _join_handle) =
            EventLoop::start("xhci".to_string(), Some(fail_handle.clone()))
                .map_err(Error::StartEventLoop)?;
        let interrupter = Arc::new(Mutex::new(Interrupter::new(mem.clone(), irq_evt, &regs)));
        let event_loop = Arc::new(event_loop);
        let intr_resample_handler =
            IntrResampleHandler::start(&event_loop, interrupter.clone(), irq_resample_evt)
                .ok_or(Error::StartResampleHandler)?;
        let hub = Arc::new(UsbHub::new(&regs, interrupter.clone()));

        let mut device_provider = device_provider;
        device_provider
            .start(fail_handle.clone(), event_loop.clone(), hub.clone())
            .map_err(|_| Error::StartProvider)?;

        let device_slots = DeviceSlots::new(
            fail_handle.clone(),
            regs.dcbaap.clone(),
            hub.clone(),
            interrupter.clone(),
            event_loop.clone(),
            mem.clone(),
        );
        let command_ring_controller = CommandRingController::new(
            mem.clone(),
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
            let r = xhci.crcr_callback(val);
            xhci.handle_register_callback_result(r, 0)
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
            usb_debug!("xhci_controller: reset controller");
            self.reset()?;
            return Ok(value & (!USB_CMD_RESET));
        }

        if (value & USB_CMD_RUNSTOP) > 0 {
            usb_debug!("xhci_controller: clear halt bits");
            self.regs.usbsts.clear_bits(USB_STS_HALTED);
        } else {
            usb_debug!("xhci_controller: halt device");
            self.halt()?;
            self.regs.crcr.clear_bits(CRCR_COMMAND_RING_RUNNING);
        }

        // Enable interrupter if needed.
        let enabled = (value & USB_CMD_INTERRUPTER_ENABLE) > 0
            && (self.regs.iman.get_value() & IMAN_INTERRUPT_ENABLE) > 0;
        usb_debug!("xhci_controller: interrupter enable?: {}", enabled);
        self.interrupter
            .lock()
            .set_enabled(enabled)
            .map_err(Error::EnableInterrupter)?;
        Ok(value)
    }

    // Callback for crcr register write.
    fn crcr_callback(&self, value: u64) -> Result<u64> {
        usb_debug!("xhci_controller: write to crcr {:x}", value);
        let value = if (self.regs.crcr.get_value() & CRCR_COMMAND_RING_RUNNING) == 0 {
            self.command_ring_controller
                .set_dequeue_pointer(GuestAddress(value & CRCR_COMMAND_RING_POINTER));
            self.command_ring_controller
                .set_consumer_cycle_state((value & CRCR_RING_CYCLE_STATE) > 0);
            value
        } else {
            error!("Write to crcr while command ring is running");
            self.regs.crcr.get_value()
        };
        Ok(value)
    }

    // Callback for portsc register write.
    fn portsc_callback(&self, index: u32, value: u32) -> Result<u32> {
        let mut value = value;
        usb_debug!(
            "xhci_controller: write to portsc index {} value {:x}",
            index,
            value
        );
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
        usb_debug!(
            "xhci_controller: write to doorbell index {} value {:x}",
            index,
            value
        );
        let target = (value & DOORBELL_TARGET) as u8;
        let stream_id: u16 = (value >> DOORBELL_STREAM_ID_OFFSET) as u16;
        if (self.regs.usbcmd.get_value() & USB_CMD_RUNSTOP) > 0 {
            // First doorbell is for command ring.
            if index == 0 {
                if target != 0 || stream_id != 0 {
                    return Ok(());
                }
                usb_debug!("doorbell to command ring");
                self.regs.crcr.set_bits(CRCR_COMMAND_RING_RUNNING);
                self.command_ring_controller.start();
            } else {
                usb_debug!("doorbell to device slot");
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
        usb_debug!("xhci_controller: write to iman {:x}", value);
        let enabled = ((value & IMAN_INTERRUPT_ENABLE) > 0)
            && ((self.regs.usbcmd.get_value() & USB_CMD_INTERRUPTER_ENABLE) > 0);
        self.interrupter
            .lock()
            .set_enabled(enabled)
            .map_err(Error::EnableInterrupter)
    }

    // Callback for imod register write.
    fn imod_callback(&self, value: u32) -> Result<()> {
        usb_debug!("xhci_controller: write to imod {:x}", value);
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
        usb_debug!("xhci_controller: write to erstz {:x}", value);
        self.interrupter
            .lock()
            .set_event_ring_seg_table_size((value & ERSTSZ_SEGMENT_TABLE_SIZE) as u16)
            .map_err(Error::SetupEventRing)
    }

    // Callback for erstba register write.
    fn erstba_callback(&self, value: u64) -> Result<()> {
        usb_debug!("xhci_controller: write to erstba {:x}", value);
        self.interrupter
            .lock()
            .set_event_ring_seg_table_base_addr(GuestAddress(
                value & ERSTBA_SEGMENT_TABLE_BASE_ADDRESS,
            ))
            .map_err(Error::SetupEventRing)
    }

    // Callback for erdp register write.
    fn erdp_callback(&self, value: u64) -> Result<()> {
        usb_debug!("xhci_controller: write to erdp {:x}", value);
        let mut interrupter = self.interrupter.lock();
        interrupter
            .set_event_ring_dequeue_pointer(GuestAddress(value & ERDP_EVENT_RING_DEQUEUE_POINTER))
            .map_err(Error::SetupEventRing)?;
        interrupter
            .set_event_handler_busy((value & ERDP_EVENT_HANDLER_BUSY) > 0)
            .map_err(Error::SetEventHandlerBusy)
    }

    fn reset(&self) -> Result<()> {
        self.regs.usbsts.set_bits(USB_STS_CONTROLLER_NOT_READY);
        let usbsts = self.regs.usbsts.clone();
        self.device_slots.stop_all_and_reset(move || {
            usbsts.clear_bits(USB_STS_CONTROLLER_NOT_READY);
        });
        Ok(())
    }

    fn halt(&self) -> Result<()> {
        let usbsts = self.regs.usbsts.clone();
        self.device_slots
            .stop_all(RingBufferStopCallback::new(move || {
                usbsts.set_bits(USB_STS_HALTED);
            }));
        Ok(())
    }
}

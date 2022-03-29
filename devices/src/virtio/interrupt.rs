// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::{INTERRUPT_STATUS_CONFIG_CHANGED, INTERRUPT_STATUS_USED_RING, VIRTIO_MSI_NO_VECTOR};
use crate::irq_event::IrqLevelEvent;
use crate::pci::MsixConfig;
use base::Event;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use sync::Mutex;

pub trait SignalableInterrupt {
    /// Writes to the irqfd to VMM to deliver virtual interrupt to the guest.
    fn signal(&self, vector: u16, interrupt_status_mask: u32);

    /// Notify the driver that buffers have been placed in the used queue.
    fn signal_used_queue(&self, vector: u16) {
        self.signal(vector, INTERRUPT_STATUS_USED_RING)
    }

    /// Notify the driver that the device configuration has changed.
    fn signal_config_changed(&self);

    /// Get the event to signal resampling is needed if it exists.
    fn get_resample_evt(&self) -> Option<&Event>;

    /// Reads the status and writes to the interrupt event. Doesn't read the resample event, it
    /// assumes the resample has been requested.
    fn do_interrupt_resample(&self);
}

pub struct Interrupt {
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: IrqLevelEvent,
    msix_config: Option<Arc<Mutex<MsixConfig>>>,
    config_msix_vector: u16,
}

impl SignalableInterrupt for Interrupt {
    /// Virtqueue Interrupts From The Device
    ///
    /// If MSI-X is enabled in this device, MSI-X interrupt is preferred.
    /// Write to the irqfd to VMM to deliver virtual interrupt to the guest
    fn signal(&self, vector: u16, interrupt_status_mask: u32) {
        // Don't need to set ISR for MSI-X interrupts
        if let Some(msix_config) = &self.msix_config {
            let mut msix_config = msix_config.lock();
            if msix_config.enabled() {
                if vector != VIRTIO_MSI_NO_VECTOR {
                    msix_config.trigger(vector);
                }
                return;
            }
        }

        // Set bit in ISR and inject the interrupt if it was not already pending.
        // Don't need to inject the interrupt if the guest hasn't processed it.
        if self
            .interrupt_status
            .fetch_or(interrupt_status_mask as usize, Ordering::SeqCst)
            == 0
        {
            // Write to irqfd to inject INTx interrupt
            self.interrupt_evt.trigger().unwrap();
        }
    }

    fn signal_config_changed(&self) {
        self.signal(self.config_msix_vector, INTERRUPT_STATUS_CONFIG_CHANGED)
    }

    fn get_resample_evt(&self) -> Option<&Event> {
        Some(self.interrupt_evt.get_resample())
    }

    fn do_interrupt_resample(&self) {
        if self.interrupt_status.load(Ordering::SeqCst) != 0 {
            self.interrupt_evt.trigger().unwrap();
        }
    }
}

impl<I: SignalableInterrupt> SignalableInterrupt for Arc<Mutex<I>> {
    fn signal(&self, vector: u16, interrupt_status_mask: u32) {
        self.lock().signal(vector, interrupt_status_mask);
    }

    fn signal_used_queue(&self, vector: u16) {
        self.lock().signal_used_queue(vector);
    }

    fn signal_config_changed(&self) {
        self.lock().signal_config_changed();
    }

    fn get_resample_evt(&self) -> Option<&Event> {
        // Cannot get resample event from a borrowed item.
        None
    }

    fn do_interrupt_resample(&self) {}
}

impl<I: SignalableInterrupt> SignalableInterrupt for Rc<RefCell<I>> {
    fn signal(&self, vector: u16, interrupt_status_mask: u32) {
        self.borrow().signal(vector, interrupt_status_mask);
    }

    fn signal_used_queue(&self, vector: u16) {
        self.borrow().signal_used_queue(vector);
    }

    fn signal_config_changed(&self) {
        self.borrow().signal_config_changed();
    }

    fn get_resample_evt(&self) -> Option<&Event> {
        // Cannot get resample event from a borrowed item.
        None
    }

    fn do_interrupt_resample(&self) {}
}

impl Interrupt {
    pub fn new(
        interrupt_status: Arc<AtomicUsize>,
        interrupt_evt: IrqLevelEvent,
        msix_config: Option<Arc<Mutex<MsixConfig>>>,
        config_msix_vector: u16,
    ) -> Interrupt {
        Interrupt {
            interrupt_status,
            interrupt_evt,
            msix_config,
            config_msix_vector,
        }
    }

    /// Get a reference to the interrupt event.
    pub fn get_interrupt_evt(&self) -> &Event {
        self.interrupt_evt.get_trigger()
    }

    /// Handle interrupt resampling event, reading the value from the event and doing the resample.
    pub fn interrupt_resample(&self) {
        self.interrupt_evt.clear_resample();
        self.do_interrupt_resample();
    }

    /// Get a reference to the msix configuration
    pub fn get_msix_config(&self) -> &Option<Arc<Mutex<MsixConfig>>> {
        &self.msix_config
    }
}

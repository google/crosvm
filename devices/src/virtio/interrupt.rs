// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::{INTERRUPT_STATUS_CONFIG_CHANGED, INTERRUPT_STATUS_USED_RING};
use crate::pci::MsixConfig;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use sync::Mutex;
use sys_util::EventFd;

pub struct Interrupt {
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    interrupt_resample_evt: EventFd,
    msix_config: Option<Arc<Mutex<MsixConfig>>>,
}

impl Interrupt {
    pub fn new(
        interrupt_status: Arc<AtomicUsize>,
        interrupt_evt: EventFd,
        interrupt_resample_evt: EventFd,
        msix_config: Option<Arc<Mutex<MsixConfig>>>,
    ) -> Interrupt {
        Interrupt {
            interrupt_status,
            interrupt_evt,
            interrupt_resample_evt,
            msix_config,
        }
    }

    /// Virtqueue Interrupts From The Device
    ///
    /// If MSI-X is enabled in this device, MSI-X interrupt is preferred.
    /// Write to the irqfd to VMM to deliver virtual interrupt to the guest
    pub fn signal_used_queue(&self, vector: u16) {
        // Don't need to set ISR for MSI-X interrupts
        if let Some(msix_config) = &self.msix_config {
            let mut msix_config = msix_config.lock();
            if msix_config.enabled() {
                msix_config.trigger(vector);
                return;
            }
        }

        // Set BIT0 in ISR and inject the interrupt if it was not already pending.
        // Don't need to inject the interrupt if the guest hasn't processed it.
        if self
            .interrupt_status
            .fetch_or(INTERRUPT_STATUS_USED_RING as usize, Ordering::SeqCst)
            == 0
        {
            // Write to irqfd to inject INTx interrupt
            self.interrupt_evt.write(1).unwrap();
        }
    }

    /// Notification of Device Configuration Changes
    /// Set BIT1 in ISR and write to irqfd
    pub fn signal_config_changed(&self) {
        self.interrupt_status
            .fetch_or(INTERRUPT_STATUS_CONFIG_CHANGED as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).unwrap();
    }

    /// Handle interrupt resampling event
    pub fn interrupt_resample(&self) {
        let _ = self.interrupt_resample_evt.read();
        if self.interrupt_status.load(Ordering::SeqCst) != 0 {
            self.interrupt_evt.write(1).unwrap();
        }
    }

    /// Return the reference of interrupt_resample_evt
    /// To keep the interface clean, this member is private.
    pub fn get_resample_evt(&self) -> &EventFd {
        &self.interrupt_resample_evt
    }
}

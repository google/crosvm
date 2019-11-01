// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::{INTERRUPT_STATUS_CONFIG_CHANGED, INTERRUPT_STATUS_USED_RING, VIRTIO_MSI_NO_VECTOR};
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
    config_msix_vector: u16,
}

impl Interrupt {
    pub fn new(
        interrupt_status: Arc<AtomicUsize>,
        interrupt_evt: EventFd,
        interrupt_resample_evt: EventFd,
        msix_config: Option<Arc<Mutex<MsixConfig>>>,
        config_msix_vector: u16,
    ) -> Interrupt {
        Interrupt {
            interrupt_status,
            interrupt_evt,
            interrupt_resample_evt,
            msix_config,
            config_msix_vector,
        }
    }

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
            self.interrupt_evt.write(1).unwrap();
        }
    }

    /// Notify the driver that buffers have been placed in the used queue.
    pub fn signal_used_queue(&self, vector: u16) {
        self.signal(vector, INTERRUPT_STATUS_USED_RING)
    }

    /// Notify the driver that the device configuration has changed.
    pub fn signal_config_changed(&self) {
        self.signal(self.config_msix_vector, INTERRUPT_STATUS_CONFIG_CHANGED)
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

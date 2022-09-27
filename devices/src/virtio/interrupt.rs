// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use base::Event;
use sync::Mutex;

use super::INTERRUPT_STATUS_CONFIG_CHANGED;
use super::INTERRUPT_STATUS_USED_RING;
use super::VIRTIO_MSI_NO_VECTOR;
use crate::irq_event::IrqEdgeEvent;
use crate::irq_event::IrqLevelEvent;
use crate::pci::MsixConfig;

pub trait SignalableInterrupt: Clone {
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

struct TransportPci {
    irq_evt_lvl: IrqLevelEvent,
    msix_config: Option<Arc<Mutex<MsixConfig>>>,
    config_msix_vector: u16,
}

enum Transport {
    Pci { pci: TransportPci },
    Mmio { irq_evt_edge: IrqEdgeEvent },
}

struct InterruptInner {
    interrupt_status: AtomicUsize,
    transport: Transport,
    async_intr_status: bool,
}

#[derive(Clone)]
pub struct Interrupt {
    inner: Arc<InterruptInner>,
}

impl SignalableInterrupt for Interrupt {
    /// Virtqueue Interrupts From The Device
    ///
    /// If MSI-X is enabled in this device, MSI-X interrupt is preferred.
    /// Write to the irqfd to VMM to deliver virtual interrupt to the guest
    fn signal(&self, vector: u16, interrupt_status_mask: u32) {
        // Don't need to set ISR for MSI-X interrupts
        if let Transport::Pci { pci } = &self.inner.as_ref().transport {
            if let Some(msix_config) = &pci.msix_config {
                let mut msix_config = msix_config.lock();
                if msix_config.enabled() {
                    if vector != VIRTIO_MSI_NO_VECTOR {
                        msix_config.trigger(vector);
                    }
                    return;
                }
            }
        }

        // Set bit in ISR and inject the interrupt if it was not already pending.
        // Don't need to inject the interrupt if the guest hasn't processed it.
        // In hypervisors where interrupt_status is updated asynchronously, inject the
        // interrupt even if the previous interrupt appears to be already pending.
        if self
            .inner
            .as_ref()
            .interrupt_status
            .fetch_or(interrupt_status_mask as usize, Ordering::SeqCst)
            == 0
            || self.inner.as_ref().async_intr_status
        {
            // Write to irqfd to inject PCI INTx or MMIO interrupt
            match &self.inner.as_ref().transport {
                Transport::Pci { pci } => pci.irq_evt_lvl.trigger().unwrap(),
                Transport::Mmio { irq_evt_edge } => irq_evt_edge.trigger().unwrap(),
            }
        }
    }

    fn signal_config_changed(&self) {
        let vector = match &self.inner.as_ref().transport {
            Transport::Pci { pci } => pci.config_msix_vector,
            _ => VIRTIO_MSI_NO_VECTOR,
        };
        self.signal(vector, INTERRUPT_STATUS_CONFIG_CHANGED)
    }

    fn get_resample_evt(&self) -> Option<&Event> {
        match &self.inner.as_ref().transport {
            Transport::Pci { pci } => Some(pci.irq_evt_lvl.get_resample()),
            _ => None,
        }
    }

    fn do_interrupt_resample(&self) {
        if self.inner.interrupt_status.load(Ordering::SeqCst) != 0 {
            match &self.inner.as_ref().transport {
                Transport::Pci { pci } => pci.irq_evt_lvl.trigger().unwrap(),
                _ => panic!("do_interrupt_resample() not supported"),
            }
        }
    }
}

impl Interrupt {
    pub fn new(
        irq_evt_lvl: IrqLevelEvent,
        msix_config: Option<Arc<Mutex<MsixConfig>>>,
        config_msix_vector: u16,
    ) -> Interrupt {
        Interrupt {
            inner: Arc::new(InterruptInner {
                interrupt_status: AtomicUsize::new(0),
                async_intr_status: false,
                transport: Transport::Pci {
                    pci: TransportPci {
                        irq_evt_lvl,
                        msix_config,
                        config_msix_vector,
                    },
                },
            }),
        }
    }

    pub fn new_mmio(irq_evt_edge: IrqEdgeEvent, async_intr_status: bool) -> Interrupt {
        Interrupt {
            inner: Arc::new(InterruptInner {
                interrupt_status: AtomicUsize::new(0),
                transport: Transport::Mmio { irq_evt_edge },
                async_intr_status,
            }),
        }
    }

    /// Get a reference to the interrupt event.
    pub fn get_interrupt_evt(&self) -> &Event {
        match &self.inner.as_ref().transport {
            Transport::Pci { pci } => pci.irq_evt_lvl.get_trigger(),
            Transport::Mmio { irq_evt_edge } => irq_evt_edge.get_trigger(),
        }
    }

    /// Handle interrupt resampling event, reading the value from the event and doing the resample.
    pub fn interrupt_resample(&self) {
        match &self.inner.as_ref().transport {
            Transport::Pci { pci } => {
                pci.irq_evt_lvl.clear_resample();
                self.do_interrupt_resample();
            }
            _ => panic!("interrupt_resample() not supported"),
        }
    }

    /// Get a reference to the msix configuration
    pub fn get_msix_config(&self) -> &Option<Arc<Mutex<MsixConfig>>> {
        match &self.inner.as_ref().transport {
            Transport::Pci { pci } => &pci.msix_config,
            _ => &None,
        }
    }

    /// Reads the current value of the interrupt status.
    pub fn read_interrupt_status(&self) -> u8 {
        self.inner.interrupt_status.load(Ordering::SeqCst) as u8
    }

    /// Reads the current value of the interrupt status and resets it to 0.
    pub fn read_and_reset_interrupt_status(&self) -> u8 {
        self.inner.interrupt_status.swap(0, Ordering::SeqCst) as u8
    }

    /// Clear the bits set in `mask` in the interrupt status.
    pub fn clear_interrupt_status_bits(&self, mask: u8) {
        self.inner
            .interrupt_status
            .fetch_and(!(mask as usize), Ordering::SeqCst);
    }
}

// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::AsRawDescriptor;
use base::AsRawDescriptors;
use base::Event;
use base::RawDescriptor;
use base::Result;
use serde::Deserialize;
use serde::Serialize;

/// A structure suitable for implementing edge triggered interrupts in device backends.
pub struct IrqEdgeEvent(Event);

impl IrqEdgeEvent {
    pub fn new() -> Result<IrqEdgeEvent> {
        Event::new().map(IrqEdgeEvent)
    }

    pub fn try_clone(&self) -> Result<IrqEdgeEvent> {
        self.0.try_clone().map(IrqEdgeEvent)
    }

    /// Creates an instance of IrqLevelEvent from an existing event.
    pub fn from_event(trigger_evt: Event) -> IrqEdgeEvent {
        IrqEdgeEvent(trigger_evt)
    }

    pub fn get_trigger(&self) -> &Event {
        &self.0
    }

    pub fn trigger(&self) -> Result<()> {
        self.0.signal()
    }

    pub fn clear_trigger(&self) {
        let _ = self.0.wait();
    }
}

/// A structure suitable for implementing level triggered interrupts in device backends.
///
/// Level-triggered interrupts require the device to monitor a resample event from the IRQ chip,
/// which can be retrieved with [`IrqLevelEvent::get_resample()`]. When the guest OS acknowledges
/// the interrupt with an End of Interrupt (EOI) command, the IRQ chip will signal the resample
/// event. Each time the resample event is signalled, the device should re-check its state and call
/// [`IrqLevelEvent::trigger()`] again if the interrupt should still be asserted.
#[derive(Debug, Serialize, Deserialize)]
pub struct IrqLevelEvent {
    /// An event used by the device backend to signal hypervisor/VM about data or new unit
    /// of work being available.
    trigger_evt: Event,
    /// An event used by the hypervisor to signal device backend that it completed processing a unit
    /// of work and that device should re-raise `trigger_evt` if additional work needs to be done.
    resample_evt: Event,
}

impl IrqLevelEvent {
    pub fn new() -> Result<IrqLevelEvent> {
        let trigger_evt = Event::new()?;
        let resample_evt = Event::new()?;
        Ok(IrqLevelEvent {
            trigger_evt,
            resample_evt,
        })
    }

    pub fn try_clone(&self) -> Result<IrqLevelEvent> {
        let trigger_evt = self.trigger_evt.try_clone()?;
        let resample_evt = self.resample_evt.try_clone()?;
        Ok(IrqLevelEvent {
            trigger_evt,
            resample_evt,
        })
    }

    /// Creates an instance of IrqLevelEvent from an existing pair of events.
    pub fn from_event_pair(trigger_evt: Event, resample_evt: Event) -> IrqLevelEvent {
        IrqLevelEvent {
            trigger_evt,
            resample_evt,
        }
    }

    pub fn get_trigger(&self) -> &Event {
        &self.trigger_evt
    }

    pub fn get_resample(&self) -> &Event {
        &self.resample_evt
    }

    /// Allows backend to inject interrupt (typically into guest).
    pub fn trigger(&self) -> Result<()> {
        self.trigger_evt.signal()
    }

    /// Allows code servicing interrupt to consume or clear the event.
    pub fn clear_trigger(&self) {
        let _ = self.trigger_evt.wait();
    }

    /// Allows code servicing interrupt to signal that processing is done and that the backend
    /// should go ahead and re-trigger it if there is more work needs to be done.
    /// Note that typically resampling is signalled not by individual backends, but rather
    /// by the code implementing interrupt controller.
    pub fn trigger_resample(&self) -> Result<()> {
        self.resample_evt.signal()
    }

    /// Allows backend to consume or clear the resample event.
    pub fn clear_resample(&self) {
        let _ = self.resample_evt.wait();
    }
}

impl AsRawDescriptors for IrqEdgeEvent {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        vec![self.0.as_raw_descriptor()]
    }
}

impl AsRawDescriptors for IrqLevelEvent {
    fn as_raw_descriptors(&self) -> Vec<RawDescriptor> {
        vec![
            self.trigger_evt.as_raw_descriptor(),
            self.resample_evt.as_raw_descriptor(),
        ]
    }
}

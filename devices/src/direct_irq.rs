// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::mem::size_of;

use base::ioctl_with_ref;
use base::AsRawDescriptor;
use base::Event;
use base::RawDescriptor;
use data_model::vec_with_array_field;
use remain::sorted;
use thiserror::Error;
use vfio_sys::*;

use crate::ACPIPMFixedEvent;
use crate::IrqEdgeEvent;
use crate::IrqLevelEvent;

#[sorted]
#[derive(Error, Debug)]
pub enum DirectIrqError {
    #[error("failed to clone trigger event: {0}")]
    CloneEvent(base::Error),
    #[error("failed to clone resample event: {0}")]
    CloneResampleEvent(base::Error),
    #[error("failed to enable direct irq")]
    Enable,
    #[error("failed to enable fixed event irq")]
    EnableFixedEvent,
    #[error("failed to enable gpe irq")]
    EnableGpe,
    #[error("failed to enable direct sci irq")]
    EnableSci,
    #[error("failed to open /dev/plat-irq-forward: {0}")]
    Open(io::Error),
}

pub struct DirectIrq {
    dev: File,
    trigger: Event,
    resample: Option<Event>,
    sci_irq_prepared: bool,
}

impl DirectIrq {
    fn new(trigger_evt: &Event, resample_evt: Option<&Event>) -> Result<Self, DirectIrqError> {
        let trigger = trigger_evt
            .try_clone()
            .map_err(DirectIrqError::CloneEvent)?;
        let resample = if let Some(event) = resample_evt {
            Some(
                event
                    .try_clone()
                    .map_err(DirectIrqError::CloneResampleEvent)?,
            )
        } else {
            None
        };
        let dev = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/plat-irq-forward")
            .map_err(DirectIrqError::Open)?;
        Ok(DirectIrq {
            dev,
            trigger,
            resample,
            sci_irq_prepared: false,
        })
    }

    /// Create DirectIrq object to access hardware edge triggered interrupts.
    pub fn new_edge(irq_evt: &IrqEdgeEvent) -> Result<Self, DirectIrqError> {
        DirectIrq::new(irq_evt.get_trigger(), None)
    }

    /// Create DirectIrq object to access hardware level triggered interrupts.
    pub fn new_level(irq_evt: &IrqLevelEvent) -> Result<Self, DirectIrqError> {
        DirectIrq::new(irq_evt.get_trigger(), Some(irq_evt.get_resample()))
    }

    /// Enable hardware triggered interrupt handling.
    ///
    /// Note: this feature is not part of VFIO, but provides
    /// missing IRQ forwarding functionality.
    ///
    /// # Arguments
    ///
    /// * `irq_num` - host interrupt number (GSI).
    ///
    pub fn irq_enable(&self, irq_num: u32) -> Result<(), DirectIrqError> {
        if let Some(resample) = &self.resample {
            self.plat_irq_ioctl(
                irq_num,
                PLAT_IRQ_FORWARD_SET_LEVEL_TRIGGER_EVENTFD,
                self.trigger.as_raw_descriptor(),
            )?;
            self.plat_irq_ioctl(
                irq_num,
                PLAT_IRQ_FORWARD_SET_LEVEL_UNMASK_EVENTFD,
                resample.as_raw_descriptor(),
            )?;
        } else {
            self.plat_irq_ioctl(
                irq_num,
                PLAT_IRQ_FORWARD_SET_EDGE_TRIGGER,
                self.trigger.as_raw_descriptor(),
            )?;
        };

        Ok(())
    }

    /// Enable hardware triggered SCI interrupt handling for GPE or fixed events.
    ///
    /// Note: sci_irq_prepare() itself does not enable SCI forwarding yet
    /// but configures it so it can be enabled for selected GPEs or fixed events
    /// using gpe_enable_forwarding() or fixed_event_enable_forwarding().
    pub fn sci_irq_prepare(&mut self) -> Result<(), DirectIrqError> {
        if let Some(resample) = &self.resample {
            self.plat_irq_ioctl(
                0,
                PLAT_IRQ_FORWARD_SET_LEVEL_ACPI_SCI_TRIGGER_EVENTFD,
                self.trigger.as_raw_descriptor(),
            )?;
            self.plat_irq_ioctl(
                0,
                PLAT_IRQ_FORWARD_SET_LEVEL_ACPI_SCI_UNMASK_EVENTFD,
                resample.as_raw_descriptor(),
            )?;
        } else {
            return Err(DirectIrqError::EnableSci);
        }

        self.sci_irq_prepared = true;

        Ok(())
    }

    fn plat_irq_ioctl(
        &self,
        irq_num: u32,
        action: u32,
        fd: RawDescriptor,
    ) -> Result<(), DirectIrqError> {
        let count = 1;
        let u32_size = size_of::<u32>();
        let mut irq_set = vec_with_array_field::<plat_irq_forward_set, u32>(count);
        irq_set[0].argsz = (size_of::<plat_irq_forward_set>() + count * u32_size) as u32;
        irq_set[0].action_flags = action;
        irq_set[0].count = count as u32;
        irq_set[0].irq_number_host = irq_num;
        // Safe as we are the owner of irq_set and allocation provides enough space for
        // eventfd array.
        let data = unsafe { irq_set[0].eventfd.as_mut_slice(count * u32_size) };
        let (left, _right) = data.split_at_mut(u32_size);
        left.copy_from_slice(&fd.to_ne_bytes()[..]);

        // Safe as we are the owner of plat_irq_forward and irq_set which are valid value
        let ret = unsafe { ioctl_with_ref(self, PLAT_IRQ_FORWARD_SET(), &irq_set[0]) };
        if ret < 0 {
            Err(DirectIrqError::Enable)
        } else {
            Ok(())
        }
    }

    /// Enable hardware triggered GPE handling via SCI interrupt forwarding.
    /// Note: requires sci_irq_prepare() to be called beforehand.
    ///
    /// # Arguments
    ///
    /// * `gpe_num` - host GPE number.
    ///
    pub fn gpe_enable_forwarding(&mut self, gpe_num: u32) -> Result<(), DirectIrqError> {
        if self.resample.is_none() || !self.sci_irq_prepared {
            return Err(DirectIrqError::EnableGpe);
        }

        self.gpe_forward_ioctl(gpe_num)?;

        Ok(())
    }

    fn gpe_forward_ioctl(&self, gpe_num: u32) -> Result<(), DirectIrqError> {
        let mut evt_set = vec_with_array_field::<acpi_evt_forward_set, u32>(0);
        evt_set[0].argsz = (size_of::<acpi_evt_forward_set>()) as u32;
        evt_set[0].action_flags = ACPI_EVT_FORWARD_SET_GPE_TRIGGER;
        evt_set[0].__bindgen_anon_1.gpe_host_nr = gpe_num;

        // Safe as we are the owner of self and evt_set which are valid value
        let ret = unsafe { ioctl_with_ref(self, ACPI_EVT_FORWARD_SET(), &evt_set[0]) };
        if ret < 0 {
            Err(DirectIrqError::EnableGpe)
        } else {
            Ok(())
        }
    }

    /// Enable hardware triggered ACPI fixed event handling via SCI interrupt forwarding.
    /// Note: requires sci_irq_prepare() to be called beforehand.
    ///
    /// # Arguments
    ///
    /// * `event` - ACPI fixed event.
    ///
    pub fn fixed_event_enable_forwarding(
        &mut self,
        event: ACPIPMFixedEvent,
    ) -> Result<(), DirectIrqError> {
        if self.resample.is_none() || !self.sci_irq_prepared {
            return Err(DirectIrqError::EnableFixedEvent);
        }

        self.fixed_event_forward_ioctl(
            // Numeric values from ACPI_EVENT_xxx in include/acpi/actypes.h in kernel.
            match event {
                ACPIPMFixedEvent::GlobalLock => 1,
                ACPIPMFixedEvent::PowerButton => 2,
                ACPIPMFixedEvent::SleepButton => 3,
                ACPIPMFixedEvent::RTC => 4,
            },
        )?;

        Ok(())
    }

    fn fixed_event_forward_ioctl(&self, event_num: u32) -> Result<(), DirectIrqError> {
        let mut evt_set = vec_with_array_field::<acpi_evt_forward_set, u32>(0);
        evt_set[0].argsz = (size_of::<acpi_evt_forward_set>()) as u32;
        evt_set[0].action_flags = ACPI_EVT_FORWARD_SET_FIXED_EVENT_TRIGGER;
        evt_set[0].__bindgen_anon_1.fixed_evt_nr = event_num;

        // Safe as we are the owner of self and evt_set which are valid value
        let ret = unsafe { ioctl_with_ref(self, ACPI_EVT_FORWARD_SET(), &evt_set[0]) };
        if ret < 0 {
            Err(DirectIrqError::EnableFixedEvent)
        } else {
            Ok(())
        }
    }
}

impl AsRawDescriptor for DirectIrq {
    fn as_raw_descriptor(&self) -> i32 {
        self.dev.as_raw_descriptor()
    }
}

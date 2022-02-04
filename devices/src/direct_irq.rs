// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::{ioctl_with_ref, AsRawDescriptor, Event, RawDescriptor};
use data_model::vec_with_array_field;
use std::fs::{File, OpenOptions};
use std::io;
use std::mem::size_of;

use remain::sorted;
use thiserror::Error;
use vfio_sys::*;

#[sorted]
#[derive(Error, Debug)]
pub enum DirectIrqError {
    #[error("failed to enable direct irq")]
    Enable,
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
    /// Create DirectIrq object to access hardware triggered interrupts.
    pub fn new(trigger: Event, resample: Option<Event>) -> Result<Self, DirectIrqError> {
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

    /// Enable hardware triggered SCI interrupt handling for GPE.
    ///
    /// Note: sci_irq_prepare() itself does not enable SCI forwarding yet
    /// but configures it so it can be enabled for selected GPEs using gpe_enable_forwarding().
    pub fn sci_irq_prepare(&mut self) -> Result<(), DirectIrqError> {
        if let Some(resample) = &self.resample {
            self.plat_irq_ioctl(
                0,
                PLAT_IRQ_FORWARD_SET_LEVEL_SCI_FOR_GPE_TRIGGER_EVENTFD,
                self.trigger.as_raw_descriptor(),
            )?;
            self.plat_irq_ioctl(
                0,
                PLAT_IRQ_FORWARD_SET_LEVEL_SCI_FOR_GPE_UNMASK_EVENTFD,
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

        self.gpe_forward_ioctl(gpe_num, ACPI_GPE_FORWARD_SET_TRIGGER)?;

        Ok(())
    }

    fn gpe_forward_ioctl(&self, gpe_num: u32, action: u32) -> Result<(), DirectIrqError> {
        let mut gpe_set = vec_with_array_field::<gpe_forward_set, u32>(0);
        gpe_set[0].argsz = (size_of::<gpe_forward_set>()) as u32;
        gpe_set[0].action_flags = action;
        gpe_set[0].gpe_host_nr = gpe_num;

        // Safe as we are the owner of plat_irq_forward and gpe_set which are valid value
        let ret = unsafe { ioctl_with_ref(self, ACPI_GPE_FORWARD_SET(), &gpe_set[0]) };
        if ret < 0 {
            Err(DirectIrqError::EnableGpe)
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

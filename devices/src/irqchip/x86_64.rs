// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::Bus;
use hypervisor::{IoapicState, LapicState, PicSelect, PicState, PitState, VcpuX86_64};
use sys_util::Result;

use crate::IrqChip;

pub trait IrqChipX86_64<V: VcpuX86_64>: IrqChip<V> {
    /// Get the current state of the PIC
    fn get_pic_state(&self, select: PicSelect) -> Result<PicState>;

    /// Set the current state of the PIC
    fn set_pic_state(&mut self, select: PicSelect, state: &PicState) -> Result<()>;

    /// Get the current state of the IOAPIC
    fn get_ioapic_state(&self) -> Result<IoapicState>;

    /// Set the current state of the IOAPIC
    fn set_ioapic_state(&mut self, state: &IoapicState) -> Result<()>;

    /// Get the current state of the specified VCPU's local APIC
    fn get_lapic_state(&self, vcpu_id: usize) -> Result<LapicState>;

    /// Set the current state of the specified VCPU's local APIC
    fn set_lapic_state(&mut self, vcpu_id: usize, state: &LapicState) -> Result<()>;

    /// Create a PIT (Programmable Interval Timer) for this VM.
    fn create_pit(&mut self, io_bus: &mut Bus) -> Result<()>;

    /// Retrieves the state of the PIT.
    fn get_pit(&self) -> Result<PitState>;

    /// Sets the state of the PIT.
    fn set_pit(&mut self, state: &PitState) -> Result<()>;
}

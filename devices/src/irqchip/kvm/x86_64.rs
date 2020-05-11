// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use hypervisor::kvm::KvmVcpu;
use hypervisor::{IoapicState, LapicState, PicSelect, PicState, PitState};

use sys_util::Result;

use crate::{Bus, IrqChipX86_64, KvmKernelIrqChip};

impl IrqChipX86_64<KvmVcpu> for KvmKernelIrqChip {
    /// Get the current state of the PIC
    fn get_pic_state(&self, _select: PicSelect) -> Result<PicState> {
        unimplemented!("get_pic_state for KvmKernelIrqChip is not yet implemented");
    }

    /// Set the current state of the PIC
    fn set_pic_state(&mut self, _select: PicSelect, _state: &PicState) -> Result<()> {
        unimplemented!("set_pic_state for KvmKernelIrqChip is not yet implemented");
    }

    /// Get the current state of the IOAPIC
    fn get_ioapic_state(&self) -> Result<IoapicState> {
        unimplemented!("get_ioapic_state for KvmKernelIrqChip is not yet implemented");
    }

    /// Set the current state of the IOAPIC
    fn set_ioapic_state(&mut self, _state: &IoapicState) -> Result<()> {
        unimplemented!("set_ioapic_state for KvmKernelIrqChip is not yet implemented");
    }

    /// Get the current state of the specified VCPU's local APIC
    fn get_lapic_state(&self, _vcpu_id: usize) -> Result<LapicState> {
        unimplemented!("get_lapic_state for KvmKernelIrqChip is not yet implemented");
    }

    /// Set the current state of the specified VCPU's local APIC
    fn set_lapic_state(&mut self, _vcpu_id: usize, _state: &LapicState) -> Result<()> {
        unimplemented!("set_lapic_state for KvmKernelIrqChip is not yet implemented");
    }

    /// Create a PIT (Programmable Interval Timer) for this VM.
    fn create_pit(&mut self, _io_bus: &mut Bus) -> Result<()> {
        unimplemented!("create_pit for KvmKernelIrqChip is not yet implemented");
    }

    /// Retrieves the state of the PIT.
    fn get_pit(&self) -> Result<PitState> {
        unimplemented!("get_pit for KvmKernelIrqChip is not yet implemented");
    }

    /// Sets the state of the PIT.
    fn set_pit(&mut self, _state: &PitState) -> Result<()> {
        unimplemented!("set_pit for KvmKernelIrqChip is not yet implemented");
    }
}

// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::result;

use devices::IrqChipX86_64;
use remain::sorted;
use thiserror::Error;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("GetLapic ioctl failed: {0}")]
    GetLapic(base::Error),
    #[error("SetLapic ioctl failed: {0}")]
    SetLapic(base::Error),
}

pub type Result<T> = result::Result<T, Error>;

// Defines poached from apicdef.h kernel header.

// Offset, in bytes, of LAPIC local vector table LINT0/LINT1 registers.
const APIC_LVT0_OFFSET: usize = 0x350;
const APIC_LVT1_OFFSET: usize = 0x360;

// Register num of LINT0/LINT1 register.
const APIC_LVT0_REGISTER: usize = lapic_byte_offset_to_register(APIC_LVT0_OFFSET);
const APIC_LVT1_REGISTER: usize = lapic_byte_offset_to_register(APIC_LVT1_OFFSET);

const APIC_MODE_NMI: u32 = 0x4;
const APIC_MODE_EXTINT: u32 = 0x7;

// Converts a LAPIC register byte offset to a register number.
const fn lapic_byte_offset_to_register(offset_bytes: usize) -> usize {
    // Registers are 16 byte aligned
    offset_bytes / 16
}

fn set_apic_delivery_mode(reg: u32, mode: u32) -> u32 {
    ((reg) & !0x700) | ((mode) << 8)
}

/// Configures LAPICs.  LAPIC0 is set for external interrupts, LAPIC1 is set for NMI.
///
/// # Arguments
/// * `vcpu_id` - The number of the VCPU to configure.
/// * `irqchip` - The IrqChip for getting/setting LAPIC state.
pub fn set_lint(vcpu_id: usize, irqchip: &mut dyn IrqChipX86_64) -> Result<()> {
    let mut lapic = irqchip.get_lapic_state(vcpu_id).map_err(Error::GetLapic)?;

    for (reg, mode) in &[
        (APIC_LVT0_REGISTER, APIC_MODE_EXTINT),
        (APIC_LVT1_REGISTER, APIC_MODE_NMI),
    ] {
        lapic.regs[*reg] = set_apic_delivery_mode(lapic.regs[*reg], *mode);
    }

    irqchip
        .set_lapic_state(vcpu_id, &lapic)
        .map_err(Error::SetLapic)
}

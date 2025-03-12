// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use aarch64_sys_reg::AArch64SysRegId;
use aarch64_sys_reg::ICC_AP0R0_EL1;
use aarch64_sys_reg::ICC_AP0R1_EL1;
use aarch64_sys_reg::ICC_AP0R2_EL1;
use aarch64_sys_reg::ICC_AP0R3_EL1;
use aarch64_sys_reg::ICC_AP1R0_EL1;
use aarch64_sys_reg::ICC_AP1R1_EL1;
use aarch64_sys_reg::ICC_AP1R2_EL1;
use aarch64_sys_reg::ICC_AP1R3_EL1;
use aarch64_sys_reg::ICC_BPR0_EL1;
use aarch64_sys_reg::ICC_BPR1_EL1;
use aarch64_sys_reg::ICC_IGRPEN0_EL1;
use aarch64_sys_reg::ICC_IGRPEN1_EL1;
use aarch64_sys_reg::ICC_PMR_EL1;
use aarch64_sys_reg::ICC_SRE_EL1;
use anyhow::anyhow;
use base::Result;
use hypervisor::DeviceKind;
use snapshot::AnySnapshot;

use crate::IrqChip;

pub trait IrqChipAArch64: IrqChip {
    // Clones this trait as a `Box` version of itself.
    fn try_box_clone(&self) -> Result<Box<dyn IrqChipAArch64>>;

    // Get this as the super-trait IrqChip.
    fn as_irq_chip(&self) -> &dyn IrqChip;

    // Get this as the mutable super-trait IrqChip.
    fn as_irq_chip_mut(&mut self) -> &mut dyn IrqChip;

    /// Get the version of VGIC that this chip is emulating. Currently KVM may either implement
    /// VGIC version 2 or 3.
    fn get_vgic_version(&self) -> DeviceKind;

    /// Once all the VCPUs have been enabled, finalize the irq chip.
    fn finalize(&self) -> Result<()>;

    // Snapshot irqchip.
    fn snapshot(&self, _cpus_num: usize) -> anyhow::Result<AnySnapshot> {
        Err(anyhow!("Snapshot not yet implemented for AArch64"))
    }

    fn restore(&mut self, _data: AnySnapshot, _vcpus_num: usize) -> anyhow::Result<()> {
        Err(anyhow!("Restore not yet implemented for AArch64"))
    }
}

// List of registers taken from https://web.git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/arm64/kvm/vgic-sys-reg-v3.c?h=v6.13.5#n300
pub fn icc_regs(prio_bits: u8) -> anyhow::Result<Vec<AArch64SysRegId>> {
    let mut regs = vec![
        ICC_PMR_EL1,
        ICC_BPR0_EL1,
        ICC_BPR1_EL1,
        ICC_SRE_EL1,
        ICC_IGRPEN0_EL1,
        ICC_IGRPEN1_EL1,
    ];
    icc_ap0r_regs(&mut regs, prio_bits)?;
    icc_ap1r_regs(&mut regs, prio_bits)?;
    Ok(regs)
}

fn icc_ap0r_regs(regs: &mut Vec<AArch64SysRegId>, prio_bits: u8) -> anyhow::Result<()> {
    if prio_bits > 8 || prio_bits == 0 {
        return Err(anyhow!("Invalid number of priroity bits: {prio_bits}"));
    }
    regs.push(ICC_AP0R0_EL1);
    if prio_bits >= 6 {
        regs.push(ICC_AP0R1_EL1);
    }
    if prio_bits >= 7 {
        regs.push(ICC_AP0R2_EL1);
        regs.push(ICC_AP0R3_EL1);
    }
    Ok(())
}

fn icc_ap1r_regs(regs: &mut Vec<AArch64SysRegId>, prio_bits: u8) -> anyhow::Result<()> {
    if prio_bits > 8 || prio_bits == 0 {
        return Err(anyhow!("Invalid number of priroity bits: {prio_bits}"));
    }
    regs.push(ICC_AP1R0_EL1);
    if prio_bits >= 6 {
        regs.push(ICC_AP1R1_EL1);
    }
    if prio_bits >= 7 {
        regs.push(ICC_AP1R2_EL1);
        regs.push(ICC_AP1R3_EL1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icc_ap0r_1() {
        let mut regs = Vec::new();
        icc_ap0r_regs(&mut regs, 4).unwrap();
        assert_eq!(
            regs,
            vec![AArch64SysRegId::new_unchecked(
                0b11, 0b000, 0b1100, 0b1000, 0b100
            ),]
        );
    }

    #[test]
    fn icc_ap0r_2() {
        let mut regs = Vec::new();
        icc_ap0r_regs(&mut regs, 6).unwrap();
        assert_eq!(
            regs,
            vec![
                AArch64SysRegId::new_unchecked(0b11, 0b000, 0b1100, 0b1000, 0b100),
                AArch64SysRegId::new_unchecked(0b11, 0b000, 0b1100, 0b1000, 0b101),
            ]
        );
    }

    #[test]
    fn icc_ap0r_4() {
        let mut regs = Vec::new();
        icc_ap0r_regs(&mut regs, 7).unwrap();
        assert_eq!(
            regs,
            vec![
                AArch64SysRegId::new_unchecked(0b11, 0b000, 0b1100, 0b1000, 0b100),
                AArch64SysRegId::new_unchecked(0b11, 0b000, 0b1100, 0b1000, 0b101),
                AArch64SysRegId::new_unchecked(0b11, 0b000, 0b1100, 0b1000, 0b110),
                AArch64SysRegId::new_unchecked(0b11, 0b000, 0b1100, 0b1000, 0b111),
            ]
        );
    }

    #[test]
    #[should_panic]
    fn icc_ap0r_invalid_0() {
        let mut regs = Vec::new();
        icc_ap0r_regs(&mut regs, 0).unwrap();
    }

    #[test]
    #[should_panic]
    fn icc_ap0r_invalid_5() {
        let mut regs = Vec::new();
        icc_ap0r_regs(&mut regs, 9).unwrap();
    }

    #[test]
    fn icc_ap1r_1() {
        let mut regs = Vec::new();
        icc_ap1r_regs(&mut regs, 5).unwrap();
        assert_eq!(
            regs,
            vec![AArch64SysRegId::new_unchecked(
                0b11, 0b000, 0b1100, 0b1001, 0b000
            ),]
        );
    }

    #[test]
    fn icc_ap1r_2() {
        let mut regs = Vec::new();
        icc_ap1r_regs(&mut regs, 6).unwrap();
        assert_eq!(
            regs,
            vec![
                AArch64SysRegId::new_unchecked(0b11, 0b000, 0b1100, 0b1001, 0b000),
                AArch64SysRegId::new_unchecked(0b11, 0b000, 0b1100, 0b1001, 0b001),
            ]
        );
    }

    #[test]
    fn icc_ap1r_4() {
        let mut regs = Vec::new();
        icc_ap1r_regs(&mut regs, 8).unwrap();
        assert_eq!(
            regs,
            vec![
                AArch64SysRegId::new_unchecked(0b11, 0b000, 0b1100, 0b1001, 0b000),
                AArch64SysRegId::new_unchecked(0b11, 0b000, 0b1100, 0b1001, 0b001),
                AArch64SysRegId::new_unchecked(0b11, 0b000, 0b1100, 0b1001, 0b010),
                AArch64SysRegId::new_unchecked(0b11, 0b000, 0b1100, 0b1001, 0b011),
            ]
        );
    }

    #[test]
    #[should_panic]
    fn icc_ap1r_invalid_0() {
        let mut regs = Vec::new();
        icc_ap1r_regs(&mut regs, 0).unwrap();
    }

    #[test]
    #[should_panic]
    fn icc_ap1r_invalid_5() {
        let mut regs = Vec::new();
        icc_ap1r_regs(&mut regs, 9).unwrap();
    }

    #[test]
    fn icc_regs_pribits_8() {
        let regs = icc_regs(8).unwrap();
        assert_eq!(
            regs,
            [
                ICC_PMR_EL1,
                ICC_BPR0_EL1,
                ICC_BPR1_EL1,
                ICC_SRE_EL1,
                ICC_IGRPEN0_EL1,
                ICC_IGRPEN1_EL1,
                ICC_AP0R0_EL1,
                ICC_AP0R1_EL1,
                ICC_AP0R2_EL1,
                ICC_AP0R3_EL1,
                ICC_AP1R0_EL1,
                ICC_AP1R1_EL1,
                ICC_AP1R2_EL1,
                ICC_AP1R3_EL1,
            ]
        );
    }
}

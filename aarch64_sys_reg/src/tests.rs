// Copyright 2025 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(non_snake_case, non_upper_case_globals)]

use crate::*;

#[test]
fn sysreg_new() {
    let sysreg = AArch64SysRegId::new(1, 2, 3, 4, 5).unwrap();
    assert_eq!(sysreg.op0(), 1);
    assert_eq!(sysreg.op1(), 2);
    assert_eq!(sysreg.crn(), 3);
    assert_eq!(sysreg.crm(), 4);
    assert_eq!(sysreg.op2(), 5);
    assert_eq!(sysreg.encoded(), 0x51A5);
}

#[test]
fn sysreg_new_max() {
    let sysreg = AArch64SysRegId::new(0b11, 0b111, 0b1111, 0b1111, 0b111).unwrap();
    assert_eq!(sysreg.op0(), 3);
    assert_eq!(sysreg.op1(), 7);
    assert_eq!(sysreg.crn(), 15);
    assert_eq!(sysreg.crm(), 15);
    assert_eq!(sysreg.op2(), 7);
    assert_eq!(sysreg.encoded(), 0xFFFF);
}

#[test]
fn sysreg_new_out_of_range() {
    AArch64SysRegId::new(4, 0, 0, 0, 0).expect_err("invalid Op0");
    AArch64SysRegId::new(0, 8, 0, 0, 0).expect_err("invalid Op1");
    AArch64SysRegId::new(0, 0, 16, 0, 0).expect_err("invalid CRn");
    AArch64SysRegId::new(0, 0, 0, 16, 0).expect_err("invalid CRm");
    AArch64SysRegId::new(0, 0, 0, 0, 8).expect_err("invalid Op2");
}

#[test]
fn sysreg_encoding_mpidr_el1() {
    assert_eq!(MPIDR_EL1.op0(), 3);
    assert_eq!(MPIDR_EL1.op1(), 0);
    assert_eq!(MPIDR_EL1.crn(), 0);
    assert_eq!(MPIDR_EL1.crm(), 0);
    assert_eq!(MPIDR_EL1.op2(), 5);
    assert_eq!(MPIDR_EL1.encoded(), 0xC005);
    assert_eq!(MPIDR_EL1, AArch64SysRegId::new(3, 0, 0, 0, 5).unwrap());
}

#[test]
fn sysreg_encoding_cntvct_el0() {
    assert_eq!(CNTVCT_EL0.op0(), 3);
    assert_eq!(CNTVCT_EL0.op1(), 3);
    assert_eq!(CNTVCT_EL0.crn(), 14);
    assert_eq!(CNTVCT_EL0.crm(), 0);
    assert_eq!(CNTVCT_EL0.op2(), 2);
    assert_eq!(CNTVCT_EL0.encoded(), 0xDF02);
    assert_eq!(CNTVCT_EL0, AArch64SysRegId::new(3, 3, 14, 0, 2).unwrap());
}

#[test]
fn sysreg_encoding_cntv_cval_el0() {
    assert_eq!(CNTV_CVAL_EL0.op0(), 3);
    assert_eq!(CNTV_CVAL_EL0.op1(), 3);
    assert_eq!(CNTV_CVAL_EL0.crn(), 14);
    assert_eq!(CNTV_CVAL_EL0.crm(), 3);
    assert_eq!(CNTV_CVAL_EL0.op2(), 2);
    assert_eq!(CNTV_CVAL_EL0.encoded(), 0xDF1A);
    assert_eq!(CNTV_CVAL_EL0, AArch64SysRegId::new(3, 3, 14, 3, 2).unwrap()
    );
}

#[test]
fn sysreg_debug() {
    assert_eq!(
        format!("{:?}", MPIDR_EL1),
        "AArch64SysRegId { Op0: 3, Op1: 0, CRn: 0, CRm: 0, Op2: 5 }"
    );
}

fn sysreg(op0: u8, op1: u8, crn: u8, crm: u8, op2: u8) -> AArch64SysRegId {
    AArch64SysRegId::new(op0, op1, crn, crm, op2).expect("invalid encoding")
}

#[test]
fn test_AMEVCNTR0n_EL0() {
    assert_eq!(AMEVCNTR00_EL0, sysreg(0b11, 0b011, 0b1101, 0b0100, 0b000));
    assert_eq!(AMEVCNTR01_EL0, sysreg(0b11, 0b011, 0b1101, 0b0100, 0b001));
    assert_eq!(AMEVCNTR02_EL0, sysreg(0b11, 0b011, 0b1101, 0b0100, 0b010));
    assert_eq!(AMEVCNTR03_EL0, sysreg(0b11, 0b011, 0b1101, 0b0100, 0b011));
}

#[test]
fn test_AMEVCNTR1n_EL0() {
    assert_eq!(AMEVCNTR10_EL0, sysreg(0b11, 0b011, 0b1101, 0b1100, 0b000));
    assert_eq!(AMEVCNTR11_EL0, sysreg(0b11, 0b011, 0b1101, 0b1100, 0b001));
    assert_eq!(AMEVCNTR12_EL0, sysreg(0b11, 0b011, 0b1101, 0b1100, 0b010));
    assert_eq!(AMEVCNTR13_EL0, sysreg(0b11, 0b011, 0b1101, 0b1100, 0b011));
    assert_eq!(AMEVCNTR14_EL0, sysreg(0b11, 0b011, 0b1101, 0b1100, 0b100));
    assert_eq!(AMEVCNTR15_EL0, sysreg(0b11, 0b011, 0b1101, 0b1100, 0b101));
    assert_eq!(AMEVCNTR16_EL0, sysreg(0b11, 0b011, 0b1101, 0b1100, 0b110));
    assert_eq!(AMEVCNTR17_EL0, sysreg(0b11, 0b011, 0b1101, 0b1100, 0b111));
    assert_eq!(AMEVCNTR18_EL0, sysreg(0b11, 0b011, 0b1101, 0b1101, 0b000));
    assert_eq!(AMEVCNTR19_EL0, sysreg(0b11, 0b011, 0b1101, 0b1101, 0b001));
    assert_eq!(AMEVCNTR1A_EL0, sysreg(0b11, 0b011, 0b1101, 0b1101, 0b010));
    assert_eq!(AMEVCNTR1B_EL0, sysreg(0b11, 0b011, 0b1101, 0b1101, 0b011));
    assert_eq!(AMEVCNTR1C_EL0, sysreg(0b11, 0b011, 0b1101, 0b1101, 0b100));
    assert_eq!(AMEVCNTR1D_EL0, sysreg(0b11, 0b011, 0b1101, 0b1101, 0b101));
    assert_eq!(AMEVCNTR1E_EL0, sysreg(0b11, 0b011, 0b1101, 0b1101, 0b110));
    assert_eq!(AMEVCNTR1F_EL0, sysreg(0b11, 0b011, 0b1101, 0b1101, 0b111));
}

#[test]
fn test_AMEVCNTVOFF0n_EL2() {
    assert_eq!(AMEVCNTVOFF00_EL2, sysreg(0b11, 0b100, 0b1101, 0b1000, 0b000));
    assert_eq!(AMEVCNTVOFF02_EL2, sysreg(0b11, 0b100, 0b1101, 0b1000, 0b010));
    assert_eq!(AMEVCNTVOFF03_EL2, sysreg(0b11, 0b100, 0b1101, 0b1000, 0b011));
}

#[test]
fn test_AMEVCNTVOFF1n_EL2() {
    assert_eq!(AMEVCNTVOFF10_EL2, sysreg(0b11, 0b100, 0b1101, 0b1010, 0b000));
    assert_eq!(AMEVCNTVOFF11_EL2, sysreg(0b11, 0b100, 0b1101, 0b1010, 0b001));
    assert_eq!(AMEVCNTVOFF12_EL2, sysreg(0b11, 0b100, 0b1101, 0b1010, 0b010));
    assert_eq!(AMEVCNTVOFF13_EL2, sysreg(0b11, 0b100, 0b1101, 0b1010, 0b011));
    assert_eq!(AMEVCNTVOFF14_EL2, sysreg(0b11, 0b100, 0b1101, 0b1010, 0b100));
    assert_eq!(AMEVCNTVOFF15_EL2, sysreg(0b11, 0b100, 0b1101, 0b1010, 0b101));
    assert_eq!(AMEVCNTVOFF16_EL2, sysreg(0b11, 0b100, 0b1101, 0b1010, 0b110));
    assert_eq!(AMEVCNTVOFF17_EL2, sysreg(0b11, 0b100, 0b1101, 0b1010, 0b111));
    assert_eq!(AMEVCNTVOFF18_EL2, sysreg(0b11, 0b100, 0b1101, 0b1011, 0b000));
    assert_eq!(AMEVCNTVOFF19_EL2, sysreg(0b11, 0b100, 0b1101, 0b1011, 0b001));
    assert_eq!(AMEVCNTVOFF1A_EL2, sysreg(0b11, 0b100, 0b1101, 0b1011, 0b010));
    assert_eq!(AMEVCNTVOFF1B_EL2, sysreg(0b11, 0b100, 0b1101, 0b1011, 0b011));
    assert_eq!(AMEVCNTVOFF1C_EL2, sysreg(0b11, 0b100, 0b1101, 0b1011, 0b100));
    assert_eq!(AMEVCNTVOFF1D_EL2, sysreg(0b11, 0b100, 0b1101, 0b1011, 0b101));
    assert_eq!(AMEVCNTVOFF1E_EL2, sysreg(0b11, 0b100, 0b1101, 0b1011, 0b110));
    assert_eq!(AMEVCNTVOFF1F_EL2, sysreg(0b11, 0b100, 0b1101, 0b1011, 0b111));
}

#[test]
fn test_AMEVTYPER0n_EL0() {
    assert_eq!(AMEVTYPER00_EL0, sysreg(0b11, 0b011, 0b1101, 0b0110, 0b000));
    assert_eq!(AMEVTYPER01_EL0, sysreg(0b11, 0b011, 0b1101, 0b0110, 0b001));
    assert_eq!(AMEVTYPER02_EL0, sysreg(0b11, 0b011, 0b1101, 0b0110, 0b010));
    assert_eq!(AMEVTYPER03_EL0, sysreg(0b11, 0b011, 0b1101, 0b0110, 0b011));
}

#[test]
fn test_AMEVTYPER1n_EL0() {
    assert_eq!(AMEVTYPER10_EL0, sysreg(0b11, 0b011, 0b1101, 0b1110, 0b000));
    assert_eq!(AMEVTYPER11_EL0, sysreg(0b11, 0b011, 0b1101, 0b1110, 0b001));
    assert_eq!(AMEVTYPER12_EL0, sysreg(0b11, 0b011, 0b1101, 0b1110, 0b010));
    assert_eq!(AMEVTYPER13_EL0, sysreg(0b11, 0b011, 0b1101, 0b1110, 0b011));
    assert_eq!(AMEVTYPER14_EL0, sysreg(0b11, 0b011, 0b1101, 0b1110, 0b100));
    assert_eq!(AMEVTYPER15_EL0, sysreg(0b11, 0b011, 0b1101, 0b1110, 0b101));
    assert_eq!(AMEVTYPER16_EL0, sysreg(0b11, 0b011, 0b1101, 0b1110, 0b110));
    assert_eq!(AMEVTYPER17_EL0, sysreg(0b11, 0b011, 0b1101, 0b1110, 0b111));
    assert_eq!(AMEVTYPER18_EL0, sysreg(0b11, 0b011, 0b1101, 0b1111, 0b000));
    assert_eq!(AMEVTYPER19_EL0, sysreg(0b11, 0b011, 0b1101, 0b1111, 0b001));
    assert_eq!(AMEVTYPER1A_EL0, sysreg(0b11, 0b011, 0b1101, 0b1111, 0b010));
    assert_eq!(AMEVTYPER1B_EL0, sysreg(0b11, 0b011, 0b1101, 0b1111, 0b011));
    assert_eq!(AMEVTYPER1C_EL0, sysreg(0b11, 0b011, 0b1101, 0b1111, 0b100));
    assert_eq!(AMEVTYPER1D_EL0, sysreg(0b11, 0b011, 0b1101, 0b1111, 0b101));
    assert_eq!(AMEVTYPER1E_EL0, sysreg(0b11, 0b011, 0b1101, 0b1111, 0b110));
    assert_eq!(AMEVTYPER1F_EL0, sysreg(0b11, 0b011, 0b1101, 0b1111, 0b111));
}

#[test]
fn test_BRBINFn_EL1() {
    assert_eq!(BRBINF0_EL1,  sysreg(0b10, 0b001, 0b1000, 0b0000, 0b000));
    assert_eq!(BRBINF1_EL1,  sysreg(0b10, 0b001, 0b1000, 0b0001, 0b000));
    assert_eq!(BRBINF15_EL1, sysreg(0b10, 0b001, 0b1000, 0b1111, 0b000));
    assert_eq!(BRBINF16_EL1, sysreg(0b10, 0b001, 0b1000, 0b0000, 0b100));
    assert_eq!(BRBINF31_EL1, sysreg(0b10, 0b001, 0b1000, 0b1111, 0b100));
}

#[test]
fn test_BRBSRCn_EL1() {
    assert_eq!(BRBSRC0_EL1,  sysreg(0b10, 0b001, 0b1000, 0b0000, 0b001));
    assert_eq!(BRBSRC1_EL1,  sysreg(0b10, 0b001, 0b1000, 0b0001, 0b001));
    assert_eq!(BRBSRC15_EL1, sysreg(0b10, 0b001, 0b1000, 0b1111, 0b001));
    assert_eq!(BRBSRC16_EL1, sysreg(0b10, 0b001, 0b1000, 0b0000, 0b101));
    assert_eq!(BRBSRC31_EL1, sysreg(0b10, 0b001, 0b1000, 0b1111, 0b101));
}

#[test]
fn test_BRBTGTn_EL1() {
    assert_eq!(BRBTGT0_EL1,  sysreg(0b10, 0b001, 0b1000, 0b0000, 0b010));
    assert_eq!(BRBTGT1_EL1,  sysreg(0b10, 0b001, 0b1000, 0b0001, 0b010));
    assert_eq!(BRBTGT15_EL1, sysreg(0b10, 0b001, 0b1000, 0b1111, 0b010));
    assert_eq!(BRBTGT16_EL1, sysreg(0b10, 0b001, 0b1000, 0b0000, 0b110));
    assert_eq!(BRBTGT31_EL1, sysreg(0b10, 0b001, 0b1000, 0b1111, 0b110));
}

#[test]
fn test_DBGBCRn_EL1() {
    assert_eq!(DBGBCR0_EL1, sysreg(0b10, 0b000, 0b0000, 0b0000, 0b101));
    assert_eq!(DBGBCR1_EL1, sysreg(0b10, 0b000, 0b0000, 0b0001, 0b101));
    assert_eq!(DBGBCR2_EL1, sysreg(0b10, 0b000, 0b0000, 0b0010, 0b101));
    assert_eq!(DBGBCR3_EL1, sysreg(0b10, 0b000, 0b0000, 0b0011, 0b101));
    assert_eq!(DBGBCR4_EL1, sysreg(0b10, 0b000, 0b0000, 0b0100, 0b101));
    assert_eq!(DBGBCR5_EL1, sysreg(0b10, 0b000, 0b0000, 0b0101, 0b101));
    assert_eq!(DBGBCR6_EL1, sysreg(0b10, 0b000, 0b0000, 0b0110, 0b101));
    assert_eq!(DBGBCR7_EL1, sysreg(0b10, 0b000, 0b0000, 0b0111, 0b101));
    assert_eq!(DBGBCR8_EL1, sysreg(0b10, 0b000, 0b0000, 0b1000, 0b101));
    assert_eq!(DBGBCR9_EL1, sysreg(0b10, 0b000, 0b0000, 0b1001, 0b101));
    assert_eq!(DBGBCRA_EL1, sysreg(0b10, 0b000, 0b0000, 0b1010, 0b101));
    assert_eq!(DBGBCRB_EL1, sysreg(0b10, 0b000, 0b0000, 0b1011, 0b101));
    assert_eq!(DBGBCRC_EL1, sysreg(0b10, 0b000, 0b0000, 0b1100, 0b101));
    assert_eq!(DBGBCRD_EL1, sysreg(0b10, 0b000, 0b0000, 0b1101, 0b101));
    assert_eq!(DBGBCRE_EL1, sysreg(0b10, 0b000, 0b0000, 0b1110, 0b101));
    assert_eq!(DBGBCRF_EL1, sysreg(0b10, 0b000, 0b0000, 0b1111, 0b101));
}

#[test]
fn test_DBGBVRn_EL1() {
    assert_eq!(DBGBVR0_EL1, sysreg(0b10, 0b000, 0b0000, 0b0000, 0b100));
    assert_eq!(DBGBVR1_EL1, sysreg(0b10, 0b000, 0b0000, 0b0001, 0b100));
    assert_eq!(DBGBVR2_EL1, sysreg(0b10, 0b000, 0b0000, 0b0010, 0b100));
    assert_eq!(DBGBVR3_EL1, sysreg(0b10, 0b000, 0b0000, 0b0011, 0b100));
    assert_eq!(DBGBVR4_EL1, sysreg(0b10, 0b000, 0b0000, 0b0100, 0b100));
    assert_eq!(DBGBVR5_EL1, sysreg(0b10, 0b000, 0b0000, 0b0101, 0b100));
    assert_eq!(DBGBVR6_EL1, sysreg(0b10, 0b000, 0b0000, 0b0110, 0b100));
    assert_eq!(DBGBVR7_EL1, sysreg(0b10, 0b000, 0b0000, 0b0111, 0b100));
    assert_eq!(DBGBVR8_EL1, sysreg(0b10, 0b000, 0b0000, 0b1000, 0b100));
    assert_eq!(DBGBVR9_EL1, sysreg(0b10, 0b000, 0b0000, 0b1001, 0b100));
    assert_eq!(DBGBVRA_EL1, sysreg(0b10, 0b000, 0b0000, 0b1010, 0b100));
    assert_eq!(DBGBVRB_EL1, sysreg(0b10, 0b000, 0b0000, 0b1011, 0b100));
    assert_eq!(DBGBVRC_EL1, sysreg(0b10, 0b000, 0b0000, 0b1100, 0b100));
    assert_eq!(DBGBVRD_EL1, sysreg(0b10, 0b000, 0b0000, 0b1101, 0b100));
    assert_eq!(DBGBVRE_EL1, sysreg(0b10, 0b000, 0b0000, 0b1110, 0b100));
    assert_eq!(DBGBVRF_EL1, sysreg(0b10, 0b000, 0b0000, 0b1111, 0b100));
}

#[test]
fn test_DBGWCRn_EL1() {
    assert_eq!(DBGWCR0_EL1, sysreg(0b10, 0b000, 0b0000, 0b0000, 0b111));
    assert_eq!(DBGWCR1_EL1, sysreg(0b10, 0b000, 0b0000, 0b0001, 0b111));
    assert_eq!(DBGWCR2_EL1, sysreg(0b10, 0b000, 0b0000, 0b0010, 0b111));
    assert_eq!(DBGWCR3_EL1, sysreg(0b10, 0b000, 0b0000, 0b0011, 0b111));
    assert_eq!(DBGWCR4_EL1, sysreg(0b10, 0b000, 0b0000, 0b0100, 0b111));
    assert_eq!(DBGWCR5_EL1, sysreg(0b10, 0b000, 0b0000, 0b0101, 0b111));
    assert_eq!(DBGWCR6_EL1, sysreg(0b10, 0b000, 0b0000, 0b0110, 0b111));
    assert_eq!(DBGWCR7_EL1, sysreg(0b10, 0b000, 0b0000, 0b0111, 0b111));
    assert_eq!(DBGWCR8_EL1, sysreg(0b10, 0b000, 0b0000, 0b1000, 0b111));
    assert_eq!(DBGWCR9_EL1, sysreg(0b10, 0b000, 0b0000, 0b1001, 0b111));
    assert_eq!(DBGWCRA_EL1, sysreg(0b10, 0b000, 0b0000, 0b1010, 0b111));
    assert_eq!(DBGWCRB_EL1, sysreg(0b10, 0b000, 0b0000, 0b1011, 0b111));
    assert_eq!(DBGWCRC_EL1, sysreg(0b10, 0b000, 0b0000, 0b1100, 0b111));
    assert_eq!(DBGWCRD_EL1, sysreg(0b10, 0b000, 0b0000, 0b1101, 0b111));
    assert_eq!(DBGWCRE_EL1, sysreg(0b10, 0b000, 0b0000, 0b1110, 0b111));
    assert_eq!(DBGWCRF_EL1, sysreg(0b10, 0b000, 0b0000, 0b1111, 0b111));
}

#[test]
fn test_DBGWVRn_EL1() {
    assert_eq!(DBGWVR0_EL1, sysreg(0b10, 0b000, 0b0000, 0b0000, 0b110));
    assert_eq!(DBGWVR1_EL1, sysreg(0b10, 0b000, 0b0000, 0b0001, 0b110));
    assert_eq!(DBGWVR2_EL1, sysreg(0b10, 0b000, 0b0000, 0b0010, 0b110));
    assert_eq!(DBGWVR3_EL1, sysreg(0b10, 0b000, 0b0000, 0b0011, 0b110));
    assert_eq!(DBGWVR4_EL1, sysreg(0b10, 0b000, 0b0000, 0b0100, 0b110));
    assert_eq!(DBGWVR5_EL1, sysreg(0b10, 0b000, 0b0000, 0b0101, 0b110));
    assert_eq!(DBGWVR6_EL1, sysreg(0b10, 0b000, 0b0000, 0b0110, 0b110));
    assert_eq!(DBGWVR7_EL1, sysreg(0b10, 0b000, 0b0000, 0b0111, 0b110));
    assert_eq!(DBGWVR8_EL1, sysreg(0b10, 0b000, 0b0000, 0b1000, 0b110));
    assert_eq!(DBGWVR9_EL1, sysreg(0b10, 0b000, 0b0000, 0b1001, 0b110));
    assert_eq!(DBGWVRA_EL1, sysreg(0b10, 0b000, 0b0000, 0b1010, 0b110));
    assert_eq!(DBGWVRB_EL1, sysreg(0b10, 0b000, 0b0000, 0b1011, 0b110));
    assert_eq!(DBGWVRC_EL1, sysreg(0b10, 0b000, 0b0000, 0b1100, 0b110));
    assert_eq!(DBGWVRD_EL1, sysreg(0b10, 0b000, 0b0000, 0b1101, 0b110));
    assert_eq!(DBGWVRE_EL1, sysreg(0b10, 0b000, 0b0000, 0b1110, 0b110));
    assert_eq!(DBGWVRF_EL1, sysreg(0b10, 0b000, 0b0000, 0b1111, 0b110));
}

#[test]
fn test_ICC_AP0Rn_EL1() {
    assert_eq!(ICC_AP0R0_EL1, sysreg(0b11, 0b000, 0b1100, 0b1000, 0b100));
    assert_eq!(ICC_AP0R1_EL1, sysreg(0b11, 0b000, 0b1100, 0b1000, 0b101));
    assert_eq!(ICC_AP0R2_EL1, sysreg(0b11, 0b000, 0b1100, 0b1000, 0b110));
    assert_eq!(ICC_AP0R3_EL1, sysreg(0b11, 0b000, 0b1100, 0b1000, 0b111));
}

#[test]
fn test_ICC_AP1Rn_EL1() {
    assert_eq!(ICC_AP1R0_EL1, sysreg(0b11, 0b000, 0b1100, 0b1001, 0b000));
    assert_eq!(ICC_AP1R1_EL1, sysreg(0b11, 0b000, 0b1100, 0b1001, 0b001));
    assert_eq!(ICC_AP1R2_EL1, sysreg(0b11, 0b000, 0b1100, 0b1001, 0b010));
    assert_eq!(ICC_AP1R3_EL1, sysreg(0b11, 0b000, 0b1100, 0b1001, 0b011));
}

#[test]
fn test_ICH_AP0Rn_EL2() {
    assert_eq!(ICH_AP0R0_EL2, sysreg(0b11, 0b100, 0b1100, 0b1000, 0b000));
    assert_eq!(ICH_AP0R1_EL2, sysreg(0b11, 0b100, 0b1100, 0b1000, 0b001));
    assert_eq!(ICH_AP0R2_EL2, sysreg(0b11, 0b100, 0b1100, 0b1000, 0b010));
    assert_eq!(ICH_AP0R3_EL2, sysreg(0b11, 0b100, 0b1100, 0b1000, 0b011));
}

#[test]
fn test_ICH_AP1Rn_EL2() {
    assert_eq!(ICH_AP1R0_EL2, sysreg(0b11, 0b100, 0b1100, 0b1001, 0b000));
    assert_eq!(ICH_AP1R1_EL2, sysreg(0b11, 0b100, 0b1100, 0b1001, 0b001));
    assert_eq!(ICH_AP1R2_EL2, sysreg(0b11, 0b100, 0b1100, 0b1001, 0b010));
    assert_eq!(ICH_AP1R3_EL2, sysreg(0b11, 0b100, 0b1100, 0b1001, 0b011));
}

#[test]
fn test_PMEVCNTRn_EL0() {
    assert_eq!(PMEVCNTR0_EL0, sysreg(0b11, 0b011, 0b1110, 0b1000, 0b000));
    assert_eq!(PMEVCNTR7_EL0, sysreg(0b11, 0b011, 0b1110, 0b1000, 0b111));
    assert_eq!(PMEVCNTR8_EL0, sysreg(0b11, 0b011, 0b1110, 0b1001, 0b000));
    assert_eq!(PMEVCNTR15_EL0, sysreg(0b11, 0b011, 0b1110, 0b1001, 0b111));
    assert_eq!(PMEVCNTR30_EL0, sysreg(0b11, 0b011, 0b1110, 0b1011, 0b110));
}

#[test]
fn test_PMEVCNTSVRn_EL1() {
    assert_eq!(PMEVCNTSVR0_EL1,  sysreg(0b10, 0b000, 0b1110, 0b1000, 0b000));
    assert_eq!(PMEVCNTSVR7_EL1,  sysreg(0b10, 0b000, 0b1110, 0b1000, 0b111));
    assert_eq!(PMEVCNTSVR8_EL1,  sysreg(0b10, 0b000, 0b1110, 0b1001, 0b000));
    assert_eq!(PMEVCNTSVR15_EL1, sysreg(0b10, 0b000, 0b1110, 0b1001, 0b111));
    assert_eq!(PMEVCNTSVR30_EL1, sysreg(0b10, 0b000, 0b1110, 0b1011, 0b110));
}

#[test]
fn test_PMEVTYPERn_EL0() {
    assert_eq!(PMEVTYPER0_EL0,  sysreg(0b11, 0b011, 0b1110, 0b1100, 0b000));
    assert_eq!(PMEVTYPER7_EL0,  sysreg(0b11, 0b011, 0b1110, 0b1100, 0b111));
    assert_eq!(PMEVTYPER8_EL0,  sysreg(0b11, 0b011, 0b1110, 0b1101, 0b000));
    assert_eq!(PMEVTYPER15_EL0, sysreg(0b11, 0b011, 0b1110, 0b1101, 0b111));
    assert_eq!(PMEVTYPER30_EL0, sysreg(0b11, 0b011, 0b1110, 0b1111, 0b110));
}

#[test]
fn test_SPMCGCRn_EL1() {
    assert_eq!(SPMCGCR0_EL1, sysreg(0b10, 0b000, 0b1001, 0b1101, 0b000));
    assert_eq!(SPMCGCR1_EL1, sysreg(0b10, 0b000, 0b1001, 0b1101, 0b001));
}

#[test]
fn test_SPMEVCNTRn_EL0() {
    assert_eq!(SPMEVCNTR0_EL0, sysreg(0b10, 0b011, 0b1110, 0b0000, 0b000));
    assert_eq!(SPMEVCNTR1_EL0, sysreg(0b10, 0b011, 0b1110, 0b0000, 0b001));
    assert_eq!(SPMEVCNTR2_EL0, sysreg(0b10, 0b011, 0b1110, 0b0000, 0b010));
    assert_eq!(SPMEVCNTR3_EL0, sysreg(0b10, 0b011, 0b1110, 0b0000, 0b011));
    assert_eq!(SPMEVCNTR4_EL0, sysreg(0b10, 0b011, 0b1110, 0b0000, 0b100));
    assert_eq!(SPMEVCNTR5_EL0, sysreg(0b10, 0b011, 0b1110, 0b0000, 0b101));
    assert_eq!(SPMEVCNTR6_EL0, sysreg(0b10, 0b011, 0b1110, 0b0000, 0b110));
    assert_eq!(SPMEVCNTR7_EL0, sysreg(0b10, 0b011, 0b1110, 0b0000, 0b111));
    assert_eq!(SPMEVCNTR8_EL0, sysreg(0b10, 0b011, 0b1110, 0b0001, 0b000));
    assert_eq!(SPMEVCNTR9_EL0, sysreg(0b10, 0b011, 0b1110, 0b0001, 0b001));
    assert_eq!(SPMEVCNTRA_EL0, sysreg(0b10, 0b011, 0b1110, 0b0001, 0b010));
    assert_eq!(SPMEVCNTRB_EL0, sysreg(0b10, 0b011, 0b1110, 0b0001, 0b011));
    assert_eq!(SPMEVCNTRC_EL0, sysreg(0b10, 0b011, 0b1110, 0b0001, 0b100));
    assert_eq!(SPMEVCNTRD_EL0, sysreg(0b10, 0b011, 0b1110, 0b0001, 0b101));
    assert_eq!(SPMEVCNTRE_EL0, sysreg(0b10, 0b011, 0b1110, 0b0001, 0b110));
    assert_eq!(SPMEVCNTRF_EL0, sysreg(0b10, 0b011, 0b1110, 0b0001, 0b111));
}

#[test]
fn test_SPMEVFILT2Rn_EL0() {
    assert_eq!(SPMEVFILT2R0_EL0, sysreg(0b10, 0b011, 0b1110, 0b0110, 0b000));
    assert_eq!(SPMEVFILT2R1_EL0, sysreg(0b10, 0b011, 0b1110, 0b0110, 0b001));
    assert_eq!(SPMEVFILT2R2_EL0, sysreg(0b10, 0b011, 0b1110, 0b0110, 0b010));
    assert_eq!(SPMEVFILT2R3_EL0, sysreg(0b10, 0b011, 0b1110, 0b0110, 0b011));
    assert_eq!(SPMEVFILT2R4_EL0, sysreg(0b10, 0b011, 0b1110, 0b0110, 0b100));
    assert_eq!(SPMEVFILT2R5_EL0, sysreg(0b10, 0b011, 0b1110, 0b0110, 0b101));
    assert_eq!(SPMEVFILT2R6_EL0, sysreg(0b10, 0b011, 0b1110, 0b0110, 0b110));
    assert_eq!(SPMEVFILT2R7_EL0, sysreg(0b10, 0b011, 0b1110, 0b0110, 0b111));
    assert_eq!(SPMEVFILT2R8_EL0, sysreg(0b10, 0b011, 0b1110, 0b0111, 0b000));
    assert_eq!(SPMEVFILT2R9_EL0, sysreg(0b10, 0b011, 0b1110, 0b0111, 0b001));
    assert_eq!(SPMEVFILT2RA_EL0, sysreg(0b10, 0b011, 0b1110, 0b0111, 0b010));
    assert_eq!(SPMEVFILT2RB_EL0, sysreg(0b10, 0b011, 0b1110, 0b0111, 0b011));
    assert_eq!(SPMEVFILT2RC_EL0, sysreg(0b10, 0b011, 0b1110, 0b0111, 0b100));
    assert_eq!(SPMEVFILT2RD_EL0, sysreg(0b10, 0b011, 0b1110, 0b0111, 0b101));
    assert_eq!(SPMEVFILT2RE_EL0, sysreg(0b10, 0b011, 0b1110, 0b0111, 0b110));
    assert_eq!(SPMEVFILT2RF_EL0, sysreg(0b10, 0b011, 0b1110, 0b0111, 0b111));
}

#[test]
fn test_SPMEVFILTRn_EL0() {
    assert_eq!(SPMEVFILTR0_EL0, sysreg(0b10, 0b011, 0b1110, 0b0100, 0b000));
    assert_eq!(SPMEVFILTR1_EL0, sysreg(0b10, 0b011, 0b1110, 0b0100, 0b001));
    assert_eq!(SPMEVFILTR2_EL0, sysreg(0b10, 0b011, 0b1110, 0b0100, 0b010));
    assert_eq!(SPMEVFILTR3_EL0, sysreg(0b10, 0b011, 0b1110, 0b0100, 0b011));
    assert_eq!(SPMEVFILTR4_EL0, sysreg(0b10, 0b011, 0b1110, 0b0100, 0b100));
    assert_eq!(SPMEVFILTR5_EL0, sysreg(0b10, 0b011, 0b1110, 0b0100, 0b101));
    assert_eq!(SPMEVFILTR6_EL0, sysreg(0b10, 0b011, 0b1110, 0b0100, 0b110));
    assert_eq!(SPMEVFILTR7_EL0, sysreg(0b10, 0b011, 0b1110, 0b0100, 0b111));
    assert_eq!(SPMEVFILTR8_EL0, sysreg(0b10, 0b011, 0b1110, 0b0101, 0b000));
    assert_eq!(SPMEVFILTR9_EL0, sysreg(0b10, 0b011, 0b1110, 0b0101, 0b001));
    assert_eq!(SPMEVFILTRA_EL0, sysreg(0b10, 0b011, 0b1110, 0b0101, 0b010));
    assert_eq!(SPMEVFILTRB_EL0, sysreg(0b10, 0b011, 0b1110, 0b0101, 0b011));
    assert_eq!(SPMEVFILTRC_EL0, sysreg(0b10, 0b011, 0b1110, 0b0101, 0b100));
    assert_eq!(SPMEVFILTRD_EL0, sysreg(0b10, 0b011, 0b1110, 0b0101, 0b101));
    assert_eq!(SPMEVFILTRE_EL0, sysreg(0b10, 0b011, 0b1110, 0b0101, 0b110));
    assert_eq!(SPMEVFILTRF_EL0, sysreg(0b10, 0b011, 0b1110, 0b0101, 0b111));
}

#[test]
fn test_SPMEVTYPERn_EL0() {
    assert_eq!(SPMEVTYPER0_EL0, sysreg(0b10, 0b011, 0b1110, 0b0010, 0b000));
    assert_eq!(SPMEVTYPER1_EL0, sysreg(0b10, 0b011, 0b1110, 0b0010, 0b001));
    assert_eq!(SPMEVTYPER2_EL0, sysreg(0b10, 0b011, 0b1110, 0b0010, 0b010));
    assert_eq!(SPMEVTYPER3_EL0, sysreg(0b10, 0b011, 0b1110, 0b0010, 0b011));
    assert_eq!(SPMEVTYPER4_EL0, sysreg(0b10, 0b011, 0b1110, 0b0010, 0b100));
    assert_eq!(SPMEVTYPER5_EL0, sysreg(0b10, 0b011, 0b1110, 0b0010, 0b101));
    assert_eq!(SPMEVTYPER6_EL0, sysreg(0b10, 0b011, 0b1110, 0b0010, 0b110));
    assert_eq!(SPMEVTYPER7_EL0, sysreg(0b10, 0b011, 0b1110, 0b0010, 0b111));
    assert_eq!(SPMEVTYPER8_EL0, sysreg(0b10, 0b011, 0b1110, 0b0011, 0b000));
    assert_eq!(SPMEVTYPER9_EL0, sysreg(0b10, 0b011, 0b1110, 0b0011, 0b001));
    assert_eq!(SPMEVTYPERA_EL0, sysreg(0b10, 0b011, 0b1110, 0b0011, 0b010));
    assert_eq!(SPMEVTYPERB_EL0, sysreg(0b10, 0b011, 0b1110, 0b0011, 0b011));
    assert_eq!(SPMEVTYPERC_EL0, sysreg(0b10, 0b011, 0b1110, 0b0011, 0b100));
    assert_eq!(SPMEVTYPERD_EL0, sysreg(0b10, 0b011, 0b1110, 0b0011, 0b101));
    assert_eq!(SPMEVTYPERE_EL0, sysreg(0b10, 0b011, 0b1110, 0b0011, 0b110));
    assert_eq!(SPMEVTYPERF_EL0, sysreg(0b10, 0b011, 0b1110, 0b0011, 0b111));
}

#[test]
fn test_TRCACATRn() {
    assert_eq!(TRCACATR0, sysreg(0b10, 0b001, 0b0010, 0b0000, 0b010));
    assert_eq!(TRCACATR1, sysreg(0b10, 0b001, 0b0010, 0b0010, 0b010));
    assert_eq!(TRCACATR2, sysreg(0b10, 0b001, 0b0010, 0b0100, 0b010));
    assert_eq!(TRCACATR3, sysreg(0b10, 0b001, 0b0010, 0b0110, 0b010));
    assert_eq!(TRCACATR4, sysreg(0b10, 0b001, 0b0010, 0b1000, 0b010));
    assert_eq!(TRCACATR5, sysreg(0b10, 0b001, 0b0010, 0b1010, 0b010));
    assert_eq!(TRCACATR6, sysreg(0b10, 0b001, 0b0010, 0b1100, 0b010));
    assert_eq!(TRCACATR7, sysreg(0b10, 0b001, 0b0010, 0b1110, 0b010));
    assert_eq!(TRCACATR8, sysreg(0b10, 0b001, 0b0010, 0b0000, 0b011));
    assert_eq!(TRCACATR9, sysreg(0b10, 0b001, 0b0010, 0b0010, 0b011));
    assert_eq!(TRCACATRA, sysreg(0b10, 0b001, 0b0010, 0b0100, 0b011));
    assert_eq!(TRCACATRB, sysreg(0b10, 0b001, 0b0010, 0b0110, 0b011));
    assert_eq!(TRCACATRC, sysreg(0b10, 0b001, 0b0010, 0b1000, 0b011));
    assert_eq!(TRCACATRD, sysreg(0b10, 0b001, 0b0010, 0b1010, 0b011));
    assert_eq!(TRCACATRE, sysreg(0b10, 0b001, 0b0010, 0b1100, 0b011));
    assert_eq!(TRCACATRF, sysreg(0b10, 0b001, 0b0010, 0b1110, 0b011));
}

#[test]
fn test_TRCACVRn() {
    assert_eq!(TRCACVR0, sysreg(0b10, 0b001, 0b0010, 0b0000, 0b000));
    assert_eq!(TRCACVR1, sysreg(0b10, 0b001, 0b0010, 0b0010, 0b000));
    assert_eq!(TRCACVR2, sysreg(0b10, 0b001, 0b0010, 0b0100, 0b000));
    assert_eq!(TRCACVR3, sysreg(0b10, 0b001, 0b0010, 0b0110, 0b000));
    assert_eq!(TRCACVR4, sysreg(0b10, 0b001, 0b0010, 0b1000, 0b000));
    assert_eq!(TRCACVR5, sysreg(0b10, 0b001, 0b0010, 0b1010, 0b000));
    assert_eq!(TRCACVR6, sysreg(0b10, 0b001, 0b0010, 0b1100, 0b000));
    assert_eq!(TRCACVR7, sysreg(0b10, 0b001, 0b0010, 0b1110, 0b000));
    assert_eq!(TRCACVR8, sysreg(0b10, 0b001, 0b0010, 0b0000, 0b001));
    assert_eq!(TRCACVR9, sysreg(0b10, 0b001, 0b0010, 0b0010, 0b001));
    assert_eq!(TRCACVRA, sysreg(0b10, 0b001, 0b0010, 0b0100, 0b001));
    assert_eq!(TRCACVRB, sysreg(0b10, 0b001, 0b0010, 0b0110, 0b001));
    assert_eq!(TRCACVRC, sysreg(0b10, 0b001, 0b0010, 0b1000, 0b001));
    assert_eq!(TRCACVRD, sysreg(0b10, 0b001, 0b0010, 0b1010, 0b001));
    assert_eq!(TRCACVRE, sysreg(0b10, 0b001, 0b0010, 0b1100, 0b001));
    assert_eq!(TRCACVRF, sysreg(0b10, 0b001, 0b0010, 0b1110, 0b001));
}

#[test]
fn test_TRCCIDCVRn() {
    assert_eq!(TRCCIDCVR0, sysreg(0b10, 0b001, 0b0011, 0b0000, 0b000));
    assert_eq!(TRCCIDCVR1, sysreg(0b10, 0b001, 0b0011, 0b0010, 0b000));
    assert_eq!(TRCCIDCVR2, sysreg(0b10, 0b001, 0b0011, 0b0100, 0b000));
    assert_eq!(TRCCIDCVR3, sysreg(0b10, 0b001, 0b0011, 0b0110, 0b000));
    assert_eq!(TRCCIDCVR4, sysreg(0b10, 0b001, 0b0011, 0b1000, 0b000));
    assert_eq!(TRCCIDCVR5, sysreg(0b10, 0b001, 0b0011, 0b1010, 0b000));
    assert_eq!(TRCCIDCVR6, sysreg(0b10, 0b001, 0b0011, 0b1100, 0b000));
    assert_eq!(TRCCIDCVR7, sysreg(0b10, 0b001, 0b0011, 0b1110, 0b000));
}

#[test]
fn test_TRCCNTCTLRn() {
    assert_eq!(TRCCNTCTLR0, sysreg(0b10, 0b001, 0b0000, 0b0100, 0b101));
    assert_eq!(TRCCNTCTLR1, sysreg(0b10, 0b001, 0b0000, 0b0101, 0b101));
    assert_eq!(TRCCNTCTLR2, sysreg(0b10, 0b001, 0b0000, 0b0110, 0b101));
    assert_eq!(TRCCNTCTLR3, sysreg(0b10, 0b001, 0b0000, 0b0111, 0b101));
}

#[test]
fn test_TRCCNTRLDVRn() {
    assert_eq!(TRCCNTRLDVR0, sysreg(0b10, 0b001, 0b0000, 0b0000, 0b101));
    assert_eq!(TRCCNTRLDVR1, sysreg(0b10, 0b001, 0b0000, 0b0001, 0b101));
    assert_eq!(TRCCNTRLDVR2, sysreg(0b10, 0b001, 0b0000, 0b0010, 0b101));
    assert_eq!(TRCCNTRLDVR3, sysreg(0b10, 0b001, 0b0000, 0b0011, 0b101));
}

#[test]
fn test_TRCCNTVRn() {
    assert_eq!(TRCCNTVR0, sysreg(0b10, 0b001, 0b0000, 0b1000, 0b101));
    assert_eq!(TRCCNTVR1, sysreg(0b10, 0b001, 0b0000, 0b1001, 0b101));
    assert_eq!(TRCCNTVR2, sysreg(0b10, 0b001, 0b0000, 0b1010, 0b101));
    assert_eq!(TRCCNTVR3, sysreg(0b10, 0b001, 0b0000, 0b1011, 0b101));
}

#[test]
fn test_TRCEXTINSELRn() {
    assert_eq!(TRCEXTINSELR0, sysreg(0b10, 0b001, 0b0000, 0b1000, 0b100));
    assert_eq!(TRCEXTINSELR1, sysreg(0b10, 0b001, 0b0000, 0b1001, 0b100));
    assert_eq!(TRCEXTINSELR2, sysreg(0b10, 0b001, 0b0000, 0b1010, 0b100));
    assert_eq!(TRCEXTINSELR3, sysreg(0b10, 0b001, 0b0000, 0b1011, 0b100));
}

#[test]
fn test_TRCIMSPECn() {
    assert_eq!(TRCIMSPEC1, sysreg(0b10, 0b001, 0b0000, 0b0001, 0b111));
    assert_eq!(TRCIMSPEC2, sysreg(0b10, 0b001, 0b0000, 0b0010, 0b111));
    assert_eq!(TRCIMSPEC3, sysreg(0b10, 0b001, 0b0000, 0b0011, 0b111));
    assert_eq!(TRCIMSPEC4, sysreg(0b10, 0b001, 0b0000, 0b0100, 0b111));
    assert_eq!(TRCIMSPEC5, sysreg(0b10, 0b001, 0b0000, 0b0101, 0b111));
    assert_eq!(TRCIMSPEC6, sysreg(0b10, 0b001, 0b0000, 0b0110, 0b111));
    assert_eq!(TRCIMSPEC7, sysreg(0b10, 0b001, 0b0000, 0b0111, 0b111));
}

#[test]
fn test_TRCRSCTLRn() {
    assert_eq!(TRCRSCTLR2,  sysreg(0b10, 0b001, 0b0001, 0b0010, 0b000));
    assert_eq!(TRCRSCTLR3,  sysreg(0b10, 0b001, 0b0001, 0b0011, 0b000));
    assert_eq!(TRCRSCTLR4,  sysreg(0b10, 0b001, 0b0001, 0b0100, 0b000));
    assert_eq!(TRCRSCTLR5,  sysreg(0b10, 0b001, 0b0001, 0b0101, 0b000));
    assert_eq!(TRCRSCTLR6,  sysreg(0b10, 0b001, 0b0001, 0b0110, 0b000));
    assert_eq!(TRCRSCTLR7,  sysreg(0b10, 0b001, 0b0001, 0b0111, 0b000));
    assert_eq!(TRCRSCTLR8,  sysreg(0b10, 0b001, 0b0001, 0b1000, 0b000));
    assert_eq!(TRCRSCTLR9,  sysreg(0b10, 0b001, 0b0001, 0b1001, 0b000));
    assert_eq!(TRCRSCTLR10, sysreg(0b10, 0b001, 0b0001, 0b1010, 0b000));
    assert_eq!(TRCRSCTLR11, sysreg(0b10, 0b001, 0b0001, 0b1011, 0b000));
    assert_eq!(TRCRSCTLR12, sysreg(0b10, 0b001, 0b0001, 0b1100, 0b000));
    assert_eq!(TRCRSCTLR13, sysreg(0b10, 0b001, 0b0001, 0b1101, 0b000));
    assert_eq!(TRCRSCTLR14, sysreg(0b10, 0b001, 0b0001, 0b1110, 0b000));
    assert_eq!(TRCRSCTLR15, sysreg(0b10, 0b001, 0b0001, 0b1111, 0b000));
    assert_eq!(TRCRSCTLR16, sysreg(0b10, 0b001, 0b0001, 0b0000, 0b001));
    assert_eq!(TRCRSCTLR17, sysreg(0b10, 0b001, 0b0001, 0b0001, 0b001));
    assert_eq!(TRCRSCTLR18, sysreg(0b10, 0b001, 0b0001, 0b0010, 0b001));
    assert_eq!(TRCRSCTLR19, sysreg(0b10, 0b001, 0b0001, 0b0011, 0b001));
    assert_eq!(TRCRSCTLR20, sysreg(0b10, 0b001, 0b0001, 0b0100, 0b001));
    assert_eq!(TRCRSCTLR21, sysreg(0b10, 0b001, 0b0001, 0b0101, 0b001));
    assert_eq!(TRCRSCTLR22, sysreg(0b10, 0b001, 0b0001, 0b0110, 0b001));
    assert_eq!(TRCRSCTLR23, sysreg(0b10, 0b001, 0b0001, 0b0111, 0b001));
    assert_eq!(TRCRSCTLR24, sysreg(0b10, 0b001, 0b0001, 0b1000, 0b001));
    assert_eq!(TRCRSCTLR25, sysreg(0b10, 0b001, 0b0001, 0b1001, 0b001));
    assert_eq!(TRCRSCTLR26, sysreg(0b10, 0b001, 0b0001, 0b1010, 0b001));
    assert_eq!(TRCRSCTLR27, sysreg(0b10, 0b001, 0b0001, 0b1011, 0b001));
    assert_eq!(TRCRSCTLR28, sysreg(0b10, 0b001, 0b0001, 0b1100, 0b001));
    assert_eq!(TRCRSCTLR29, sysreg(0b10, 0b001, 0b0001, 0b1101, 0b001));
    assert_eq!(TRCRSCTLR30, sysreg(0b10, 0b001, 0b0001, 0b1110, 0b001));
    assert_eq!(TRCRSCTLR31, sysreg(0b10, 0b001, 0b0001, 0b1111, 0b001));
}

#[test]
fn test_TRCSEQEVRn() {
    assert_eq!(TRCSEQEVR0, sysreg(0b10, 0b001, 0b0000, 0b0000, 0b100));
    assert_eq!(TRCSEQEVR1, sysreg(0b10, 0b001, 0b0000, 0b0001, 0b100));
    assert_eq!(TRCSEQEVR2, sysreg(0b10, 0b001, 0b0000, 0b0010, 0b100));
}

#[test]
fn test_TRCSSCCRn() {
    assert_eq!(TRCSSCCR0, sysreg(0b10, 0b001, 0b0001, 0b0000, 0b010));
    assert_eq!(TRCSSCCR1, sysreg(0b10, 0b001, 0b0001, 0b0001, 0b010));
    assert_eq!(TRCSSCCR2, sysreg(0b10, 0b001, 0b0001, 0b0010, 0b010));
    assert_eq!(TRCSSCCR3, sysreg(0b10, 0b001, 0b0001, 0b0011, 0b010));
    assert_eq!(TRCSSCCR4, sysreg(0b10, 0b001, 0b0001, 0b0100, 0b010));
    assert_eq!(TRCSSCCR5, sysreg(0b10, 0b001, 0b0001, 0b0101, 0b010));
    assert_eq!(TRCSSCCR6, sysreg(0b10, 0b001, 0b0001, 0b0110, 0b010));
    assert_eq!(TRCSSCCR7, sysreg(0b10, 0b001, 0b0001, 0b0111, 0b010));
}

#[test]
fn test_TRCSSCSRn() {
    assert_eq!(TRCSSCSR0, sysreg(0b10, 0b001, 0b0001, 0b1000, 0b010));
    assert_eq!(TRCSSCSR1, sysreg(0b10, 0b001, 0b0001, 0b1001, 0b010));
    assert_eq!(TRCSSCSR2, sysreg(0b10, 0b001, 0b0001, 0b1010, 0b010));
    assert_eq!(TRCSSCSR3, sysreg(0b10, 0b001, 0b0001, 0b1011, 0b010));
    assert_eq!(TRCSSCSR4, sysreg(0b10, 0b001, 0b0001, 0b1100, 0b010));
    assert_eq!(TRCSSCSR5, sysreg(0b10, 0b001, 0b0001, 0b1101, 0b010));
    assert_eq!(TRCSSCSR6, sysreg(0b10, 0b001, 0b0001, 0b1110, 0b010));
    assert_eq!(TRCSSCSR7, sysreg(0b10, 0b001, 0b0001, 0b1111, 0b010));
}

#[test]
fn test_TRCSSPCICRn() {
    assert_eq!(TRCSSPCICR0, sysreg(0b10, 0b001, 0b0001, 0b0000, 0b011));
    assert_eq!(TRCSSPCICR1, sysreg(0b10, 0b001, 0b0001, 0b0001, 0b011));
    assert_eq!(TRCSSPCICR2, sysreg(0b10, 0b001, 0b0001, 0b0010, 0b011));
    assert_eq!(TRCSSPCICR3, sysreg(0b10, 0b001, 0b0001, 0b0011, 0b011));
    assert_eq!(TRCSSPCICR4, sysreg(0b10, 0b001, 0b0001, 0b0100, 0b011));
    assert_eq!(TRCSSPCICR5, sysreg(0b10, 0b001, 0b0001, 0b0101, 0b011));
    assert_eq!(TRCSSPCICR6, sysreg(0b10, 0b001, 0b0001, 0b0110, 0b011));
    assert_eq!(TRCSSPCICR7, sysreg(0b10, 0b001, 0b0001, 0b0111, 0b011));
}

#[test]
fn test_TRCVMIDCVRn() {
    assert_eq!(TRCVMIDCVR0, sysreg(0b10, 0b001, 0b0011, 0b0000, 0b001));
    assert_eq!(TRCVMIDCVR1, sysreg(0b10, 0b001, 0b0011, 0b0010, 0b001));
    assert_eq!(TRCVMIDCVR2, sysreg(0b10, 0b001, 0b0011, 0b0100, 0b001));
    assert_eq!(TRCVMIDCVR3, sysreg(0b10, 0b001, 0b0011, 0b0110, 0b001));
    assert_eq!(TRCVMIDCVR4, sysreg(0b10, 0b001, 0b0011, 0b1000, 0b001));
    assert_eq!(TRCVMIDCVR5, sysreg(0b10, 0b001, 0b0011, 0b1010, 0b001));
    assert_eq!(TRCVMIDCVR6, sysreg(0b10, 0b001, 0b0011, 0b1100, 0b001));
    assert_eq!(TRCVMIDCVR7, sysreg(0b10, 0b001, 0b0011, 0b1110, 0b001));
}

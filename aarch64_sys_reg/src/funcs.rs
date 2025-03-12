// Copyright 2025 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! AArch64 system register range functions.
//!
//! This file consists of manually written functions to generate registers that cannot be handled
//! automatically by the code generator.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::AArch64SysRegId;

const fn bit(val: u8, bit_index: u32) -> u8 {
    (val >> bit_index) & 1
}

const fn bits(val: u8, hi_index: u32, lo_index: u32) -> u8 {
    let mask = 1u8.wrapping_shl(hi_index - lo_index + 1).wrapping_sub(1);
    (val >> lo_index) & mask
}

pub const fn AMEVCNTR0n_EL0(m: u8) -> AArch64SysRegId {
    assert!(m <= 3);
    let crm = (0b010 << 1) | bit(m, 3);
    let op2 = bits(m, 2, 0);
    AArch64SysRegId::new_unchecked(0b11, 0b011, 0b1101, crm, op2)
}

pub const fn AMEVCNTR1n_EL0(m: u8) -> AArch64SysRegId {
    assert!(m <= 15);
    let crm = (0b110 << 1) | bit(m, 3);
    let op2 = bits(m, 2, 0);
    AArch64SysRegId::new_unchecked(0b11, 0b011, 0b1101, crm, op2)
}

pub const fn AMEVCNTVOFF0n_EL2(m: u8) -> AArch64SysRegId {
    assert!(m <= 15);
    let crm = (0b100 << 1) | bit(m, 3);
    let op2 = bits(m, 2, 0);
    AArch64SysRegId::new_unchecked(0b11, 0b100, 0b1101, crm, op2)
}

pub const fn AMEVCNTVOFF1n_EL2(m: u8) -> AArch64SysRegId {
    assert!(m <= 15);
    let crm = (0b101 << 1) | bit(m, 3);
    let op2 = bits(m, 2, 0);
    AArch64SysRegId::new_unchecked(0b11, 0b100, 0b1101, crm, op2)
}

pub const fn AMEVTYPER0n_EL0(m: u8) -> AArch64SysRegId {
    assert!(m <= 3);
    let crm = (0b011 << 1) | bit(m, 3);
    let op2 = bits(m, 2, 0);
    AArch64SysRegId::new_unchecked(0b11, 0b011, 0b1101, crm, op2)
}

pub const fn AMEVTYPER1n_EL0(m: u8) -> AArch64SysRegId {
    assert!(m <= 15);
    let crm = (0b111 << 1) | bit(m, 3);
    let op2 = bits(m, 2, 0);
    AArch64SysRegId::new_unchecked(0b11, 0b011, 0b1101, crm, op2)
}

pub const fn BRBINFn_EL1(m: u8) -> AArch64SysRegId {
    assert!(m <= 31);
    let crm = bits(m, 3, 0);
    let op2 = (bit(m, 4) << 2) | 0b00;
    AArch64SysRegId::new_unchecked(0b10, 0b001, 0b1000, crm, op2)
}

pub const fn BRBSRCn_EL1(m: u8) -> AArch64SysRegId {
    assert!(m <= 31);
    let crm = bits(m, 3, 0);
    let op2 = (bit(m, 4) << 2) | 0b01;
    AArch64SysRegId::new_unchecked(0b10, 0b001, 0b1000, crm, op2)
}

pub const fn BRBTGTn_EL1(m: u8) -> AArch64SysRegId {
    assert!(m <= 31);
    let crm = bits(m, 3, 0);
    let op2 = (bit(m, 4) << 2) | 0b10;
    AArch64SysRegId::new_unchecked(0b10, 0b001, 0b1000, crm, op2)
}

pub const fn DBGBCRn_EL1(m: u8) -> AArch64SysRegId {
    assert!(m <= 15);
    let crm = bits(m, 3, 0);
    AArch64SysRegId::new_unchecked(0b10, 0b000, 0b0000, crm, 0b101)
}

pub const fn DBGBVRn_EL1(m: u8) -> AArch64SysRegId {
    assert!(m <= 15);
    let crm = bits(m, 3, 0);
    AArch64SysRegId::new_unchecked(0b10, 0b000, 0b0000, crm, 0b100)
}

pub const fn DBGWCRn_EL1(m: u8) -> AArch64SysRegId {
    assert!(m <= 15);
    let crm = bits(m, 3, 0);
    AArch64SysRegId::new_unchecked(0b10, 0b000, 0b0000, crm, 0b111)
}

pub const fn DBGWVRn_EL1(m: u8) -> AArch64SysRegId {
    assert!(m <= 15);
    let crm = bits(m, 3, 0);
    AArch64SysRegId::new_unchecked(0b10, 0b000, 0b0000, crm, 0b110)
}

pub const fn ICC_AP0Rn_EL1(m: u8) -> AArch64SysRegId {
    assert!(m <= 3);
    let op2 = (0b1 << 2) | bits(m, 1, 0);
    AArch64SysRegId::new_unchecked(0b11, 0b000, 0b1100, 0b1000, op2)
}

pub const fn ICC_AP1Rn_EL1(m: u8) -> AArch64SysRegId {
    assert!(m <= 3);
    let op2 = (0b0 << 2) | bits(m, 1, 0);
    AArch64SysRegId::new_unchecked(0b11, 0b000, 0b1100, 0b1001, op2)
}

pub const fn ICH_AP0Rn_EL2(m: u8) -> AArch64SysRegId {
    assert!(m <= 3);
    let op2 = (0b0 << 2) | bits(m, 1, 0);
    AArch64SysRegId::new_unchecked(0b11, 0b100, 0b1100, 0b1000, op2)
}

pub const fn ICH_AP1Rn_EL2(m: u8) -> AArch64SysRegId {
    assert!(m <= 3);
    let op2 = (0b0 << 2) | bits(m, 1, 0);
    AArch64SysRegId::new_unchecked(0b11, 0b100, 0b1100, 0b1001, op2)
}

pub const fn ICH_LRn_EL2(m: u8) -> AArch64SysRegId {
    assert!(m <= 15);
    let crm = (0b110 << 1) | bit(m, 3);
    let op2 = bits(m, 2, 0);
    AArch64SysRegId::new_unchecked(0b11, 0b100, 0b1100, crm, op2)
}

pub const fn PMEVCNTRn_EL0(m: u8) -> AArch64SysRegId {
    assert!(m <= 30);
    let crm = (0b10 << 2) | bits(m, 4, 3);
    let op2 = bits(m, 2, 0);
    AArch64SysRegId::new_unchecked(0b11, 0b011, 0b1110, crm, op2)
}

pub const fn PMEVCNTSVRn_EL1(m: u8) -> AArch64SysRegId {
    assert!(m <= 30);
    let crm = (0b10 << 2) | bits(m, 4, 3);
    let op2 = bits(m, 2, 0);
    AArch64SysRegId::new_unchecked(0b10, 0b000, 0b1110, crm, op2)
}

pub const fn PMEVTYPERn_EL0(m: u8) -> AArch64SysRegId {
    assert!(m <= 30);
    let crm = (0b11 << 2) | bits(m, 4, 3);
    let op2 = bits(m, 2, 0);
    AArch64SysRegId::new_unchecked(0b11, 0b011, 0b1110, crm, op2)
}

pub const fn SPMCGCRn_EL1(m: u8) -> AArch64SysRegId {
    assert!(m <= 1);
    let op2 = (0b00 << 1) | bit(m, 0);
    AArch64SysRegId::new_unchecked(0b10, 0b000, 0b1001, 0b1101, op2)
}

pub const fn SPMEVCNTRn_EL0(m: u8) -> AArch64SysRegId {
    assert!(m <= 15);
    let crm = (0b000 << 1) | bit(m, 3);
    let op2 = bits(m, 2, 0);
    AArch64SysRegId::new_unchecked(0b10, 0b011, 0b1110, crm, op2)
}

pub const fn SPMEVFILT2Rn_EL0(m: u8) -> AArch64SysRegId {
    assert!(m <= 15);
    let crm = (0b011 << 1) | bit(m, 3);
    let op2 = bits(m, 2, 0);
    AArch64SysRegId::new_unchecked(0b10, 0b011, 0b1110, crm, op2)
}

pub const fn SPMEVFILTRn_EL0(m: u8) -> AArch64SysRegId {
    assert!(m <= 15);
    let crm = (0b010 << 1) | bit(m, 3);
    let op2 = bits(m, 2, 0);
    AArch64SysRegId::new_unchecked(0b10, 0b011, 0b1110, crm, op2)
}

pub const fn SPMEVTYPERn_EL0(m: u8) -> AArch64SysRegId {
    assert!(m <= 15);
    let crm = (0b001 << 1) | bit(m, 3);
    let op2 = bits(m, 2, 0);
    AArch64SysRegId::new_unchecked(0b10, 0b011, 0b1110, crm, op2)
}

pub const fn TRCACATRn(m: u8) -> AArch64SysRegId {
    assert!(m <= 15);
    let crm = (bits(m, 2, 0) << 1) | 0b0;
    let op2 = (0b01 << 1) | bit(m, 3);
    AArch64SysRegId::new_unchecked(0b10, 0b001, 0b0010, crm, op2)
}

pub const fn TRCACVRn(m: u8) -> AArch64SysRegId {
    assert!(m <= 15);
    let crm = (bits(m, 2, 0) << 1) | 0b0;
    let op2 = (0b00 << 1) | bit(m, 3);
    AArch64SysRegId::new_unchecked(0b10, 0b001, 0b0010, crm, op2)
}

pub const fn TRCCIDCVRn(m: u8) -> AArch64SysRegId {
    assert!(m <= 7);
    let crm = (bits(m, 2, 0) << 1) | 0b0;
    AArch64SysRegId::new_unchecked(0b10, 0b001, 0b0011, crm, 0b000)
}

pub const fn TRCCNTCTLRn(m: u8) -> AArch64SysRegId {
    assert!(m <= 3);
    let crm = (0b01 << 2) | bits(m, 1, 0);
    AArch64SysRegId::new_unchecked(0b10, 0b001, 0b0000, crm, 0b101)
}

pub const fn TRCCNTRLDVRn(m: u8) -> AArch64SysRegId {
    assert!(m <= 3);
    let crm = (0b00 << 1) | bits(m, 1, 0);
    AArch64SysRegId::new_unchecked(0b10, 0b001, 0b0000, crm, 0b101)
}

pub const fn TRCCNTVRn(m: u8) -> AArch64SysRegId {
    assert!(m <= 3);
    let crm = (0b10 << 2) | bits(m, 1, 0);
    AArch64SysRegId::new_unchecked(0b10, 0b001, 0b0000, crm, 0b101)
}

pub const fn TRCEXTINSELRn(m: u8) -> AArch64SysRegId {
    assert!(m <= 3);
    let crm = (0b10 << 2) | bits(m, 1, 0);
    AArch64SysRegId::new_unchecked(0b10, 0b001, 0b0000, crm, 0b100)
}

pub const fn TRCIMSPECn(m: u8) -> AArch64SysRegId {
    assert!(m >= 1 && m <= 7);
    let crm = (0b0 << 3) | bits(m, 2, 0);
    AArch64SysRegId::new_unchecked(0b10, 0b001, 0b0000, crm, 0b111)
}

pub const fn TRCRSCTLRn(m: u8) -> AArch64SysRegId {
    assert!(m >= 2 && m <= 31);
    let crm = bits(m, 3, 0);
    let op2 = (0b00 << 1) | bit(m, 4);
    AArch64SysRegId::new_unchecked(0b10, 0b001, 0b0001, crm, op2)
}

pub const fn TRCSEQEVRn(m: u8) -> AArch64SysRegId {
    assert!(m <= 2);
    let crm = (0b00 << 2) | bits(m, 1, 0);
    AArch64SysRegId::new_unchecked(0b10, 0b001, 0b0000, crm, 0b100)
}

pub const fn TRCSSCCRn(m: u8) -> AArch64SysRegId {
    assert!(m <= 7);
    let crm = (0b0 << 3) | bits(m, 2, 0);
    AArch64SysRegId::new_unchecked(0b10, 0b001, 0b0001, crm, 0b010)
}

pub const fn TRCSSCSRn(m: u8) -> AArch64SysRegId {
    assert!(m <= 7);
    let crm = (0b1 << 3) | bits(m, 2, 0);
    AArch64SysRegId::new_unchecked(0b10, 0b001, 0b0001, crm, 0b010)
}

pub const fn TRCSSPCICRn(m: u8) -> AArch64SysRegId {
    assert!(m <= 7);
    let crm = (0b0 << 3) | bits(m, 2, 0);
    AArch64SysRegId::new_unchecked(0b10, 0b001, 0b0001, crm, 0b011)
}

pub const fn TRCVMIDCVRn(m: u8) -> AArch64SysRegId {
    assert!(m <= 7);
    let crm = (bits(m, 2, 0) << 1) | 0b0;
    AArch64SysRegId::new_unchecked(0b10, 0b001, 0b0011, crm, 0b001)
}

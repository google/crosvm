// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;

use once_cell::sync::Lazy;
use serde::Deserialize;
use serde::Serialize;

use super::whpx_sys::*;
use crate::CpuIdEntry;
use crate::DebugRegs;
use crate::DescriptorTable;
use crate::Fpu;
use crate::FpuReg;
use crate::LapicState;
use crate::Regs;
use crate::Segment;
use crate::Sregs;

#[derive(Default)]
pub(super) struct WhpxRegs {
    register_values: [WHV_REGISTER_VALUE; 18],
}

impl WhpxRegs {
    pub(super) fn get_register_names() -> &'static [WHV_REGISTER_NAME; 18] {
        const REG_NAMES: [WHV_REGISTER_NAME; 18] = [
            WHV_REGISTER_NAME_WHvX64RegisterRax,
            WHV_REGISTER_NAME_WHvX64RegisterRbx,
            WHV_REGISTER_NAME_WHvX64RegisterRcx,
            WHV_REGISTER_NAME_WHvX64RegisterRdx,
            WHV_REGISTER_NAME_WHvX64RegisterRsi,
            WHV_REGISTER_NAME_WHvX64RegisterRdi,
            WHV_REGISTER_NAME_WHvX64RegisterRsp,
            WHV_REGISTER_NAME_WHvX64RegisterRbp,
            WHV_REGISTER_NAME_WHvX64RegisterR8,
            WHV_REGISTER_NAME_WHvX64RegisterR9,
            WHV_REGISTER_NAME_WHvX64RegisterR10,
            WHV_REGISTER_NAME_WHvX64RegisterR11,
            WHV_REGISTER_NAME_WHvX64RegisterR12,
            WHV_REGISTER_NAME_WHvX64RegisterR13,
            WHV_REGISTER_NAME_WHvX64RegisterR14,
            WHV_REGISTER_NAME_WHvX64RegisterR15,
            WHV_REGISTER_NAME_WHvX64RegisterRip,
            WHV_REGISTER_NAME_WHvX64RegisterRflags,
        ];
        &REG_NAMES
    }
    pub(super) fn as_ptr(&self) -> *const WHV_REGISTER_VALUE {
        self.register_values.as_ptr()
    }
    pub(super) fn as_mut_ptr(&mut self) -> *mut WHV_REGISTER_VALUE {
        self.register_values.as_mut_ptr()
    }
}

impl From<&Regs> for WhpxRegs {
    fn from(regs: &Regs) -> Self {
        WhpxRegs {
            register_values: [
                WHV_REGISTER_VALUE { Reg64: regs.rax },
                WHV_REGISTER_VALUE { Reg64: regs.rbx },
                WHV_REGISTER_VALUE { Reg64: regs.rcx },
                WHV_REGISTER_VALUE { Reg64: regs.rdx },
                WHV_REGISTER_VALUE { Reg64: regs.rsi },
                WHV_REGISTER_VALUE { Reg64: regs.rdi },
                WHV_REGISTER_VALUE { Reg64: regs.rsp },
                WHV_REGISTER_VALUE { Reg64: regs.rbp },
                WHV_REGISTER_VALUE { Reg64: regs.r8 },
                WHV_REGISTER_VALUE { Reg64: regs.r9 },
                WHV_REGISTER_VALUE { Reg64: regs.r10 },
                WHV_REGISTER_VALUE { Reg64: regs.r11 },
                WHV_REGISTER_VALUE { Reg64: regs.r12 },
                WHV_REGISTER_VALUE { Reg64: regs.r13 },
                WHV_REGISTER_VALUE { Reg64: regs.r14 },
                WHV_REGISTER_VALUE { Reg64: regs.r15 },
                WHV_REGISTER_VALUE { Reg64: regs.rip },
                WHV_REGISTER_VALUE { Reg64: regs.rflags },
            ],
        }
    }
}

impl From<&WhpxRegs> for Regs {
    fn from(whpx_regs: &WhpxRegs) -> Self {
        unsafe {
            Regs {
                rax: whpx_regs.register_values[0].Reg64,
                rbx: whpx_regs.register_values[1].Reg64,
                rcx: whpx_regs.register_values[2].Reg64,
                rdx: whpx_regs.register_values[3].Reg64,
                rsi: whpx_regs.register_values[4].Reg64,
                rdi: whpx_regs.register_values[5].Reg64,
                rsp: whpx_regs.register_values[6].Reg64,
                rbp: whpx_regs.register_values[7].Reg64,
                r8: whpx_regs.register_values[8].Reg64,
                r9: whpx_regs.register_values[9].Reg64,
                r10: whpx_regs.register_values[10].Reg64,
                r11: whpx_regs.register_values[11].Reg64,
                r12: whpx_regs.register_values[12].Reg64,
                r13: whpx_regs.register_values[13].Reg64,
                r14: whpx_regs.register_values[14].Reg64,
                r15: whpx_regs.register_values[15].Reg64,
                rip: whpx_regs.register_values[16].Reg64,
                rflags: whpx_regs.register_values[17].Reg64,
            }
        }
    }
}

impl From<&Segment> for WHV_X64_SEGMENT_REGISTER {
    fn from(segment: &Segment) -> Self {
        let attributes = WHV_X64_SEGMENT_REGISTER__bindgen_ty_1__bindgen_ty_1::new_bitfield_1(
            segment.type_.into(),
            segment.s.into(),
            segment.dpl.into(),
            segment.present.into(),
            0, // reserved
            segment.avl.into(),
            segment.l.into(),
            segment.db.into(),
            segment.g.into(),
        );
        WHV_X64_SEGMENT_REGISTER {
            Base: segment.base,
            Limit: segment.limit,
            Selector: segment.selector,
            __bindgen_anon_1: WHV_X64_SEGMENT_REGISTER__bindgen_ty_1 {
                __bindgen_anon_1: WHV_X64_SEGMENT_REGISTER__bindgen_ty_1__bindgen_ty_1 {
                    _bitfield_align_1: [],
                    _bitfield_1: attributes,
                },
            },
        }
    }
}

impl From<&WHV_X64_SEGMENT_REGISTER> for Segment {
    fn from(whpx_segment: &WHV_X64_SEGMENT_REGISTER) -> Self {
        // safe because the union field can always be interpreteted as a bitfield
        let attributes = unsafe { whpx_segment.__bindgen_anon_1.__bindgen_anon_1 };
        Segment {
            base: whpx_segment.Base,
            limit: whpx_segment.Limit,
            selector: whpx_segment.Selector,
            type_: attributes.SegmentType() as u8,
            present: attributes.Present() as u8,
            dpl: attributes.DescriptorPrivilegeLevel() as u8,
            db: attributes.Default() as u8,
            s: attributes.NonSystemSegment() as u8,
            l: attributes.Long() as u8,
            g: attributes.Granularity() as u8,
            avl: attributes.Available() as u8,
        }
    }
}

impl From<&DescriptorTable> for WHV_X64_TABLE_REGISTER {
    fn from(descr_table: &DescriptorTable) -> Self {
        WHV_X64_TABLE_REGISTER {
            Pad: Default::default(),
            Base: descr_table.base,
            Limit: descr_table.limit,
        }
    }
}

impl From<&WHV_X64_TABLE_REGISTER> for DescriptorTable {
    fn from(whpx_table_register: &WHV_X64_TABLE_REGISTER) -> Self {
        DescriptorTable {
            base: whpx_table_register.Base,
            limit: whpx_table_register.Limit,
        }
    }
}

#[derive(Default)]
pub(super) struct WhpxSregs {
    register_values: [WHV_REGISTER_VALUE; 16],
}

impl WhpxSregs {
    pub(super) fn get_register_names() -> &'static [WHV_REGISTER_NAME; 16] {
        const REG_NAMES: [WHV_REGISTER_NAME; 16] = [
            WHV_REGISTER_NAME_WHvX64RegisterCs,
            WHV_REGISTER_NAME_WHvX64RegisterDs,
            WHV_REGISTER_NAME_WHvX64RegisterEs,
            WHV_REGISTER_NAME_WHvX64RegisterFs,
            WHV_REGISTER_NAME_WHvX64RegisterGs,
            WHV_REGISTER_NAME_WHvX64RegisterSs,
            WHV_REGISTER_NAME_WHvX64RegisterTr,
            WHV_REGISTER_NAME_WHvX64RegisterLdtr,
            WHV_REGISTER_NAME_WHvX64RegisterGdtr,
            WHV_REGISTER_NAME_WHvX64RegisterIdtr,
            WHV_REGISTER_NAME_WHvX64RegisterCr0,
            WHV_REGISTER_NAME_WHvX64RegisterCr2,
            WHV_REGISTER_NAME_WHvX64RegisterCr3,
            WHV_REGISTER_NAME_WHvX64RegisterCr4,
            WHV_REGISTER_NAME_WHvX64RegisterCr8,
            WHV_REGISTER_NAME_WHvX64RegisterEfer, // this is actually an msr
        ];
        &REG_NAMES
    }
    pub(super) fn as_ptr(&self) -> *const WHV_REGISTER_VALUE {
        self.register_values.as_ptr()
    }
    pub(super) fn as_mut_ptr(&mut self) -> *mut WHV_REGISTER_VALUE {
        self.register_values.as_mut_ptr()
    }
}

impl From<&Sregs> for WhpxSregs {
    fn from(sregs: &Sregs) -> Self {
        WhpxSregs {
            register_values: [
                WHV_REGISTER_VALUE {
                    Segment: WHV_X64_SEGMENT_REGISTER::from(&sregs.cs),
                },
                WHV_REGISTER_VALUE {
                    Segment: WHV_X64_SEGMENT_REGISTER::from(&sregs.ds),
                },
                WHV_REGISTER_VALUE {
                    Segment: WHV_X64_SEGMENT_REGISTER::from(&sregs.es),
                },
                WHV_REGISTER_VALUE {
                    Segment: WHV_X64_SEGMENT_REGISTER::from(&sregs.fs),
                },
                WHV_REGISTER_VALUE {
                    Segment: WHV_X64_SEGMENT_REGISTER::from(&sregs.gs),
                },
                WHV_REGISTER_VALUE {
                    Segment: WHV_X64_SEGMENT_REGISTER::from(&sregs.ss),
                },
                WHV_REGISTER_VALUE {
                    Segment: WHV_X64_SEGMENT_REGISTER::from(&sregs.tr),
                },
                WHV_REGISTER_VALUE {
                    Segment: WHV_X64_SEGMENT_REGISTER::from(&sregs.ldt),
                },
                WHV_REGISTER_VALUE {
                    Table: WHV_X64_TABLE_REGISTER::from(&sregs.gdt),
                },
                WHV_REGISTER_VALUE {
                    Table: WHV_X64_TABLE_REGISTER::from(&sregs.idt),
                },
                WHV_REGISTER_VALUE { Reg64: sregs.cr0 },
                WHV_REGISTER_VALUE { Reg64: sregs.cr2 },
                WHV_REGISTER_VALUE { Reg64: sregs.cr3 },
                WHV_REGISTER_VALUE { Reg64: sregs.cr4 },
                WHV_REGISTER_VALUE { Reg64: sregs.cr8 },
                WHV_REGISTER_VALUE { Reg64: sregs.efer },
            ],
        }
    }
}

impl From<&WhpxSregs> for Sregs {
    fn from(whpx_regs: &WhpxSregs) -> Self {
        unsafe {
            Sregs {
                cs: Segment::from(&whpx_regs.register_values[0].Segment),
                ds: Segment::from(&whpx_regs.register_values[1].Segment),
                es: Segment::from(&whpx_regs.register_values[2].Segment),
                fs: Segment::from(&whpx_regs.register_values[3].Segment),
                gs: Segment::from(&whpx_regs.register_values[4].Segment),
                ss: Segment::from(&whpx_regs.register_values[5].Segment),
                tr: Segment::from(&whpx_regs.register_values[6].Segment),
                ldt: Segment::from(&whpx_regs.register_values[7].Segment),
                gdt: DescriptorTable::from(&whpx_regs.register_values[8].Table),
                idt: DescriptorTable::from(&whpx_regs.register_values[9].Table),
                cr0: whpx_regs.register_values[10].Reg64,
                cr2: whpx_regs.register_values[11].Reg64,
                cr3: whpx_regs.register_values[12].Reg64,
                cr4: whpx_regs.register_values[13].Reg64,
                cr8: whpx_regs.register_values[14].Reg64,
                efer: whpx_regs.register_values[15].Reg64,
            }
        }
    }
}

impl From<u128> for WHV_UINT128 {
    fn from(v: u128) -> WHV_UINT128 {
        WHV_UINT128 {
            __bindgen_anon_1: WHV_UINT128__bindgen_ty_1 {
                Low64: v as u64,
                High64: (v >> 64) as u64,
            },
        }
    }
}

impl From<WHV_UINT128> for u128 {
    fn from(v: WHV_UINT128) -> u128 {
        // SAFETY: Accessing u64 fields of the union is always safe since all bit patterns are valid
        // for u64.
        let (low64, high64) = unsafe { (v.__bindgen_anon_1.Low64, v.__bindgen_anon_1.High64) };
        u128::from(low64) | (u128::from(high64) << 64)
    }
}

impl WHV_UINT128 {
    #[inline]
    pub fn from_ne_bytes(bytes: [u8; 16]) -> WHV_UINT128 {
        WHV_UINT128::from(u128::from_ne_bytes(bytes))
    }

    #[inline]
    pub fn to_ne_bytes(self) -> [u8; 16] {
        u128::from(self).to_ne_bytes()
    }
}

#[derive(Default)]
pub(super) struct WhpxFpu {
    register_values: [WHV_REGISTER_VALUE; 26],
}

impl WhpxFpu {
    pub(super) fn get_register_names() -> &'static [WHV_REGISTER_NAME; 26] {
        const REG_NAMES: [WHV_REGISTER_NAME; 26] = [
            WHV_REGISTER_NAME_WHvX64RegisterFpMmx0,
            WHV_REGISTER_NAME_WHvX64RegisterFpMmx1,
            WHV_REGISTER_NAME_WHvX64RegisterFpMmx2,
            WHV_REGISTER_NAME_WHvX64RegisterFpMmx3,
            WHV_REGISTER_NAME_WHvX64RegisterFpMmx4,
            WHV_REGISTER_NAME_WHvX64RegisterFpMmx5,
            WHV_REGISTER_NAME_WHvX64RegisterFpMmx6,
            WHV_REGISTER_NAME_WHvX64RegisterFpMmx7,
            WHV_REGISTER_NAME_WHvX64RegisterFpControlStatus,
            WHV_REGISTER_NAME_WHvX64RegisterXmmControlStatus,
            WHV_REGISTER_NAME_WHvX64RegisterXmm0,
            WHV_REGISTER_NAME_WHvX64RegisterXmm1,
            WHV_REGISTER_NAME_WHvX64RegisterXmm2,
            WHV_REGISTER_NAME_WHvX64RegisterXmm3,
            WHV_REGISTER_NAME_WHvX64RegisterXmm4,
            WHV_REGISTER_NAME_WHvX64RegisterXmm5,
            WHV_REGISTER_NAME_WHvX64RegisterXmm6,
            WHV_REGISTER_NAME_WHvX64RegisterXmm7,
            WHV_REGISTER_NAME_WHvX64RegisterXmm8,
            WHV_REGISTER_NAME_WHvX64RegisterXmm9,
            WHV_REGISTER_NAME_WHvX64RegisterXmm10,
            WHV_REGISTER_NAME_WHvX64RegisterXmm11,
            WHV_REGISTER_NAME_WHvX64RegisterXmm12,
            WHV_REGISTER_NAME_WHvX64RegisterXmm13,
            WHV_REGISTER_NAME_WHvX64RegisterXmm14,
            WHV_REGISTER_NAME_WHvX64RegisterXmm15,
        ];
        &REG_NAMES
    }
    pub(super) fn as_ptr(&self) -> *const WHV_REGISTER_VALUE {
        self.register_values.as_ptr()
    }
    pub(super) fn as_mut_ptr(&mut self) -> *mut WHV_REGISTER_VALUE {
        self.register_values.as_mut_ptr()
    }
}

fn whpx_register_from_fpu_reg(fpr: FpuReg) -> WHV_REGISTER_VALUE {
    WHV_REGISTER_VALUE {
        Fp: WHV_X64_FP_REGISTER {
            AsUINT128: WHV_UINT128::from_ne_bytes(fpr.into()),
        },
    }
}

impl From<&Fpu> for WhpxFpu {
    fn from(fpu: &Fpu) -> Self {
        WhpxFpu {
            register_values: [
                whpx_register_from_fpu_reg(fpu.fpr[0]),
                whpx_register_from_fpu_reg(fpu.fpr[1]),
                whpx_register_from_fpu_reg(fpu.fpr[2]),
                whpx_register_from_fpu_reg(fpu.fpr[3]),
                whpx_register_from_fpu_reg(fpu.fpr[4]),
                whpx_register_from_fpu_reg(fpu.fpr[5]),
                whpx_register_from_fpu_reg(fpu.fpr[6]),
                whpx_register_from_fpu_reg(fpu.fpr[7]),
                WHV_REGISTER_VALUE {
                    FpControlStatus: WHV_X64_FP_CONTROL_STATUS_REGISTER {
                        __bindgen_anon_1: WHV_X64_FP_CONTROL_STATUS_REGISTER__bindgen_ty_1 {
                            FpControl: fpu.fcw,
                            FpStatus: fpu.fsw,
                            FpTag: fpu.ftwx,
                            Reserved: 0,
                            LastFpOp: fpu.last_opcode,
                            __bindgen_anon_1:
                                WHV_X64_FP_CONTROL_STATUS_REGISTER__bindgen_ty_1__bindgen_ty_1 {
                                    LastFpRip: fpu.last_ip,
                                },
                        },
                    },
                },
                WHV_REGISTER_VALUE {
                    XmmControlStatus: WHV_X64_XMM_CONTROL_STATUS_REGISTER {
                        __bindgen_anon_1: WHV_X64_XMM_CONTROL_STATUS_REGISTER__bindgen_ty_1 {
                            __bindgen_anon_1:
                                WHV_X64_XMM_CONTROL_STATUS_REGISTER__bindgen_ty_1__bindgen_ty_1 {
                                    LastFpRdp: fpu.last_dp,
                                },
                            XmmStatusControl: fpu.mxcsr,
                            XmmStatusControlMask: 0,
                        },
                    },
                },
                WHV_REGISTER_VALUE {
                    Reg128: WHV_UINT128::from_ne_bytes(fpu.xmm[0]),
                },
                WHV_REGISTER_VALUE {
                    Reg128: WHV_UINT128::from_ne_bytes(fpu.xmm[1]),
                },
                WHV_REGISTER_VALUE {
                    Reg128: WHV_UINT128::from_ne_bytes(fpu.xmm[2]),
                },
                WHV_REGISTER_VALUE {
                    Reg128: WHV_UINT128::from_ne_bytes(fpu.xmm[3]),
                },
                WHV_REGISTER_VALUE {
                    Reg128: WHV_UINT128::from_ne_bytes(fpu.xmm[4]),
                },
                WHV_REGISTER_VALUE {
                    Reg128: WHV_UINT128::from_ne_bytes(fpu.xmm[5]),
                },
                WHV_REGISTER_VALUE {
                    Reg128: WHV_UINT128::from_ne_bytes(fpu.xmm[6]),
                },
                WHV_REGISTER_VALUE {
                    Reg128: WHV_UINT128::from_ne_bytes(fpu.xmm[7]),
                },
                WHV_REGISTER_VALUE {
                    Reg128: WHV_UINT128::from_ne_bytes(fpu.xmm[8]),
                },
                WHV_REGISTER_VALUE {
                    Reg128: WHV_UINT128::from_ne_bytes(fpu.xmm[9]),
                },
                WHV_REGISTER_VALUE {
                    Reg128: WHV_UINT128::from_ne_bytes(fpu.xmm[10]),
                },
                WHV_REGISTER_VALUE {
                    Reg128: WHV_UINT128::from_ne_bytes(fpu.xmm[11]),
                },
                WHV_REGISTER_VALUE {
                    Reg128: WHV_UINT128::from_ne_bytes(fpu.xmm[12]),
                },
                WHV_REGISTER_VALUE {
                    Reg128: WHV_UINT128::from_ne_bytes(fpu.xmm[13]),
                },
                WHV_REGISTER_VALUE {
                    Reg128: WHV_UINT128::from_ne_bytes(fpu.xmm[14]),
                },
                WHV_REGISTER_VALUE {
                    Reg128: WHV_UINT128::from_ne_bytes(fpu.xmm[15]),
                },
            ],
        }
    }
}

fn fpu_reg_from_whpx_register(whpx_reg: &WHV_REGISTER_VALUE) -> FpuReg {
    let fp_reg_bytes: [u8; 10] = unsafe {
        whpx_reg.Fp.AsUINT128.to_ne_bytes()[0..10]
            .try_into()
            .unwrap()
    };
    FpuReg::from(fp_reg_bytes)
}

impl From<&WhpxFpu> for Fpu {
    fn from(whpx_regs: &WhpxFpu) -> Self {
        unsafe {
            let fp_control = whpx_regs.register_values[8]
                .FpControlStatus
                .__bindgen_anon_1;
            let xmm_control = whpx_regs.register_values[9]
                .XmmControlStatus
                .__bindgen_anon_1;
            Fpu {
                fpr: [
                    fpu_reg_from_whpx_register(&whpx_regs.register_values[0]),
                    fpu_reg_from_whpx_register(&whpx_regs.register_values[1]),
                    fpu_reg_from_whpx_register(&whpx_regs.register_values[2]),
                    fpu_reg_from_whpx_register(&whpx_regs.register_values[3]),
                    fpu_reg_from_whpx_register(&whpx_regs.register_values[4]),
                    fpu_reg_from_whpx_register(&whpx_regs.register_values[5]),
                    fpu_reg_from_whpx_register(&whpx_regs.register_values[6]),
                    fpu_reg_from_whpx_register(&whpx_regs.register_values[7]),
                ],
                fcw: fp_control.FpControl,
                fsw: fp_control.FpStatus,
                ftwx: fp_control.FpTag,
                last_opcode: fp_control.LastFpOp,
                last_ip: fp_control.__bindgen_anon_1.LastFpRip,
                last_dp: xmm_control.__bindgen_anon_1.LastFpRdp,
                xmm: [
                    whpx_regs.register_values[10].Reg128.to_ne_bytes(),
                    whpx_regs.register_values[11].Reg128.to_ne_bytes(),
                    whpx_regs.register_values[12].Reg128.to_ne_bytes(),
                    whpx_regs.register_values[13].Reg128.to_ne_bytes(),
                    whpx_regs.register_values[14].Reg128.to_ne_bytes(),
                    whpx_regs.register_values[15].Reg128.to_ne_bytes(),
                    whpx_regs.register_values[16].Reg128.to_ne_bytes(),
                    whpx_regs.register_values[17].Reg128.to_ne_bytes(),
                    whpx_regs.register_values[18].Reg128.to_ne_bytes(),
                    whpx_regs.register_values[19].Reg128.to_ne_bytes(),
                    whpx_regs.register_values[20].Reg128.to_ne_bytes(),
                    whpx_regs.register_values[21].Reg128.to_ne_bytes(),
                    whpx_regs.register_values[22].Reg128.to_ne_bytes(),
                    whpx_regs.register_values[23].Reg128.to_ne_bytes(),
                    whpx_regs.register_values[24].Reg128.to_ne_bytes(),
                    whpx_regs.register_values[25].Reg128.to_ne_bytes(),
                ],
                mxcsr: xmm_control.XmmStatusControl,
            }
        }
    }
}

#[derive(Default)]
pub(super) struct WhpxDebugRegs {
    register_values: [WHV_REGISTER_VALUE; 6],
}

impl WhpxDebugRegs {
    pub(super) fn get_register_names() -> &'static [WHV_REGISTER_NAME; 6] {
        const REG_NAMES: [WHV_REGISTER_NAME; 6] = [
            WHV_REGISTER_NAME_WHvX64RegisterDr0,
            WHV_REGISTER_NAME_WHvX64RegisterDr1,
            WHV_REGISTER_NAME_WHvX64RegisterDr2,
            WHV_REGISTER_NAME_WHvX64RegisterDr3,
            WHV_REGISTER_NAME_WHvX64RegisterDr6,
            WHV_REGISTER_NAME_WHvX64RegisterDr7,
        ];
        &REG_NAMES
    }
    pub(super) fn as_ptr(&self) -> *const WHV_REGISTER_VALUE {
        self.register_values.as_ptr()
    }
    pub(super) fn as_mut_ptr(&mut self) -> *mut WHV_REGISTER_VALUE {
        self.register_values.as_mut_ptr()
    }
}

impl From<&DebugRegs> for WhpxDebugRegs {
    fn from(debug_regs: &DebugRegs) -> Self {
        WhpxDebugRegs {
            register_values: [
                WHV_REGISTER_VALUE {
                    Reg64: debug_regs.db[0],
                },
                WHV_REGISTER_VALUE {
                    Reg64: debug_regs.db[1],
                },
                WHV_REGISTER_VALUE {
                    Reg64: debug_regs.db[2],
                },
                WHV_REGISTER_VALUE {
                    Reg64: debug_regs.db[3],
                },
                WHV_REGISTER_VALUE {
                    Reg64: debug_regs.dr6,
                },
                WHV_REGISTER_VALUE {
                    Reg64: debug_regs.dr7,
                },
            ],
        }
    }
}

impl From<&WhpxDebugRegs> for DebugRegs {
    fn from(whpx_regs: &WhpxDebugRegs) -> Self {
        // safe because accessing the union Reg64 value for WhpxDebugRegs should
        // always be valid.
        unsafe {
            DebugRegs {
                db: [
                    whpx_regs.register_values[0].Reg64,
                    whpx_regs.register_values[1].Reg64,
                    whpx_regs.register_values[2].Reg64,
                    whpx_regs.register_values[3].Reg64,
                ],
                dr6: whpx_regs.register_values[4].Reg64,
                dr7: whpx_regs.register_values[5].Reg64,
            }
        }
    }
}

/// Registers that store pending interrupts and interrupt state.
///
/// There are four critical registers:
/// * WHvRegisterPendingInterruption (u64; HTLFS page 55): contains interrupts which are pending,
///   but not yet delivered.
/// * WHvRegisterInterruptState (u64; HTLFS page 55): contains the interrupt state for the VCPU
///   (e.g. masking nmis, etc).
/// * WHvX64RegisterDeliverabilityNotifications (u64; WHPX docs only): allows us to request a VCPU
///   exit once injection of interrupts is possible.
/// * WHvRegisterInternalActivityState (u64; WHPX docs only): this register is unspecified except
///   for its existence, so we consider it to be opaque. From experimentation, we believe it
///   contains some kind of state required by SMP guests, because snapshotting/restoring without it
///   causes all APs to freeze (the BSP does exit periodically, but also seems to be very unhappy).
#[derive(Default)]
pub(super) struct WhpxInterruptRegs {
    register_values: [WHV_REGISTER_VALUE; 4],
}

#[derive(Serialize, Deserialize)]
pub(super) struct SerializedWhpxInterruptRegs {
    pending_interruption: u64,
    interrupt_state: u64,
    deliverability_notifications: u64,
    internal_activity_state: u64,
}

impl WhpxInterruptRegs {
    pub(super) fn get_register_names() -> &'static [WHV_REGISTER_NAME; 4] {
        const REG_NAMES: [WHV_REGISTER_NAME; 4] = [
            WHV_REGISTER_NAME_WHvRegisterPendingInterruption,
            WHV_REGISTER_NAME_WHvRegisterInterruptState,
            WHV_REGISTER_NAME_WHvX64RegisterDeliverabilityNotifications,
            WHV_REGISTER_NAME_WHvRegisterInternalActivityState,
        ];
        &REG_NAMES
    }
    pub(super) fn as_ptr(&self) -> *const WHV_REGISTER_VALUE {
        self.register_values.as_ptr()
    }
    pub(super) fn as_mut_ptr(&mut self) -> *mut WHV_REGISTER_VALUE {
        self.register_values.as_mut_ptr()
    }

    pub(super) fn into_serializable(self) -> SerializedWhpxInterruptRegs {
        SerializedWhpxInterruptRegs {
            // SAFETY: This register is a valid u64.
            pending_interruption: unsafe { self.register_values[0].PendingInterruption.AsUINT64 },
            // SAFETY: This register is a valid u64.
            interrupt_state: unsafe { self.register_values[1].InterruptState.AsUINT64 },
            // SAFETY: This register is a valid u64.
            deliverability_notifications: unsafe {
                self.register_values[2].DeliverabilityNotifications.AsUINT64
            },
            // SAFETY: This register is a valid u64.
            internal_activity_state: unsafe { self.register_values[3].InternalActivity.AsUINT64 },
        }
    }

    pub(super) fn from_serializable(serialized_regs: SerializedWhpxInterruptRegs) -> Self {
        let mut whpx_interrupt_regs: WhpxInterruptRegs = Default::default();
        whpx_interrupt_regs.register_values[0]
            .PendingInterruption
            .AsUINT64 = serialized_regs.pending_interruption;
        whpx_interrupt_regs.register_values[1]
            .InterruptState
            .AsUINT64 = serialized_regs.interrupt_state;
        whpx_interrupt_regs.register_values[2]
            .DeliverabilityNotifications
            .AsUINT64 = serialized_regs.deliverability_notifications;
        whpx_interrupt_regs.register_values[3]
            .InternalActivity
            .AsUINT64 = serialized_regs.internal_activity_state;
        whpx_interrupt_regs
    }
}

// list of MSR registers for whpx, and their actual ids
pub(super) const MSR_TSC: u32 = 0x00000010;
pub(super) const MSR_EFER: u32 = 0xc0000080;
pub(super) const MSR_KERNEL_GS_BASE: u32 = 0xc0000102;
pub(super) const MSR_APIC_BASE: u32 = 0x0000001b;
pub(super) const MSR_PAT: u32 = 0x00000277;
pub(super) const MSR_SYSENTER_CS: u32 = 0x00000174;
pub(super) const MSR_SYSENTER_EIP: u32 = 0x00000176;
pub(super) const MSR_SYSENTER_ESP: u32 = 0x00000175;
pub(super) const MSR_STAR: u32 = 0xc0000081;
pub(super) const MSR_LSTAR: u32 = 0xc0000082;
pub(super) const MSR_CSTAR: u32 = 0xc0000083;
pub(super) const MSR_SFMASK: u32 = 0xc0000084;
pub(super) const MSR_MTRR_CAP: u32 = 0x000000fe;
pub(super) const MSR_MTRR_DEF_TYPE: u32 = 0x000002ff;
pub(super) const MSR_MTRR_PHYS_BASE0: u32 = 0x00000200;
pub(super) const MSR_MTRR_PHYS_BASE1: u32 = 0x00000202;
pub(super) const MSR_MTRR_PHYS_BASE2: u32 = 0x00000204;
pub(super) const MSR_MTRR_PHYS_BASE3: u32 = 0x00000206;
pub(super) const MSR_MTRR_PHYS_BASE4: u32 = 0x00000208;
pub(super) const MSR_MTRR_PHYS_BASE5: u32 = 0x0000020a;
pub(super) const MSR_MTRR_PHYS_BASE6: u32 = 0x0000020c;
pub(super) const MSR_MTRR_PHYS_BASE7: u32 = 0x0000020e;
pub(super) const MSR_MTRR_PHYS_BASE8: u32 = 0x00000210;
pub(super) const MSR_MTRR_PHYS_BASE9: u32 = 0x00000212;
pub(super) const MSR_MTRR_PHYS_BASEA: u32 = 0x00000214;
pub(super) const MSR_MTRR_PHYS_BASEB: u32 = 0x00000216;
pub(super) const MSR_MTRR_PHYS_BASEC: u32 = 0x00000218;
pub(super) const MSR_MTRR_PHYS_BASED: u32 = 0x0000021a;
pub(super) const MSR_MTRR_PHYS_BASEE: u32 = 0x0000021c;
pub(super) const MSR_MTRR_PHYS_BASEF: u32 = 0x0000021e;
pub(super) const MSR_MTRR_PHYS_MASK0: u32 = 0x00000201;
pub(super) const MSR_MTRR_PHYS_MASK1: u32 = 0x00000203;
pub(super) const MSR_MTRR_PHYS_MASK2: u32 = 0x00000205;
pub(super) const MSR_MTRR_PHYS_MASK3: u32 = 0x00000207;
pub(super) const MSR_MTRR_PHYS_MASK4: u32 = 0x00000209;
pub(super) const MSR_MTRR_PHYS_MASK5: u32 = 0x0000020b;
pub(super) const MSR_MTRR_PHYS_MASK6: u32 = 0x0000020d;
pub(super) const MSR_MTRR_PHYS_MASK7: u32 = 0x0000020f;
pub(super) const MSR_MTRR_PHYS_MASK8: u32 = 0x00000211;
pub(super) const MSR_MTRR_PHYS_MASK9: u32 = 0x00000213;
pub(super) const MSR_MTRR_PHYS_MASKA: u32 = 0x00000215;
pub(super) const MSR_MTRR_PHYS_MASKB: u32 = 0x00000217;
pub(super) const MSR_MTRR_PHYS_MASKC: u32 = 0x00000219;
pub(super) const MSR_MTRR_PHYS_MASKD: u32 = 0x0000021b;
pub(super) const MSR_MTRR_PHYS_MASKE: u32 = 0x0000021d;
pub(super) const MSR_MTRR_PHYS_MASKF: u32 = 0x0000021f;
pub(super) const MSR_MTRR_FIX64K_00000: u32 = 0x00000250;
pub(super) const MSR_MTRR_FIX16K_80000: u32 = 0x00000258;
pub(super) const MSR_MTRR_FIX16K_A0000: u32 = 0x00000259;
pub(super) const MSR_MTRR_FIX4K_C0000: u32 = 0x00000268;
pub(super) const MSR_MTRR_FIX4K_C8000: u32 = 0x00000269;
pub(super) const MSR_MTRR_FIX4K_D0000: u32 = 0x0000026a;
pub(super) const MSR_MTRR_FIX4K_D8000: u32 = 0x0000026b;
pub(super) const MSR_MTRR_FIX4K_E0000: u32 = 0x0000026c;
pub(super) const MSR_MTRR_FIX4K_E8000: u32 = 0x0000026d;
pub(super) const MSR_MTRR_FIX4K_F0000: u32 = 0x0000026e;
pub(super) const MSR_MTRR_FIX4K_F8000: u32 = 0x0000026f;
pub(super) const MSR_TSC_AUX: u32 = 0xc0000103;
pub(super) const MSR_SPEC_CTRL: u32 = 0x00000048;
pub(super) const MSR_PRED_CMD: u32 = 0x00000049;

// the valid msrs for whpx, converting from the x86 efer id's to the whpx register name value.
// https://docs.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvvirtualprocessordatatypes
#[rustfmt::skip]
pub(super) static VALID_MSRS: Lazy<HashMap<u32, WHV_REGISTER_NAME>> = Lazy::new(|| {
    [
        (MSR_TSC,WHV_REGISTER_NAME_WHvX64RegisterTsc),
        (MSR_EFER,WHV_REGISTER_NAME_WHvX64RegisterEfer),
        (MSR_KERNEL_GS_BASE,WHV_REGISTER_NAME_WHvX64RegisterKernelGsBase),
        (MSR_APIC_BASE,WHV_REGISTER_NAME_WHvX64RegisterApicBase),
        (MSR_PAT,WHV_REGISTER_NAME_WHvX64RegisterPat),
        (MSR_SYSENTER_CS,WHV_REGISTER_NAME_WHvX64RegisterSysenterCs),
        (MSR_SYSENTER_EIP,WHV_REGISTER_NAME_WHvX64RegisterSysenterEip),
        (MSR_SYSENTER_ESP,WHV_REGISTER_NAME_WHvX64RegisterSysenterEsp),
        (MSR_STAR,WHV_REGISTER_NAME_WHvX64RegisterStar),
        (MSR_LSTAR,WHV_REGISTER_NAME_WHvX64RegisterLstar),
        (MSR_CSTAR,WHV_REGISTER_NAME_WHvX64RegisterCstar),
        (MSR_SFMASK,WHV_REGISTER_NAME_WHvX64RegisterSfmask),
        (MSR_MTRR_CAP,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrCap),
        (MSR_MTRR_DEF_TYPE,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrDefType),
        (MSR_MTRR_PHYS_BASE0,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysBase0),
        (MSR_MTRR_PHYS_BASE1,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysBase1),
        (MSR_MTRR_PHYS_BASE2,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysBase2),
        (MSR_MTRR_PHYS_BASE3,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysBase3),
        (MSR_MTRR_PHYS_BASE4,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysBase4),
        (MSR_MTRR_PHYS_BASE5,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysBase5),
        (MSR_MTRR_PHYS_BASE6,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysBase6),
        (MSR_MTRR_PHYS_BASE7,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysBase7),
        (MSR_MTRR_PHYS_BASE8,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysBase8),
        (MSR_MTRR_PHYS_BASE9,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysBase9),
        (MSR_MTRR_PHYS_BASEA,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysBaseA),
        (MSR_MTRR_PHYS_BASEB,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysBaseB),
        (MSR_MTRR_PHYS_BASEC,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysBaseC),
        (MSR_MTRR_PHYS_BASED,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysBaseD),
        (MSR_MTRR_PHYS_BASEE,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysBaseE),
        (MSR_MTRR_PHYS_BASEF,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysBaseF),
        (MSR_MTRR_PHYS_MASK0,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysMask0),
        (MSR_MTRR_PHYS_MASK1,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysMask1),
        (MSR_MTRR_PHYS_MASK2,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysMask2),
        (MSR_MTRR_PHYS_MASK3,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysMask3),
        (MSR_MTRR_PHYS_MASK4,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysMask4),
        (MSR_MTRR_PHYS_MASK5,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysMask5),
        (MSR_MTRR_PHYS_MASK6,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysMask6),
        (MSR_MTRR_PHYS_MASK7,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysMask7),
        (MSR_MTRR_PHYS_MASK8,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysMask8),
        (MSR_MTRR_PHYS_MASK9,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysMask9),
        (MSR_MTRR_PHYS_MASKA,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysMaskA),
        (MSR_MTRR_PHYS_MASKB,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysMaskB),
        (MSR_MTRR_PHYS_MASKC,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysMaskC),
        (MSR_MTRR_PHYS_MASKD,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysMaskD),
        (MSR_MTRR_PHYS_MASKE,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysMaskE),
        (MSR_MTRR_PHYS_MASKF,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrPhysMaskF),
        (MSR_MTRR_FIX64K_00000,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrFix64k00000),
        (MSR_MTRR_FIX16K_80000,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrFix16k80000),
        (MSR_MTRR_FIX16K_A0000,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrFix16kA0000),
        (MSR_MTRR_FIX4K_C0000,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrFix4kC0000),
        (MSR_MTRR_FIX4K_C8000,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrFix4kC8000),
        (MSR_MTRR_FIX4K_D0000,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrFix4kD0000),
        (MSR_MTRR_FIX4K_D8000,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrFix4kD8000),
        (MSR_MTRR_FIX4K_E0000,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrFix4kE0000),
        (MSR_MTRR_FIX4K_E8000,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrFix4kE8000),
        (MSR_MTRR_FIX4K_F0000,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrFix4kF0000),
        (MSR_MTRR_FIX4K_F8000,WHV_REGISTER_NAME_WHvX64RegisterMsrMtrrFix4kF8000),
        (MSR_TSC_AUX,WHV_REGISTER_NAME_WHvX64RegisterTscAux),
        (MSR_SPEC_CTRL,WHV_REGISTER_NAME_WHvX64RegisterSpecCtrl),
        (MSR_PRED_CMD,WHV_REGISTER_NAME_WHvX64RegisterPredCmd),
    ].into_iter().collect()
});

impl From<&CpuIdEntry> for WHV_X64_CPUID_RESULT {
    fn from(entry: &CpuIdEntry) -> Self {
        WHV_X64_CPUID_RESULT {
            Function: entry.function,
            Eax: entry.cpuid.eax,
            Ebx: entry.cpuid.ebx,
            Ecx: entry.cpuid.ecx,
            Edx: entry.cpuid.edx,
            ..Default::default()
        }
    }
}

/// WHPX's LAPIC setting API just lets you supply an arbitrary buffer and size. WHPX seems to use
/// the full 4K size of the APIC, although we only care about the state of the registers which live
/// in the first 1k.
#[repr(C)]
pub struct WhpxLapicState {
    pub regs: [u32; 1024],
}

impl From<&WhpxLapicState> for LapicState {
    fn from(item: &WhpxLapicState) -> Self {
        let mut state = LapicState { regs: [0; 64] };
        for i in 0..64 {
            state.regs[i] = item.regs[i * 4];
        }
        state
    }
}

impl From<&LapicState> for WhpxLapicState {
    fn from(item: &LapicState) -> Self {
        let mut state = WhpxLapicState { regs: [0; 1024] };
        for i in 0..64 {
            state.regs[i * 4] = item.regs[i];
        }
        state
    }
}

// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! FFI bindings to Apple's Hypervisor.framework for aarch64.
//!
//! These are minimal, hand-curated bindings for the HVF APIs we need.
//! Reference: Apple's Hypervisor framework documentation.

#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(dead_code)]

use std::ffi::c_void;

// Basic types
pub type hv_return_t = i32;
pub type hv_vcpu_t = u64;
pub type hv_ipa_t = u64;
pub type hv_memory_flags_t = u64;
pub type hv_reg_t = u32;
pub type hv_sys_reg_t = u16;
pub type hv_simd_fp_reg_t = u32;
pub type hv_exit_reason_t = u32;
pub type hv_interrupt_type_t = u32;
pub type hv_gic_intid_t = u16;

// VM config opaque type
#[repr(C)]
pub struct hv_vm_config_s {
    _opaque: [u8; 0],
}
pub type hv_vm_config_t = *mut hv_vm_config_s;

// GIC config opaque type
#[repr(C)]
pub struct hv_gic_config_s {
    _opaque: [u8; 0],
}
pub type hv_gic_config_t = *mut hv_gic_config_s;

// Return codes
pub const HV_SUCCESS: hv_return_t = 0;
pub const HV_ERROR: hv_return_t = 0xfae94001_u32 as i32;
pub const HV_BUSY: hv_return_t = 0xfae94002_u32 as i32;
pub const HV_BAD_ARGUMENT: hv_return_t = 0xfae94003_u32 as i32;
pub const HV_NO_RESOURCES: hv_return_t = 0xfae94005_u32 as i32;
pub const HV_NO_DEVICE: hv_return_t = 0xfae94006_u32 as i32;
pub const HV_DENIED: hv_return_t = 0xfae94007_u32 as i32;
pub const HV_UNSUPPORTED: hv_return_t = 0xfae9400f_u32 as i32;

// Memory flags
pub const HV_MEMORY_READ: hv_memory_flags_t = 1 << 0;
pub const HV_MEMORY_WRITE: hv_memory_flags_t = 1 << 1;
pub const HV_MEMORY_EXEC: hv_memory_flags_t = 1 << 2;

// Exit reasons
pub const HV_EXIT_REASON_CANCELED: hv_exit_reason_t = 0;
pub const HV_EXIT_REASON_EXCEPTION: hv_exit_reason_t = 1;
pub const HV_EXIT_REASON_VTIMER_ACTIVATED: hv_exit_reason_t = 2;
pub const HV_EXIT_REASON_UNKNOWN: hv_exit_reason_t = 3;

// General purpose registers
pub const HV_REG_X0: hv_reg_t = 0;
pub const HV_REG_X1: hv_reg_t = 1;
pub const HV_REG_X2: hv_reg_t = 2;
pub const HV_REG_X3: hv_reg_t = 3;
pub const HV_REG_X4: hv_reg_t = 4;
pub const HV_REG_X5: hv_reg_t = 5;
pub const HV_REG_X6: hv_reg_t = 6;
pub const HV_REG_X7: hv_reg_t = 7;
pub const HV_REG_X8: hv_reg_t = 8;
pub const HV_REG_X9: hv_reg_t = 9;
pub const HV_REG_X10: hv_reg_t = 10;
pub const HV_REG_X11: hv_reg_t = 11;
pub const HV_REG_X12: hv_reg_t = 12;
pub const HV_REG_X13: hv_reg_t = 13;
pub const HV_REG_X14: hv_reg_t = 14;
pub const HV_REG_X15: hv_reg_t = 15;
pub const HV_REG_X16: hv_reg_t = 16;
pub const HV_REG_X17: hv_reg_t = 17;
pub const HV_REG_X18: hv_reg_t = 18;
pub const HV_REG_X19: hv_reg_t = 19;
pub const HV_REG_X20: hv_reg_t = 20;
pub const HV_REG_X21: hv_reg_t = 21;
pub const HV_REG_X22: hv_reg_t = 22;
pub const HV_REG_X23: hv_reg_t = 23;
pub const HV_REG_X24: hv_reg_t = 24;
pub const HV_REG_X25: hv_reg_t = 25;
pub const HV_REG_X26: hv_reg_t = 26;
pub const HV_REG_X27: hv_reg_t = 27;
pub const HV_REG_X28: hv_reg_t = 28;
pub const HV_REG_X29: hv_reg_t = 29;
pub const HV_REG_FP: hv_reg_t = 29;
pub const HV_REG_X30: hv_reg_t = 30;
pub const HV_REG_LR: hv_reg_t = 30;
pub const HV_REG_PC: hv_reg_t = 31;
pub const HV_REG_FPCR: hv_reg_t = 32;
pub const HV_REG_FPSR: hv_reg_t = 33;
pub const HV_REG_CPSR: hv_reg_t = 34;

// System registers (encoded as per ARM spec)
pub const HV_SYS_REG_SP_EL0: hv_sys_reg_t = 0xC208;
pub const HV_SYS_REG_SP_EL1: hv_sys_reg_t = 0xE208;
pub const HV_SYS_REG_ELR_EL1: hv_sys_reg_t = 0xE201;
pub const HV_SYS_REG_SPSR_EL1: hv_sys_reg_t = 0xE200;
pub const HV_SYS_REG_SCTLR_EL1: hv_sys_reg_t = 0xC080;
pub const HV_SYS_REG_CPACR_EL1: hv_sys_reg_t = 0xC082;
pub const HV_SYS_REG_TTBR0_EL1: hv_sys_reg_t = 0xC100;
pub const HV_SYS_REG_TTBR1_EL1: hv_sys_reg_t = 0xC101;
pub const HV_SYS_REG_TCR_EL1: hv_sys_reg_t = 0xC102;
pub const HV_SYS_REG_ESR_EL1: hv_sys_reg_t = 0xE290;
pub const HV_SYS_REG_FAR_EL1: hv_sys_reg_t = 0xE300;
pub const HV_SYS_REG_MAIR_EL1: hv_sys_reg_t = 0xC510;
pub const HV_SYS_REG_VBAR_EL1: hv_sys_reg_t = 0xE600;
pub const HV_SYS_REG_TPIDR_EL0: hv_sys_reg_t = 0xDE82;
pub const HV_SYS_REG_TPIDR_EL1: hv_sys_reg_t = 0xE684;
pub const HV_SYS_REG_TPIDRRO_EL0: hv_sys_reg_t = 0xDE83;
pub const HV_SYS_REG_CNTV_CTL_EL0: hv_sys_reg_t = 0xDF19;
pub const HV_SYS_REG_CNTV_CVAL_EL0: hv_sys_reg_t = 0xDF1A;
pub const HV_SYS_REG_CNTVCT_EL0: hv_sys_reg_t = 0xDF02;
pub const HV_SYS_REG_MIDR_EL1: hv_sys_reg_t = 0xC000;
pub const HV_SYS_REG_MPIDR_EL1: hv_sys_reg_t = 0xC005;

// Interrupt types
pub const HV_INTERRUPT_TYPE_IRQ: hv_interrupt_type_t = 0;
pub const HV_INTERRUPT_TYPE_FIQ: hv_interrupt_type_t = 1;

// SIMD/FP registers
pub const HV_SIMD_FP_REG_Q0: hv_simd_fp_reg_t = 0;
pub const HV_SIMD_FP_REG_Q31: hv_simd_fp_reg_t = 31;

// Exception syndrome values (EC field)
pub const EC_UNKNOWN: u32 = 0x00;
pub const EC_WFX_TRAP: u32 = 0x01;
pub const EC_AA64_SMC: u32 = 0x17;
pub const EC_AA64_HVC: u32 = 0x16;
pub const EC_SYSTEMREGISTERTRAP: u32 = 0x18;
pub const EC_INSTR_ABORT_LOWER_EL: u32 = 0x20;
pub const EC_INSTR_ABORT_SAME_EL: u32 = 0x21;
pub const EC_DATAABORT_LOWER_EL: u32 = 0x24;
pub const EC_DATAABORT_SAME_EL: u32 = 0x25;

// VCPU exit structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct hv_vcpu_exit_exception_t {
    pub syndrome: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct hv_vcpu_exit_t {
    pub reason: hv_exit_reason_t,
    pub exception: hv_vcpu_exit_exception_t,
}

// SIMD value type (128-bit)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct hv_simd_fp_uchar16_t {
    pub bytes: [u8; 16],
}

#[link(name = "Hypervisor", kind = "framework")]
extern "C" {
    // VM config
    pub fn hv_vm_config_create() -> hv_vm_config_t;

    // VM lifecycle
    pub fn hv_vm_create(config: hv_vm_config_t) -> hv_return_t;
    pub fn hv_vm_destroy() -> hv_return_t;
    pub fn hv_vm_get_max_vcpu_count(max_vcpu_count: *mut u32) -> hv_return_t;

    // Memory mapping
    pub fn hv_vm_map(
        addr: *mut c_void,
        ipa: hv_ipa_t,
        size: usize,
        flags: hv_memory_flags_t,
    ) -> hv_return_t;
    pub fn hv_vm_unmap(ipa: hv_ipa_t, size: usize) -> hv_return_t;
    pub fn hv_vm_protect(ipa: hv_ipa_t, size: usize, flags: hv_memory_flags_t) -> hv_return_t;

    // VCPU lifecycle
    pub fn hv_vcpu_create(
        vcpu: *mut hv_vcpu_t,
        exit: *mut *mut hv_vcpu_exit_t,
        config: *mut c_void,
    ) -> hv_return_t;
    pub fn hv_vcpu_destroy(vcpu: hv_vcpu_t) -> hv_return_t;

    // VCPU execution
    pub fn hv_vcpu_run(vcpu: hv_vcpu_t) -> hv_return_t;
    pub fn hv_vcpus_exit(vcpus: *mut hv_vcpu_t, vcpu_count: u32) -> hv_return_t;

    // VCPU registers
    pub fn hv_vcpu_get_reg(vcpu: hv_vcpu_t, reg: hv_reg_t, value: *mut u64) -> hv_return_t;
    pub fn hv_vcpu_set_reg(vcpu: hv_vcpu_t, reg: hv_reg_t, value: u64) -> hv_return_t;
    pub fn hv_vcpu_get_sys_reg(
        vcpu: hv_vcpu_t,
        reg: hv_sys_reg_t,
        value: *mut u64,
    ) -> hv_return_t;
    pub fn hv_vcpu_set_sys_reg(vcpu: hv_vcpu_t, reg: hv_sys_reg_t, value: u64) -> hv_return_t;

    // SIMD/FP registers
    pub fn hv_vcpu_get_simd_fp_reg(
        vcpu: hv_vcpu_t,
        reg: hv_simd_fp_reg_t,
        value: *mut hv_simd_fp_uchar16_t,
    ) -> hv_return_t;
    pub fn hv_vcpu_set_simd_fp_reg(
        vcpu: hv_vcpu_t,
        reg: hv_simd_fp_reg_t,
        value: hv_simd_fp_uchar16_t,
    ) -> hv_return_t;

    // Interrupt injection
    pub fn hv_vcpu_get_pending_interrupt(
        vcpu: hv_vcpu_t,
        interrupt_type: hv_interrupt_type_t,
        pending: *mut bool,
    ) -> hv_return_t;
    pub fn hv_vcpu_set_pending_interrupt(
        vcpu: hv_vcpu_t,
        interrupt_type: hv_interrupt_type_t,
        pending: bool,
    ) -> hv_return_t;

    // Virtual timer
    pub fn hv_vcpu_get_vtimer_mask(vcpu: hv_vcpu_t, vtimer_is_masked: *mut bool) -> hv_return_t;
    pub fn hv_vcpu_set_vtimer_mask(vcpu: hv_vcpu_t, vtimer_is_masked: bool) -> hv_return_t;
    pub fn hv_vcpu_get_vtimer_offset(vcpu: hv_vcpu_t, vtimer_offset: *mut u64) -> hv_return_t;
    pub fn hv_vcpu_set_vtimer_offset(vcpu: hv_vcpu_t, vtimer_offset: u64) -> hv_return_t;

    // Debug
    pub fn hv_vcpu_get_trap_debug_exceptions(vcpu: hv_vcpu_t, value: *mut bool) -> hv_return_t;
    pub fn hv_vcpu_set_trap_debug_exceptions(vcpu: hv_vcpu_t, value: bool) -> hv_return_t;
    pub fn hv_vcpu_get_trap_debug_reg_accesses(vcpu: hv_vcpu_t, value: *mut bool) -> hv_return_t;
    pub fn hv_vcpu_set_trap_debug_reg_accesses(vcpu: hv_vcpu_t, value: bool) -> hv_return_t;

    // Execution time
    pub fn hv_vcpu_get_exec_time(vcpu: hv_vcpu_t, time: *mut u64) -> hv_return_t;

    // GIC (Generic Interrupt Controller) - available on macOS 15+
    pub fn hv_gic_create(gic_config: hv_gic_config_t) -> hv_return_t;
    pub fn hv_gic_reset() -> hv_return_t;
    pub fn hv_gic_config_create() -> hv_gic_config_t;
    pub fn hv_gic_config_set_distributor_base(
        gic_config: hv_gic_config_t,
        distributor_base_address: hv_ipa_t,
    ) -> hv_return_t;
    pub fn hv_gic_config_set_redistributor_base(
        gic_config: hv_gic_config_t,
        redistributor_base_address: hv_ipa_t,
    ) -> hv_return_t;
    pub fn hv_gic_get_redistributor_base(
        vcpu: hv_vcpu_t,
        redistributor_base: *mut hv_ipa_t,
    ) -> hv_return_t;
    pub fn hv_gic_set_spi(intid: u32, level: bool) -> hv_return_t;
    pub fn hv_gic_get_redistributor_region_size(
        redistributor_region_size: *mut usize,
    ) -> hv_return_t;
    pub fn hv_gic_get_distributor_size(distributor_size: *mut usize) -> hv_return_t;
    pub fn hv_gic_get_distributor_base_alignment(
        distributor_base_alignment: *mut usize,
    ) -> hv_return_t;
    pub fn hv_gic_get_redistributor_base_alignment(
        redistributor_base_alignment: *mut usize,
    ) -> hv_return_t;
}

/// Helper to check HVF return value and convert to Result
pub fn check_ret(ret: hv_return_t) -> Result<(), HvfError> {
    if ret == HV_SUCCESS {
        Ok(())
    } else {
        Err(HvfError::from_return(ret))
    }
}

/// Error type for HVF operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HvfError {
    Error,
    Busy,
    BadArgument,
    NoResources,
    NoDevice,
    Denied,
    Unsupported,
    Unknown(i32),
}

impl HvfError {
    pub fn from_return(ret: hv_return_t) -> Self {
        match ret {
            HV_ERROR => HvfError::Error,
            HV_BUSY => HvfError::Busy,
            HV_BAD_ARGUMENT => HvfError::BadArgument,
            HV_NO_RESOURCES => HvfError::NoResources,
            HV_NO_DEVICE => HvfError::NoDevice,
            HV_DENIED => HvfError::Denied,
            HV_UNSUPPORTED => HvfError::Unsupported,
            other => HvfError::Unknown(other),
        }
    }
}

impl std::fmt::Display for HvfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HvfError::Error => write!(f, "HV_ERROR"),
            HvfError::Busy => write!(f, "HV_BUSY"),
            HvfError::BadArgument => write!(f, "HV_BAD_ARGUMENT"),
            HvfError::NoResources => write!(f, "HV_NO_RESOURCES"),
            HvfError::NoDevice => write!(f, "HV_NO_DEVICE"),
            HvfError::Denied => write!(f, "HV_DENIED"),
            HvfError::Unsupported => write!(f, "HV_UNSUPPORTED"),
            HvfError::Unknown(code) => write!(f, "HV_UNKNOWN(0x{:08x})", code),
        }
    }
}

impl std::error::Error for HvfError {}

/// Extract the Exception Class (EC) from a syndrome value
#[inline]
pub fn syndrome_ec(syndrome: u64) -> u32 {
    ((syndrome >> 26) & 0x3f) as u32
}

/// Extract the Instruction Specific Syndrome (ISS) from a syndrome value
#[inline]
pub fn syndrome_iss(syndrome: u64) -> u32 {
    (syndrome & 0x1ffffff) as u32
}

/// Check if a data abort is a write operation
#[inline]
pub fn data_abort_is_write(iss: u32) -> bool {
    (iss & (1 << 6)) != 0
}

/// Get the access size from a data abort ISS (SAS field)
#[inline]
pub fn data_abort_access_size(iss: u32) -> usize {
    1 << ((iss >> 22) & 0x3)
}

/// Check if ISV (Instruction Syndrome Valid) bit is set
#[inline]
pub fn data_abort_isv(iss: u32) -> bool {
    (iss & (1 << 24)) != 0
}

/// Get the register number from a data abort ISS (SRT field)
#[inline]
pub fn data_abort_srt(iss: u32) -> u32 {
    (iss >> 16) & 0x1f
}

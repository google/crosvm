// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::anyhow;
use base::Result;
use downcast_rs::impl_downcast;
use serde::Deserialize;
use serde::Serialize;
use vm_memory::GuestAddress;

use crate::Hypervisor;
use crate::IrqRoute;
use crate::IrqSource;
use crate::IrqSourceChip;
use crate::Vcpu;
use crate::Vm;

/// A wrapper for using a VM on riscv64 and getting/setting its state.
pub trait VmRiscv64: Vm {
    /// Gets the `Hypervisor` that created this VM.
    fn get_hypervisor(&self) -> &dyn Hypervisor;

    /// Create a Vcpu with the specified Vcpu ID.
    fn create_vcpu(&self, id: usize) -> Result<Box<dyn VcpuRiscv64>>;
}

/// A wrapper around creating and using a VCPU on riscv64.
pub trait VcpuRiscv64: Vcpu {
    /// Sets the value of a register on this VCPU.
    fn set_one_reg(&self, reg_id: VcpuRegister, data: u64) -> Result<()>;

    /// Gets the value of a register on this VCPU.
    fn get_one_reg(&self, reg_id: VcpuRegister) -> Result<u64>;

    /// Snapshot VCPU
    fn snapshot(&self) -> anyhow::Result<VcpuSnapshot> {
        Err(anyhow!("not yet implemented"))
    }

    /// Restore VCPU
    fn restore(&self, _snapshot: &VcpuSnapshot) -> anyhow::Result<()> {
        Err(anyhow!("not yet implemented"))
    }
}

/// Riscv64 specific vCPU snapshot.
///
/// Not implemented yet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcpuSnapshot {
    pub vcpu_id: usize,
}

impl_downcast!(VcpuRiscv64);

/// Initial state for Riscv64 VCPUs.
#[derive(Clone)]
pub struct VcpuInitRiscv64 {
    /// The address of the FDT
    pub fdt_address: GuestAddress,
}

impl VcpuInitRiscv64 {
    pub fn new(fdt_address: GuestAddress) -> Self {
        Self { fdt_address }
    }
}

/// Hold the CPU feature configurations that are needed to setup a vCPU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpuConfigRiscv64 {
    /// The address of the FDT
    pub fdt_address: GuestAddress,
}

impl CpuConfigRiscv64 {
    pub fn new(fdt_address: GuestAddress) -> Self {
        Self { fdt_address }
    }
}

/// Config registers exposed by kvm.
#[repr(u64)]
#[derive(Copy, Clone)]
pub enum ConfigRegister {
    Isa = 0,
}

/// Timer registers exposed by kvm.
#[repr(u64)]
#[derive(Copy, Clone)]
pub enum TimerRegister {
    TimebaseFrequency = 0,
}

/// Core registers exposed by kvm.
#[repr(u64)]
#[derive(Copy, Clone)]
pub enum CoreRegister {
    Pc = 0x00,   // Program counter
    Ra = 0x01,   // Return address
    Sp = 0x02,   // Stack pointer
    Gp = 0x03,   // Global pointer
    Tp = 0x04,   // Task pointer
    T0 = 0x05,   // Caller saved register 0
    T1 = 0x06,   // Caller saved register 1
    T2 = 0x07,   // Caller saved register 2
    S0 = 0x08,   // Callee saved register 0
    S1 = 0x09,   // Callee saved register 1
    A0 = 0x0a,   // Function argument (or return value) 0
    A1 = 0x0b,   // Function argument (or return value) 1
    A2 = 0x0c,   // Function argument 2
    A3 = 0x0d,   // Function argument 3
    A4 = 0x0e,   // Function argument 4
    A5 = 0x0f,   // Function argument 5
    A6 = 0x10,   // Function argument 6
    A7 = 0x11,   // Function argument 7
    S2 = 0x12,   // Callee saved register 2
    S3 = 0x13,   // Callee saved register 3
    S4 = 0x14,   // Callee saved register 4
    S5 = 0x15,   // Callee saved register 5
    S6 = 0x16,   // Callee saved register 6
    S7 = 0x17,   // Callee saved register 7
    S8 = 0x18,   // Callee saved register 8
    S9 = 0x19,   // Callee saved register 9
    S10 = 0x1a,  // Callee saved register 10
    S11 = 0x1b,  // Callee saved register 11
    T3 = 0x1c,   // Caller saved register 3
    T4 = 0x1d,   // Caller saved register 4
    T5 = 0x1e,   // Caller saved register 5
    T6 = 0x1f,   // Caller saved register 6
    Mode = 0x20, // Privilege mode (1 = S-mode or 0 = U-mode)
}

/// Registers exposed through `KVM_[GET|SET]_ONE_REG` API.
#[derive(Copy, Clone)]
pub enum VcpuRegister {
    Config(ConfigRegister),
    Core(CoreRegister),
    Timer(TimerRegister),
}

// Convenience constructors for IrqRoutes
impl IrqRoute {
    pub fn aia_irq_route(irq_num: u32) -> IrqRoute {
        IrqRoute {
            gsi: irq_num,
            source: IrqSource::Irqchip {
                chip: IrqSourceChip::Aia,
                pin: irq_num,
            },
        }
    }
}

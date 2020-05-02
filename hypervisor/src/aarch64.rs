// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::{Vcpu, Vm};
use sys_util::Result;

/// A wrapper for using a VM on aarch64 and getting/setting its state.
pub trait VmAArch64: Vm {
    type Vcpu: VcpuArm;

    /// Create a Vcpu with the specified Vcpu ID.
    fn create_vcpu(&self, id: usize) -> Result<Self::Vcpu>;
}

/// A wrapper around creating and using a VCPU on aarch64.
pub trait VcpuAArch64: Vcpu {
    /// Sets the value of register on this VCPU.
    ///
    /// # Arguments
    ///
    /// * `reg_id` - Register ID, specified in the KVM API documentation for KVM_SET_ONE_REG
    fn set_one_reg(&self, reg_id: u64, data: u64) -> Result<()>;
}

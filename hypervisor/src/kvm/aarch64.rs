// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libc::ENXIO;

use sys_util::{Error, Result};

use super::{KvmVcpu, KvmVm};
use crate::{ClockState, VcpuAArch64, VmAArch64};

impl KvmVm {
    /// Arch-specific implementation of `Vm::get_pvclock`.  Always returns an error on AArch64.
    pub fn get_pvclock_arch(&self) -> Result<ClockState> {
        Err(Error::new(ENXIO))
    }

    /// Arch-specific implementation of `Vm::set_pvclock`.  Always returns an error on AArch64.
    pub fn set_pvclock_arch(&self, _state: &ClockState) -> Result<()> {
        Err(Error::new(ENXIO))
    }
}

impl VmAArch64 for KvmVm {
    type Vcpu = KvmVcpu;

    fn create_vcpu(&self, id: usize) -> Result<Self::Vcpu> {
        self.create_kvm_vcpu(id)
    }
}

impl VcpuAArch64 for KvmVcpu {
    fn set_one_reg(&self, _reg_id: u64, _data: u64) -> Result<()> {
        Ok(())
    }
}

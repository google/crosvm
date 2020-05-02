// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use sys_util::Result;

use super::{Kvm, KvmVcpu, KvmVm};
use crate::{CpuId, HypervisorX86_64, Regs, VcpuX86_64, VmX86_64};

impl HypervisorX86_64 for Kvm {
    fn get_supported_cpuid(&self) -> Result<CpuId> {
        unimplemented!("get_supported_cpuid for Kvm is not yet implemented");
    }

    fn get_emulated_cpuid(&self) -> Result<CpuId> {
        unimplemented!("get_emulated_cpuid for Kvm is not yet implemented");
    }
}

impl VmX86_64 for KvmVm {
    type Vcpu = KvmVcpu;

    fn create_vcpu(&self, id: usize) -> Result<Self::Vcpu> {
        self.create_kvm_vcpu(id)
    }
}

impl VcpuX86_64 for KvmVcpu {
    fn get_regs(&self) -> Result<Regs> {
        Ok(Regs {})
    }
}

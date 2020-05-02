// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[path = "types.rs"]
mod types;

#[allow(unused_imports)]
use hypervisor::*;
pub use types::{HyperVm, RunnableLinuxVm};

// Inline cfg won't be needed in real code, but integration tests don't have conditional includes.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn configure_vcpu<T, U, V>(
    _hypervm: &HyperVm<T, U, V>,
    _linux: &RunnableLinuxVm,
    vcpu: &impl VcpuX86_64,
) where
    T: HypervisorX86_64,
    U: VmX86_64,
    V: VcpuX86_64,
{
    vcpu.get_regs().unwrap();
}

// Inline cfg won't be needed in real code, but integration tests don't have conditional includes.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn configure_vm<T, U, V>(hypervm: &HyperVm<T, U, V>) -> RunnableLinuxVm
where
    T: HypervisorX86_64,
    U: VmX86_64,
    V: VcpuX86_64,
{
    let linux = RunnableLinuxVm {};
    for vcpu in hypervm.vcpus.iter() {
        configure_vcpu(&hypervm, &linux, vcpu);
    }
    linux
}

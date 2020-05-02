// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[path = "types.rs"]
mod types;

#[allow(unused_imports)]
use hypervisor::*;
pub use types::{HyperVm, RunnableLinuxVm};

// Inline cfg won't be needed in real code, but integration tests don't have conditional includes.
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub fn configure_vm<T, U, V>(_hypervm: &HyperVm<T, U, V>) -> RunnableLinuxVm
where
    T: Hypervisor,
    U: VmAArch64,
    V: VcpuAArch64,
{
    RunnableLinuxVm {}
}

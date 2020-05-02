// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use hypervisor::*;

pub struct HyperVm<HyperT, VmT, VcpuT>
where
    HyperT: Hypervisor,
    VmT: Vm,
    VcpuT: Vcpu,
{
    pub hypervisor: HyperT,
    pub vm: VmT,
    pub vcpus: Vec<VcpuT>,
}

pub struct RunnableLinuxVm {}

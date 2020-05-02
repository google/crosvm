// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO: Delete these tests soon, once we start getting real implementations in place.

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
mod test_concrete_aarch64;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod test_concrete_x86_64;

use sys_util::GuestMemory;

use hypervisor::*;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use test_concrete_aarch64::*;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use test_concrete_x86_64::*;

fn run_vcpu<T, U, V>(_hypervm: &HyperVm<T, U, V>, _linux: &RunnableLinuxVm, vcpu: impl Vcpu)
where
    T: Hypervisor,
    U: Vm,
    V: Vcpu,
{
    let vcpu = vcpu.to_runnable().unwrap();
    vcpu.run().unwrap();
    vcpu.request_interrupt_window().unwrap();
}

#[test]
fn test_concrete_types() {
    let cfg_use_kvm = true;
    if cfg_use_kvm {
        let hypervisor = kvm::Kvm::new().unwrap();
        let mem = GuestMemory::new(&[]).unwrap();
        let vm = kvm::KvmVm::new(&hypervisor, mem).unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut vcpus = vec![vcpu];
        let mut hypervm = HyperVm {
            hypervisor,
            vm,
            vcpus,
        };
        let linux = configure_vm(&hypervm);
        vcpus = hypervm.vcpus.split_off(0);
        for vcpu in vcpus.into_iter() {
            run_vcpu(&hypervm, &linux, vcpu);
        }
    }
}

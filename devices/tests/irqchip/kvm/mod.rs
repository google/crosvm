// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(any(target_os = "android", target_os = "linux"))]

mod x86_64;

use devices::irqchip::IrqChip;
use devices::irqchip::KvmKernelIrqChip;
use hypervisor::kvm::Kvm;
use hypervisor::kvm::KvmVm;
use hypervisor::MPState;
use hypervisor::Vm;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use hypervisor::VmAArch64;
#[cfg(target_arch = "riscv64")]
use hypervisor::VmRiscv64;
#[cfg(target_arch = "x86_64")]
use hypervisor::VmX86_64;
use vm_memory::GuestMemory;

#[test]
fn create_kvm_kernel_irqchip() {
    let kvm = Kvm::new().expect("failed to instantiate Kvm");
    let mem = GuestMemory::new(&[]).unwrap();
    let vm = KvmVm::new(&kvm, mem, Default::default()).expect("failed to instantiate vm");

    let mut chip = KvmKernelIrqChip::new(vm.try_clone().expect("failed to clone vm"), 1)
        .expect("failed to instantiate KvmKernelIrqChip");

    let vcpu = vm.create_vcpu(0).expect("failed to instantiate vcpu");
    chip.add_vcpu(0, vcpu.as_vcpu())
        .expect("failed to add vcpu");
}

#[test]
fn mp_state() {
    let kvm = Kvm::new().expect("failed to instantiate Kvm");
    let mem = GuestMemory::new(&[]).unwrap();
    let vm = KvmVm::new(&kvm, mem, Default::default()).expect("failed to instantiate vm");

    let mut chip = KvmKernelIrqChip::new(vm.try_clone().expect("failed to clone vm"), 1)
        .expect("failed to instantiate KvmKernelIrqChip");

    let vcpu = vm.create_vcpu(0).expect("failed to instantiate vcpu");
    chip.add_vcpu(0, vcpu.as_vcpu())
        .expect("failed to add vcpu");

    let state = chip.get_mp_state(0).expect("failed to get mp state");
    assert_eq!(state, MPState::Runnable);

    let new_mpstate = if cfg!(any(target_arch = "arm", target_arch = "aarch64")) {
        MPState::Stopped
    } else if cfg!(target_arch = "x86_64") {
        MPState::Halted
    } else {
        unimplemented!();
    };

    chip.set_mp_state(0, &new_mpstate)
        .expect("failed to set mp state");

    let state = chip.get_mp_state(0).expect("failed to get mp state");
    assert_eq!(state, new_mpstate);
}

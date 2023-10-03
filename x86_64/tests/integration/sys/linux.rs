// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(b/210705746): See if we can bring in the changes compiled out from go/playcl/50499
use crate::simple_vm_test;

#[test]
fn simple_kvm_test() {
    use devices::KvmKernelIrqChip;
    use hypervisor::kvm::*;
    simple_vm_test::<_, _, KvmVcpu, _, _, _>(
        |guest_mem| {
            let kvm = Kvm::new().expect("failed to create kvm");
            let vm =
                KvmVm::new(&kvm, guest_mem, Default::default()).expect("failed to create kvm vm");
            (kvm, vm)
        },
        |vm, vcpu_count, _| {
            KvmKernelIrqChip::new(vm, vcpu_count).expect("failed to create KvmKernelIrqChip")
        },
    );
}

#[test]
fn simple_kvm_kernel_irqchip_test() {
    use devices::KvmKernelIrqChip;
    use hypervisor::kvm::*;
    simple_vm_test::<_, _, KvmVcpu, _, _, _>(
        |guest_mem| {
            let kvm = Kvm::new().expect("failed to create kvm");
            let vm =
                KvmVm::new(&kvm, guest_mem, Default::default()).expect("failed to create kvm vm");
            (kvm, vm)
        },
        |vm, vcpu_count, _| {
            KvmKernelIrqChip::new(vm, vcpu_count).expect("failed to create KvmKernelIrqChip")
        },
    );
}

#[test]
fn simple_kvm_split_irqchip_test() {
    use devices::KvmSplitIrqChip;
    use hypervisor::kvm::*;
    simple_vm_test::<_, _, KvmVcpu, _, _, _>(
        |guest_mem| {
            let kvm = Kvm::new().expect("failed to create kvm");
            let vm =
                KvmVm::new(&kvm, guest_mem, Default::default()).expect("failed to create kvm vm");
            (kvm, vm)
        },
        |vm, vcpu_count, device_tube| {
            KvmSplitIrqChip::new(vm, vcpu_count, device_tube, None)
                .expect("failed to create KvmSplitIrqChip")
        },
    );
}

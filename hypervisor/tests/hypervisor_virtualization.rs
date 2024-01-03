// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(target_arch = "x86_64")]
#![cfg(any(feature = "whpx", feature = "gvm", feature = "haxm", unix))]

use hypervisor::*;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

#[test]
#[cfg(any(target_os = "android", target_os = "linux"))]
fn test_kvm_minimal_virtualization() {
    use hypervisor::kvm::*;
    test_minimal_virtualization(|guest_mem| {
        let kvm = Kvm::new().expect("failed to create kvm");
        let vm = KvmVm::new(&kvm, guest_mem, Default::default()).expect("failed to create vm");
        (kvm, vm)
    });
}

#[test]
#[cfg(all(windows, feature = "haxm"))]
fn test_haxm_minimal_virtualization() {
    use hypervisor::haxm::*;
    test_minimal_virtualization(|guest_mem| {
        let haxm = Haxm::new().expect("failed to create haxm");
        let vm = HaxmVm::new(&haxm, guest_mem).expect("failed to create vm");
        (haxm, vm)
    });
}

#[test]
#[cfg(feature = "gvm")]
fn test_gvm_minimal_virtualization() {
    use hypervisor::gvm::*;
    test_minimal_virtualization(|guest_mem| {
        let gvm = Gvm::new().expect("failed to create gvm");
        let vm = GvmVm::new(&gvm, guest_mem).expect("failed to create vm");
        (gvm, vm)
    });
}

#[test]
#[cfg(all(windows, feature = "whpx"))]
fn test_whpx_minimal_virtualization() {
    use hypervisor::whpx::*;
    test_minimal_virtualization(|guest_mem| {
        let whpx = Whpx::new().expect("failed to create whpx");
        let vm = WhpxVm::new(&whpx, 1, guest_mem, CpuId::new(0), false, None)
            .expect("failed to create vm");
        (whpx, vm)
    });
}

// This runs a minimal program under virtualization.
// It should require only the ability to execute instructions under virtualization, physical
// memory, the ability to get and set some guest VM registers, and intercepting HLT.
fn test_minimal_virtualization<CreateVm, HypervisorT, VmT>(create_vm: CreateVm)
where
    CreateVm: FnOnce(GuestMemory) -> (HypervisorT, VmT),
    HypervisorT: Hypervisor,
    VmT: VmX86_64,
{
    /*
    0x0000000000000002:  01 D8       add ax, bx
    0x0000000000000002:  F4          hlt
    */

    let code: [u8; 3] = [0x01, 0xd8, 0xf4];
    let mem_size = 0x2000;
    let load_addr = GuestAddress(0x1000);

    let guest_mem =
        GuestMemory::new(&[(GuestAddress(0), mem_size)]).expect("failed to create guest mem");
    guest_mem
        .write_at_addr(&code[..], load_addr)
        .expect("failed to write to guest memory");

    let (_, vm) = create_vm(guest_mem);
    let mut vcpu = vm.create_vcpu(0).expect("new vcpu failed");
    let mut vcpu_sregs = vcpu.get_sregs().expect("get sregs failed");
    vcpu_sregs.cs.base = 0;
    vcpu_sregs.cs.selector = 0;

    vcpu.set_sregs(&vcpu_sregs).expect("set sregs failed");

    let vcpu_regs = Regs {
        rip: load_addr.offset(),
        rflags: 2,
        rax: 1,
        rbx: 2,
        ..Default::default()
    };
    vcpu.set_regs(&vcpu_regs).expect("set regs failed");

    loop {
        match vcpu.run().expect("run failed") {
            VcpuExit::Hlt => {
                break;
            }
            // Continue on external interrupt or signal
            VcpuExit::Intr => continue,
            r => panic!("unexpected exit reason: {:?}", r),
        }
    }

    let regs: Regs = vcpu.get_regs().expect("failed to get regs");
    assert_eq!(regs.rax, 3);
}

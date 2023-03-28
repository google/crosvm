// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(b/237714823): Currently, only kvm is enabled for this test once LUCI can run windows.
#![cfg(unix)]
#![cfg(any(target_arch = "x86", target_arch = "x86_64"))]

use hypervisor::*;
use sync::Mutex;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

#[test]
#[cfg(unix)]
fn test_kvm_real_run_addr() {
    use hypervisor::kvm::*;
    test_real_run_addr(|guest_mem| {
        let kvm = Kvm::new().expect("failed to create kvm");
        let vm = KvmVm::new(&kvm, guest_mem, Default::default()).expect("failed to create vm");
        (kvm, vm)
    });
}

#[test]
#[cfg(feature = "haxm")]
fn test_haxm_real_run_addr() {
    use hypervisor::haxm::*;
    test_real_run_addr(|guest_mem| {
        let haxm = Haxm::new().expect("failed to create haxm");
        let vm = HaxmVm::new(&haxm, guest_mem).expect("failed to create vm");
        (haxm, vm)
    });
}

#[test]
#[cfg(feature = "gvm")]
fn test_gvm_real_run_addr() {
    use hypervisor::gvm::*;
    test_real_run_addr(|guest_mem| {
        let gvm = Gvm::new().expect("failed to create gvm");
        let vm = GvmVm::new(&gvm, guest_mem).expect("failed to create vm");
        (gvm, vm)
    });
}

#[test]
#[cfg(all(windows, feature = "whpx"))]
fn test_whpx_real_run_addr() {
    use hypervisor::whpx::*;
    if !Whpx::is_enabled() {
        return;
    }
    test_real_run_addr(|guest_mem| {
        let whpx = Whpx::new().expect("failed to create whpx");
        let vm =
            WhpxVm::new(&whpx, 1, guest_mem, CpuId::new(0), false).expect("failed to create vm");
        (whpx, vm)
    });
}

fn test_real_run_addr<CreateVm, HypervisorT, VmT>(create_vm: CreateVm)
where
    CreateVm: FnOnce(GuestMemory) -> (HypervisorT, VmT),
    HypervisorT: Hypervisor,
    VmT: VmX86_64,
{
    // This example based on https://lwn.net/Articles/658511/
    let code = [
        0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
        0x00, 0xd8, /* add %bl, %al */
        0x04, b'0', /* add $'0', %al */
        0xee, /* out %al, (%dx) */
        0xb0, b'\n', /* mov $'\n', %al */
        0xee,  /* out %al, (%dx) */
        0x2e, 0xc6, 0x06, 0xf1, 0x10, 0x13, /* movb $0x13, %cs:0xf1 */
        0xf4, /* hlt */
    ];

    let mem_size = 0x1000;
    let load_addr = GuestAddress(0x1000);
    let mem = GuestMemory::new(&[(load_addr, mem_size)]).unwrap();

    let (_hyp, vm) = create_vm(mem);
    let mut vcpu = vm.create_vcpu(0).expect("new vcpu failed");

    vm.get_memory()
        .write_at_addr(&code, load_addr)
        .expect("Writing code to memory failed.");

    let mut vcpu_sregs = vcpu.get_sregs().expect("get sregs failed");
    assert_ne!(vcpu_sregs.cs.base, 0);
    assert_ne!(vcpu_sregs.cs.selector, 0);
    vcpu_sregs.cs.base = 0;
    vcpu_sregs.cs.selector = 0;
    vcpu.set_sregs(&vcpu_sregs).expect("set sregs failed");

    let vcpu_regs = Regs {
        rip: 0x1000,
        rax: 2,
        rbx: 7,
        rflags: 2,
        ..Default::default()
    };
    vcpu.set_regs(&vcpu_regs).expect("set regs failed");

    let out = Mutex::new(String::new());
    loop {
        match vcpu.run().expect("run failed") {
            VcpuExit::Io => {
                vcpu.handle_io(&mut |IoParams {
                                         address,
                                         size,
                                         operation,
                                     }| match operation {
                    IoOperation::Read => {
                        panic!("unexpected io in call");
                    }
                    IoOperation::Write { data } => {
                        assert_eq!(address, 0x3f8);
                        assert_eq!(size, 1);
                        out.lock().push(data[0] as char);
                        None
                    }
                })
                .expect("failed to set the data");
            }
            // Continue on external interrupt or signal
            VcpuExit::Intr => continue,
            VcpuExit::Hlt => break,
            r => panic!("unexpected exit reason: {:?}", r),
        }
    }

    assert_eq!(out.lock().as_str(), "9\n");
    let result: u8 = vm
        .get_memory()
        .read_obj_from_addr(load_addr.checked_add(0xf1).unwrap())
        .expect("Error reading the result.");
    assert_eq!(result, 0x13);
}

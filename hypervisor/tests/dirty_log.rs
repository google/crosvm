// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(b/237714823): Currently, only kvm is enabled for this test once LUCI can run windows.
#![cfg(any(target_os = "android", target_os = "linux"))]
#![cfg(target_arch = "x86_64")]
#![cfg(any(feature = "whpx", feature = "gvm", feature = "haxm", unix))]

use base::MemoryMappingBuilder;
use base::SharedMemory;
use hypervisor::*;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

#[test]
#[cfg(any(target_os = "android", target_os = "linux"))]
fn test_kvm_dirty_log() {
    use hypervisor::kvm::*;
    test_dirty_log(|guest_mem| {
        let kvm = Kvm::new().expect("failed to create kvm");
        let vm = KvmVm::new(&kvm, guest_mem, Default::default()).expect("failed to create vm");
        (kvm, vm)
    });
}

#[test]
#[cfg(feature = "haxm")]
fn test_haxm_dirty_log_not_supported() {
    // HAXM does not support dirty log, so we simply test that the capability
    // returns false.

    use hypervisor::haxm::*;
    let haxm = Haxm::new().expect("failed to create haxm");
    let guest_mem = GuestMemory::new(&[(GuestAddress(0x20000), 0x1000)]).unwrap();
    let vm = HaxmVm::new(&haxm, guest_mem).expect("failed to create vm");

    assert!(!vm.check_capability(VmCap::DirtyLog));
}

#[test]
#[cfg(feature = "gvm")]
fn test_gvm_dirty_log() {
    use hypervisor::gvm::*;
    test_dirty_log(|guest_mem| {
        let gvm = Gvm::new().expect("failed to create gvm");
        let vm = GvmVm::new(&gvm, guest_mem).expect("failed to create vm");
        (gvm, vm)
    });
}

#[test]
#[cfg(all(windows, feature = "whpx"))]
fn test_whpx_dirty_log() {
    use hypervisor::whpx::*;
    if !Whpx::is_enabled() {
        return;
    }
    test_dirty_log(|guest_mem| {
        let whpx = Whpx::new().expect("failed to create whpx");
        let vm =
            WhpxVm::new(&whpx, 1, guest_mem, CpuId::new(0), false).expect("failed to create vm");
        (whpx, vm)
    });
}

fn test_dirty_log<CreateVm, HypervisorT, VmT>(create_vm: CreateVm)
where
    CreateVm: FnOnce(GuestMemory) -> (HypervisorT, VmT),
    HypervisorT: Hypervisor,
    VmT: VmX86_64,
{
    /*
    0000  881C mov [si],bl
    0002  F4   hlt
    */
    let code = [0x88, 0x1c, 0xf4];
    let mem_size = 0x10000;
    let load_addr = GuestAddress(0x1000);
    // GuestMemory requires an initial set of memory, so we just
    // setup some at 0x20000, it won't be used though.
    let guest_mem = GuestMemory::new(&[(GuestAddress(0x20000), 0x1000)]).unwrap();
    let mem = SharedMemory::new("test", mem_size).expect("failed to create shared memory");
    let mmap = MemoryMappingBuilder::new(mem_size as usize)
        .from_shared_memory(&mem)
        .build()
        .expect("failed to create memory mapping");

    mmap.write_slice(&code[..], load_addr.offset() as usize)
        .expect("Writing code to memory failed.");

    let (_hyp, mut vm) = create_vm(guest_mem);
    let mut vcpu = vm.create_vcpu(0).expect("new vcpu failed");
    let mut vcpu_sregs = vcpu.get_sregs().expect("get sregs failed");
    vcpu_sregs.cs.base = 0;
    vcpu_sregs.cs.selector = 0;
    vcpu.set_sregs(&vcpu_sregs).expect("set sregs failed");

    let vcpu_regs = Regs {
        rip: load_addr.offset(),
        rflags: 2,
        // Write 0x12 to the beginning of the 9th page.
        rsi: 0x8000,
        rbx: 0x12,
        ..Default::default()
    };
    vcpu.set_regs(&vcpu_regs).expect("set regs failed");
    let slot = vm
        .add_memory_region(
            GuestAddress(0),
            Box::new(
                MemoryMappingBuilder::new(mem_size as usize)
                    .from_shared_memory(&mem)
                    .build()
                    .expect("failed to create memory mapping"),
            ),
            false,
            true,
        )
        .expect("failed to register memory");

    loop {
        match vcpu.run().expect("run failed") {
            // Continue on external interrupt or signal
            VcpuExit::Intr => continue,
            VcpuExit::Hlt => break,
            r => panic!("unexpected exit reason: {:?}", r),
        }
    }

    let mut dirty_log = [0x0, 0x0];
    vm.get_dirty_log(slot, &mut dirty_log[..])
        .expect("failed to get dirty log");
    // Tests the 9th page was written to.
    assert_eq!(dirty_log[1], 0x1);
    assert_eq!(
        mmap.read_obj::<u64>(vcpu_regs.rsi as usize).unwrap(),
        vcpu_regs.rbx
    );
}

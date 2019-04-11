// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(any(target_arch = "x86", target_arch = "x86_64"))]

use kvm::*;
use kvm_sys::kvm_regs;
use sys_util::{GuestAddress, GuestMemory, MemoryMapping, SharedMemory};

#[test]
fn test_run() {
    /*
    0000  881C mov [si],bl
    0002  F4   hlt
    */
    let code = [0x88, 0x1c, 0xf4];
    let mem_size = 0x10000;
    let load_addr = GuestAddress(0x1000);
    let guest_mem = GuestMemory::new(&[]).unwrap();
    let mut mem = SharedMemory::new(None).expect("failed to create shared memory");
    mem.set_size(mem_size)
        .expect("failed to set shared memory size");
    let mmap =
        MemoryMapping::from_fd(&mem, mem_size as usize).expect("failed to create memory mapping");

    mmap.write_slice(&code[..], load_addr.offset() as usize)
        .expect("Writing code to memory failed.");

    let kvm = Kvm::new().expect("new kvm failed");
    let mut vm = Vm::new(&kvm, guest_mem).expect("new vm failed");
    let vcpu = Vcpu::new(0, &kvm, &vm).expect("new vcpu failed");
    let mut vcpu_sregs = vcpu.get_sregs().expect("get sregs failed");
    vcpu_sregs.cs.base = 0;
    vcpu_sregs.cs.selector = 0;
    vcpu.set_sregs(&vcpu_sregs).expect("set sregs failed");

    let mut vcpu_regs: kvm_regs = unsafe { std::mem::zeroed() };
    vcpu_regs.rip = load_addr.offset() as u64;
    vcpu_regs.rflags = 2;
    // Write 0x12 to the beginning of the 9th page.
    vcpu_regs.rsi = 0x8000;
    vcpu_regs.rbx = 0x12;
    vcpu.set_regs(&vcpu_regs).expect("set regs failed");
    let slot = vm
        .add_device_memory(
            GuestAddress(0),
            MemoryMapping::from_fd(&mem, mem_size as usize)
                .expect("failed to create memory mapping"),
            false,
            true,
        )
        .expect("failed to register memory");

    loop {
        match vcpu.run().expect("run failed") {
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

// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(b/237714823): Currently, only kvm is enabled for this test once LUCI can run windows.
#![cfg(unix)]
#![cfg(any(target_arch = "x86", target_arch = "x86_64"))]

use base::MemoryMappingBuilder;
use base::SharedMemory;
use hypervisor::*;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

#[test]
#[cfg(unix)]
fn test_kvm_remove_memory() {
    use hypervisor::kvm::*;
    test_remove_memory(|guest_mem| {
        let kvm = Kvm::new().expect("failed to create kvm");
        let vm = KvmVm::new(&kvm, guest_mem, Default::default()).expect("failed to create vm");
        (kvm, vm)
    });
}

#[test]
#[cfg(feature = "haxm")]
fn test_haxm_remove_memory() {
    use hypervisor::haxm::*;
    test_remove_memory(|guest_mem| {
        let haxm = Haxm::new().expect("failed to create haxm");
        let vm = HaxmVm::new(&haxm, guest_mem).expect("failed to create vm");
        (haxm, vm)
    });
}

#[test]
#[cfg(feature = "gvm")]
fn test_gvm_remove_memory() {
    use hypervisor::gvm::*;
    test_remove_memory(|guest_mem| {
        let gvm = Gvm::new().expect("failed to create gvm");
        let vm = GvmVm::new(&gvm, guest_mem).expect("failed to create vm");
        (gvm, vm)
    });
}

#[test]
#[cfg(all(windows, feature = "whpx"))]
fn test_whpx_remove_memory() {
    use hypervisor::whpx::*;
    if !Whpx::is_enabled() {
        return;
    }
    test_remove_memory(|guest_mem| {
        let whpx = Whpx::new().expect("failed to create whpx");
        let vm =
            WhpxVm::new(&whpx, 1, guest_mem, CpuId::new(0), false).expect("failed to create vm");
        (whpx, vm)
    });
}

fn test_remove_memory<CreateVm, HypervisorT, VmT>(create_vm: CreateVm)
where
    CreateVm: FnOnce(GuestMemory) -> (HypervisorT, VmT),
    HypervisorT: Hypervisor,
    VmT: VmX86_64,
{
    /*
    0x0000000000000000:  A0 00 30    mov al, byte ptr [0x3000]
    0x0000000000000003:  F4          hlt
    */
    let code = [0xa0, 0x00, 0x30, 0xf4];
    let mem_size = 0x2000;
    let load_addr = GuestAddress(0x1000);

    // GuestMemory requires an initial set of memory, so we just
    // setup some at 0x8000, it won't be used though.
    let guest_mem =
        GuestMemory::new(&[(GuestAddress(0x8000), 0x1000)]).expect("failed to create guest mem");
    let mem = SharedMemory::new("test", mem_size).expect("failed to create shared memory");
    let mmap = MemoryMappingBuilder::new(mem_size as usize)
        .from_shared_memory(&mem)
        .build()
        .expect("failed to create memory mapping");

    mmap.write_slice(&code[..], load_addr.offset() as usize)
        .expect("Writing code to memory failed.");

    let (_, mut vm) = create_vm(guest_mem);
    let mut vcpu = vm.create_vcpu(0).expect("new vcpu failed");
    let mut vcpu_sregs = vcpu.get_sregs().expect("get sregs failed");
    vcpu_sregs.cs.base = 0;
    vcpu_sregs.cs.selector = 0;
    vcpu.set_sregs(&vcpu_sregs).expect("set sregs failed");

    let vcpu_regs = Regs {
        rip: load_addr.offset(),
        rflags: 2,
        ..Default::default()
    };
    vcpu.set_regs(&vcpu_regs).expect("set regs failed");
    vm.add_memory_region(
        GuestAddress(0),
        Box::new(
            MemoryMappingBuilder::new(mem_size as usize)
                .from_shared_memory(&mem)
                .build()
                .expect("failed to create memory mapping"),
        ),
        false,
        false,
    )
    .expect("failed to register memory");

    // This is our memory that we will remove
    let mem_to_remove = SharedMemory::new("test", 0x1000).expect("failed to create shared memory");

    let mmap_to_remove = MemoryMappingBuilder::new(0x1000)
        .from_shared_memory(&mem_to_remove)
        .build()
        .expect("failed to create memory mapping");
    mmap_to_remove
        .write_obj(0x55, 0)
        .expect("failed writing data to ro memory");
    let slot_to_remove = vm
        .add_memory_region(
            GuestAddress(0x3000),
            Box::new(
                MemoryMappingBuilder::new(0x1000)
                    .from_shared_memory(&mem_to_remove)
                    .build()
                    .expect("failed to create memory mapping"),
            ),
            false,
            false,
        )
        .expect("failed to register memory");

    // We do our initial run of our program, it should load the value of 0x55
    // from guest address 0x3000 into rax
    loop {
        match vcpu.run().expect("run failed") {
            // Continue on external interrupt or signal
            VcpuExit::Intr => continue,
            VcpuExit::Hlt => break,
            r => panic!("unexpected exit reason: {:?}", r),
        }
    }

    let mut regs = vcpu.get_regs().expect("failed to get regs");
    assert_eq!(regs.rax, 0x55);

    // now we're going to run the same instructions again, but remove the memory first
    regs.rax = 0;
    regs.rip = load_addr.offset();
    vcpu.set_regs(&regs).expect("failed to set regs");
    // now that we have removed the memory region at 0x3000, the mov [0x3000],al instruction
    // should produce mmio
    vm.remove_memory_region(slot_to_remove)
        .expect("failed to remove memory region");

    loop {
        match vcpu.run().expect("run failed") {
            // Continue on external interrupt or signal
            VcpuExit::Intr => continue,
            VcpuExit::Hlt => break,
            VcpuExit::Mmio => {
                vcpu.handle_mmio(&mut |IoParams {
                                           address,
                                           size,
                                           operation,
                                       }| match operation {
                    IoOperation::Read => {
                        let mut data = [0u8; 8];
                        assert_eq!(address, 0x3000);
                        assert_eq!(size, 1);
                        data.copy_from_slice(&0x44_u64.to_ne_bytes());
                        Some(data)
                    }
                    IoOperation::Write { .. } => {
                        panic!("unexpected mmio write");
                    }
                })
                .expect("failed to set the data");
            }
            r => panic!("unexpected exit reason: {:?}", r),
        }
    }

    let regs = vcpu.get_regs().expect("failed to get regs");
    assert_eq!(regs.rax, 0x44);
}

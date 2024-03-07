// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(b/237714823): Currently, only kvm is enabled for this test once LUCI can run windows.
#![cfg(any(target_os = "android", target_os = "linux"))]
#![cfg(target_arch = "x86_64")]

use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;

use base::MemoryMappingBuilder;
use base::SharedMemory;
use hypervisor::*;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

#[test]
#[cfg(any(target_os = "android", target_os = "linux"))]
fn test_kvm_read_only_memory() {
    use hypervisor::kvm::*;
    test_read_only_memory(|guest_mem| {
        let kvm = Kvm::new().expect("failed to create kvm");
        let vm = KvmVm::new(&kvm, guest_mem, Default::default()).expect("failed to create vm");
        (kvm, vm)
    });
}

// TODO(b/163163457): HAXM has a bug where the mmio write for read only memory
//  does not happen to the correct address.
// #[test]
// #[cfg(all(windows, feature = "haxm"))]
// fn test_haxm_read_only_memory() {
//     use hypervisor::haxm::*;
//     test_read_only_memory(|guest_mem| {
//         let haxm = Haxm::new().expect("failed to create haxm");
//         let vm = HaxmVm::new(&haxm, guest_mem).expect("failed to create vm");
//         (haxm, vm)
//     });
// }

#[test]
#[cfg(feature = "gvm")]
fn test_gvm_read_only_memory() {
    use hypervisor::gvm::*;
    test_read_only_memory(|guest_mem| {
        let gvm = Gvm::new().expect("failed to create gvm");
        let vm = GvmVm::new(&gvm, guest_mem).expect("failed to create vm");
        (gvm, vm)
    });
}

// TODO(b/163163457): whpx also fails with guest cannot be faulted
/*#[test]
#[cfg(all(windows, feature = "whpx"))]
fn test_whpx_read_only_memory() {
    use hypervisor::whpx::*;
    if !Whpx::is_enabled() { return; }
    test_read_only_memory(|guest_mem| {
        let whpx = Whpx::new().expect("failed to create whpx");
        let vm = WhpxVm::new(&whpx, 1, guest_mem, CpuId::new(0), false)
            .expect("failed to create vm");
        (whpx, vm)
    });
}*/

fn test_read_only_memory<CreateVm, HypervisorT, VmT>(create_vm: CreateVm)
where
    CreateVm: FnOnce(GuestMemory) -> (HypervisorT, VmT),
    HypervisorT: Hypervisor,
    VmT: VmX86_64,
{
    /*
    0000  268A07  mov al,[es:bx]
    0003  0401    add al,0x1
    0005  268807  mov [es:bx],al
    0008  F4      hlt
    */
    let code = [0x26, 0x8a, 0x07, 0x04, 0x01, 0x26, 0x88, 0x07, 0xf4];
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
    vcpu_sregs.cs.s = 1;
    vcpu_sregs.cs.type_ = 0b1011;
    vcpu_sregs.es.base = 0x3000;
    vcpu_sregs.es.selector = 0;
    vcpu_sregs.es.s = 1;
    vcpu_sregs.es.type_ = 0b1011;

    vcpu.set_sregs(&vcpu_sregs).expect("set sregs failed");

    let vcpu_regs = Regs {
        rip: load_addr.offset(),
        rflags: 2,
        rax: 0,
        rbx: 0,
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
        MemCacheType::CacheCoherent,
    )
    .expect("failed to register memory");

    // Give some read only memory for the test code to read from and force a vcpu exit when it reads
    // from it.
    let mem_ro = SharedMemory::new("test", 0x1000).expect("failed to create shared memory");

    let mmap_ro = MemoryMappingBuilder::new(0x1000)
        .from_shared_memory(&mem_ro)
        .build()
        .expect("failed to create memory mapping");
    mmap_ro
        .write_obj(0x66, 0)
        .expect("failed writing data to ro memory");
    vm.add_memory_region(
        GuestAddress(vcpu_sregs.es.base),
        Box::new(
            MemoryMappingBuilder::new(0x1000)
                .from_shared_memory(&mem_ro)
                .build()
                .expect("failed to create memory mapping"),
        ),
        true,
        false,
        MemCacheType::CacheCoherent,
    )
    .expect("failed to register memory");

    // Ensure we get exactly 1 exit from attempting to write to read only memory.
    let exits = AtomicU16::new(0);

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
                        panic!("unexpected mmio read call");
                    }
                    IoOperation::Write { data } => {
                        assert_eq!(size, 1);
                        assert_eq!(address, vcpu_sregs.es.base);
                        assert_eq!(data[0], 0x67);
                        exits.fetch_add(1, Ordering::SeqCst);
                        None
                    }
                })
                .expect("failed to set the data");
            }
            r => panic!("unexpected exit reason: {:?}", r),
        }
    }

    // Check that exactly 1 attempt to write to read only memory was made, and that the memory is
    // unchanged after that attempt.
    assert_eq!(exits.load(Ordering::SeqCst), 1);
    assert_eq!(
        mmap_ro
            .read_obj::<u8>(0)
            .expect("failed to read data from ro memory"),
        0x66
    );

    let vcpu_regs = vcpu.get_regs().expect("failed to get regs");
    assert_eq!(vcpu_regs.rax, 0x67);
}

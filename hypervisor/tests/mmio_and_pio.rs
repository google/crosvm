// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(b/237714823): Currently, only kvm is enabled for this test once LUCI can run windows.
#![cfg(unix)]
#![cfg(any(target_arch = "x86", target_arch = "x86_64"))]

use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;

use hypervisor::*;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

#[test]
#[cfg(unix)]
fn test_kvm_mmio_and_pio() {
    use hypervisor::kvm::*;
    test_mmio_and_pio(|guest_mem| {
        let kvm = Kvm::new().expect("failed to create kvm");
        let vm = KvmVm::new(&kvm, guest_mem, Default::default()).expect("failed to create vm");
        (kvm, vm)
    });
}

#[test]
#[cfg(feature = "haxm")]
fn test_haxm_mmio_and_pio() {
    use hypervisor::haxm::*;
    test_mmio_and_pio(|guest_mem| {
        let haxm = Haxm::new().expect("failed to create haxm");
        let vm = HaxmVm::new(&haxm, guest_mem).expect("failed to create vm");
        (haxm, vm)
    });
}

#[test]
#[cfg(all(windows, feature = "whpx"))]
fn test_whpx_mmio_and_pio() {
    use hypervisor::whpx::*;
    if !Whpx::is_enabled() {
        return;
    }
    test_mmio_and_pio(|guest_mem| {
        let whpx = Whpx::new().expect("failed to create whpx");
        let vm =
            WhpxVm::new(&whpx, 1, guest_mem, CpuId::new(0), false).expect("failed to create vm");
        (whpx, vm)
    });
}

#[test]
#[cfg(feature = "gvm")]
fn test_gvm_mmio_and_pio() {
    use hypervisor::gvm::*;
    test_mmio_and_pio(|guest_mem| {
        let gvm = Gvm::new().expect("failed to create gvm");
        let vm = GvmVm::new(&gvm, guest_mem).expect("failed to create vm");
        (gvm, vm)
    });
}

fn test_mmio_and_pio<CreateVm, HypervisorT, VmT>(create_vm: CreateVm)
where
    CreateVm: FnOnce(GuestMemory) -> (HypervisorT, VmT),
    HypervisorT: Hypervisor,
    VmT: VmX86_64,
{
    /*
    0x0000000000000000:  67 88 03    mov byte ptr [ebx], al
    0x0000000000000003:  67 8A 01    mov al, byte ptr [ecx]
    0x0000000000000006:  E6 19       out 0x19, al
    0x0000000000000008:  E4 20       in  al, 0x20
    0x000000000000000a:  F4          hlt
    */

    let code: [u8; 11] = [
        0x67, 0x88, 0x03, 0x67, 0x8a, 0x01, 0xe6, 0x19, 0xe4, 0x20, 0xf4,
    ];
    let mem_size = 0x2000;
    let load_addr = GuestAddress(0x1000);

    // GuestMemory requires an initial set of memory, so we just
    // setup some at 0x8000, it won't be used though.
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
        rax: 0x33,
        rbx: 0x3000,
        rcx: 0x3010,
        ..Default::default()
    };
    vcpu.set_regs(&vcpu_regs).expect("set regs failed");

    // Ensure we get exactly 2 exits for the mmio and the pio.
    let exits = AtomicU16::new(0);

    let run_handle = vcpu.take_run_handle(None).unwrap();
    loop {
        match vcpu.run(&run_handle).expect("run failed") {
            VcpuExit::Mmio => {
                vcpu.handle_mmio(&mut |IoParams {
                                           address,
                                           size,
                                           operation,
                                       }| {
                    match operation {
                        IoOperation::Read => {
                            let mut data = [0u8; 8];
                            assert_eq!(address, 0x3010);
                            assert_eq!(size, 1);
                            exits.fetch_add(1, Ordering::SeqCst);
                            // this number will be read into al register
                            data.copy_from_slice(&0x66_u64.to_ne_bytes());
                            Some(data)
                        }
                        IoOperation::Write { data } => {
                            assert_eq!(address, 0x3000);
                            assert_eq!(data[0], 0x33);
                            assert_eq!(size, 1);
                            exits.fetch_add(1, Ordering::SeqCst);
                            None
                        }
                    }
                })
                .expect("failed to set the data");
            }
            VcpuExit::Io => {
                vcpu.handle_io(&mut |IoParams {
                                         address,
                                         size,
                                         operation,
                                     }| {
                    match operation {
                        IoOperation::Read => {
                            let mut data = [0u8; 8];
                            assert_eq!(address, 0x20);
                            assert_eq!(size, 1);
                            exits.fetch_add(1, Ordering::SeqCst);
                            // this number will be read into the al register
                            data.copy_from_slice(&0x77_u64.to_ne_bytes());
                            Some(data)
                        }
                        IoOperation::Write { data } => {
                            assert_eq!(address, 0x19);
                            assert_eq!(size, 1);
                            assert_eq!(data[0], 0x66);
                            exits.fetch_add(1, Ordering::SeqCst);
                            None
                        }
                    }
                })
                .expect("failed to set the data");
            }
            VcpuExit::Hlt => {
                break;
            }
            // Continue on external interrupt or signal
            VcpuExit::Intr => continue,
            r => panic!("unexpected exit reason: {:?}", r),
        }
    }

    assert_eq!(exits.load(Ordering::SeqCst), 4);
    let regs: Regs = vcpu.get_regs().expect("failed to get regs");
    assert_eq!(regs.rax, 0x77);
}

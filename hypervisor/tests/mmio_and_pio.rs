// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(b/237714823): Currently, only kvm is enabled for this test once LUCI can run windows.
#![cfg(any(target_os = "android", target_os = "linux"))]
#![cfg(target_arch = "x86_64")]

use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;

use hypervisor::*;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

#[test]
#[cfg(any(target_os = "android", target_os = "linux"))]
fn test_kvm_mmio_and_pio() {
    use hypervisor::kvm::*;
    test_mmio_and_pio(|guest_mem| {
        let kvm = Kvm::new().expect("failed to create kvm");
        let vm = KvmVm::new(&kvm, guest_mem, Default::default()).expect("failed to create vm");
        (kvm, vm)
    });
}

#[test]
#[cfg(all(windows, feature = "haxm"))]
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

    loop {
        match vcpu.run().expect("run failed") {
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

#[test]
#[cfg(any(target_os = "android", target_os = "linux"))]
fn test_kvm_pio_out() {
    use hypervisor::kvm::*;
    test_pio_out(|guest_mem| {
        let kvm = Kvm::new().expect("failed to create kvm");
        let vm = KvmVm::new(&kvm, guest_mem, Default::default()).expect("failed to create vm");
        (kvm, vm)
    });
}

#[test]
#[cfg(all(windows, feature = "haxm"))]
fn test_haxm_pio_out() {
    use hypervisor::haxm::*;
    test_pio_out(|guest_mem| {
        let haxm = Haxm::new().expect("failed to create haxm");
        let vm = HaxmVm::new(&haxm, guest_mem).expect("failed to create vm");
        (haxm, vm)
    });
}

#[test]
#[cfg(all(windows, feature = "whpx"))]
fn test_whpx_pio_out() {
    use hypervisor::whpx::*;
    if !Whpx::is_enabled() {
        return;
    }
    test_pio_out(|guest_mem| {
        let whpx = Whpx::new().expect("failed to create whpx");
        let vm =
            WhpxVm::new(&whpx, 1, guest_mem, CpuId::new(0), false).expect("failed to create vm");
        (whpx, vm)
    });
}

#[test]
#[cfg(feature = "gvm")]
fn test_gvm_pio_out() {
    use hypervisor::gvm::*;
    test_pio_out(|guest_mem| {
        let gvm = Gvm::new().expect("failed to create gvm");
        let vm = GvmVm::new(&gvm, guest_mem).expect("failed to create vm");
        (gvm, vm)
    });
}

fn test_pio_out<CreateVm, HypervisorT, VmT>(create_vm: CreateVm)
where
    CreateVm: FnOnce(GuestMemory) -> (HypervisorT, VmT),
    HypervisorT: Hypervisor,
    VmT: VmX86_64,
{
    /*
      0x00: 31 c0      xor ax, ax   (ax = 0)
      0x02: 40         inc ax       (ax = 1)
      0x03: e7 01      out 0x1, ax  (OUT 0x0001 to port 1)
      0x05: 40         inc ax       (ax = 2)
      0x06: e6 02      out 0x2, al  (OUT 0x02 to port 2)
      0x08: 40         inc ax       (ax = 3)
      0x09: 89 c2      mov dx, ax   (dx = 3)
      0x0b: ef         out dx, ax   (OUT 0x0003 to port 3)
      0x0c: 40         inc ax       (ax = 4)
      0x0d: 42         inc dx       (dx = 4)
      0x0e: ee         out dx, al   (OUT 0x04 to port 4)
      0x0f: f4         hlt
    */

    let code: [u8; 16] = [
        0x31, 0xc0, 0x40, 0xe7, 0x01, 0x40, 0xe6, 0x02, 0x40, 0x89, 0xc2, 0xef, 0x40, 0x42, 0xee,
        0xf4,
    ];
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
        ..Default::default()
    };
    vcpu.set_regs(&vcpu_regs).expect("set regs failed");

    // Ensure we get the expected PIO exits
    let exit_count = AtomicU16::new(0);
    let exit_bits = AtomicU16::new(0);

    loop {
        match vcpu.run().expect("run failed") {
            VcpuExit::Io => {
                vcpu.handle_io(&mut |IoParams {
                                         address,
                                         size,
                                         operation,
                                     }| {
                    match operation {
                        IoOperation::Read => panic!("unexpected PIO read"),
                        IoOperation::Write { data } => {
                            assert!((1..=4).contains(&address));
                            if address % 2 == 0 {
                                assert_eq!(size, 1);
                                assert_eq!(data[0], address as u8);
                            } else {
                                assert_eq!(size, 2);
                                assert_eq!(data[0], address as u8);
                                assert_eq!(data[1], 0);
                            }
                            exit_bits.fetch_or(1 << (address - 1), Ordering::SeqCst);
                            exit_count.fetch_add(1, Ordering::SeqCst);
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

    // bits 0 through 3 have been set
    assert_eq!(exit_bits.load(Ordering::SeqCst), 0xf);
    assert_eq!(exit_count.load(Ordering::SeqCst), 4);
}

#[test]
#[cfg(any(target_os = "android", target_os = "linux"))]
fn test_kvm_pio_in() {
    use hypervisor::kvm::*;
    test_pio_in(|guest_mem| {
        let kvm = Kvm::new().expect("failed to create kvm");
        let vm = KvmVm::new(&kvm, guest_mem, Default::default()).expect("failed to create vm");
        (kvm, vm)
    });
}

#[test]
#[cfg(all(windows, feature = "haxm"))]
fn test_haxm_pio_in() {
    use hypervisor::haxm::*;
    test_pio_in(|guest_mem| {
        let haxm = Haxm::new().expect("failed to create haxm");
        let vm = HaxmVm::new(&haxm, guest_mem).expect("failed to create vm");
        (haxm, vm)
    });
}

#[test]
#[cfg(all(windows, feature = "whpx"))]
fn test_whpx_pio_in() {
    use hypervisor::whpx::*;
    if !Whpx::is_enabled() {
        return;
    }
    test_pio_in(|guest_mem| {
        let whpx = Whpx::new().expect("failed to create whpx");
        let vm =
            WhpxVm::new(&whpx, 1, guest_mem, CpuId::new(0), false).expect("failed to create vm");
        (whpx, vm)
    });
}

#[test]
#[cfg(feature = "gvm")]
fn test_gvm_pio_in() {
    use hypervisor::gvm::*;
    test_pio_in(|guest_mem| {
        let gvm = Gvm::new().expect("failed to create gvm");
        let vm = GvmVm::new(&gvm, guest_mem).expect("failed to create vm");
        (gvm, vm)
    });
}

fn test_pio_in<CreateVm, HypervisorT, VmT>(create_vm: CreateVm)
where
    CreateVm: FnOnce(GuestMemory) -> (HypervisorT, VmT),
    HypervisorT: Hypervisor,
    VmT: VmX86_64,
{
    /*
      0x00: e5 01      in ax, 0x1   (IN 16 bits from port 1)
      0x02: 89 c6      mov si, ax   (si = value from port 1)
      0x04: 31 c0      xor ax, ax   (clear ax, since IN will only write the lower byte)
      0x06: e4 02      in al, 0x02  (IN 8 bits from port 2)
      0x08: 89 c3      mov bx, ax   (bx = value from port 2)
      0x0a: ba 03 00   mov dx, 0x03 (dx = 3)
      0x0d: ed         in ax, dx    (IN 16 bits from port 3)
      0x0e: 89 c1      mov cx, ax   (cx = value from port 3)
      0x10: 42         inc dx       (dx = 4)
      0x11: 31 c0      xor ax, ax   (clear ax, since IN will only write the lower byte)
      0x13: ec         in al, dx    (IN 8 bits from port 4)
      0x14: 89 c2      mov dx, ax   (dx = value from port 4)
      0x16: 89 f0      mov ax, si   (ax = value from port 1)
      0x18: f4         hlt
    */

    let code: [u8; 25] = [
        0xe5, 0x01, 0x89, 0xc6, 0x31, 0xc0, 0xe4, 0x02, 0x89, 0xc3, 0xba, 0x03, 0x00, 0xed, 0x89,
        0xc1, 0x42, 0x31, 0xc0, 0xec, 0x89, 0xc2, 0x89, 0xf0, 0xf4,
    ];
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
        ..Default::default()
    };
    vcpu.set_regs(&vcpu_regs).expect("set regs failed");

    // Ensure we get the expected PIO exits
    let exit_count = AtomicU16::new(0);
    let exit_bits = AtomicU16::new(0);

    loop {
        match vcpu.run().expect("run failed") {
            VcpuExit::Io => {
                vcpu.handle_io(&mut |IoParams {
                                         address,
                                         size,
                                         operation,
                                     }| {
                    match operation {
                        IoOperation::Read => {
                            let mut data = [0u8; 8];
                            assert!((1..=4).contains(&address));

                            if address % 2 == 0 {
                                assert_eq!(size, 1);
                                data[0] = address as u8;
                            } else {
                                assert_eq!(size, 2);
                                data[0] = address as u8;
                                data[1] = address as u8;
                            }

                            exit_bits.fetch_or(1 << (address - 1), Ordering::SeqCst);
                            exit_count.fetch_add(1, Ordering::SeqCst);
                            Some(data)
                        }
                        IoOperation::Write { .. } => panic!("unexpected PIO write"),
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

    // bits 0 through 3 have been set
    assert_eq!(exit_bits.load(Ordering::SeqCst), 0xf);
    assert_eq!(exit_count.load(Ordering::SeqCst), 4);
    let regs: Regs = vcpu.get_regs().expect("failed to get regs");
    assert_eq!(regs.rax, 0x0101);
    assert_eq!(regs.rbx, 0x02);
    assert_eq!(regs.rcx, 0x0303);
    assert_eq!(regs.rdx, 0x04);
}

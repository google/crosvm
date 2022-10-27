// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(any(target_arch = "x86", target_arch = "x86_64"))]
// Test applies to whpx only.
#![cfg(all(windows, feature = "whpx"))]

use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;

use hypervisor::*;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

// This test case is for the following scenario:
// Test sets up a guest memory instruction page, such that an instruction
// straddles across a page boundary. That is, the bytes for the instruction are
// split between end of first page and start of the next page. This triggers
// WHV_EMULATOR to perform an "MMIO" load which is just a memory read from the
// second page.
#[test]
fn test_whpx_mmio_fetch_memory() {
    use hypervisor::whpx::*;
    /*
    0x0000000000000000:  67 88 03    mov byte ptr [ebx], al
    0x0000000000000003:  67 8A 01    mov al, byte ptr [ecx]
    0x000000000000000a:  F4          hlt
    */

    // Start executing the following instructions on the last byte of the page
    // so that the instruction emulator needs to fetch it from the next page
    // first.
    // If `code` or `load_addr` is changed, the memory load on line 89 will need
    // to be updated.
    let code = [0x67, 0x88, 0x03, 0x67, 0x8a, 0x01, 0xf4];
    let load_addr = GuestAddress(0x0fff);
    let mem_size = 0x2000;

    let guest_mem =
        GuestMemory::new(&[(GuestAddress(0), mem_size)]).expect("failed to create guest mem");
    guest_mem
        .write_at_addr(&code[..], load_addr)
        .expect("failed to write to guest memory");

    if !Whpx::is_enabled() {
        panic!("whpx not enabled!");
    }

    let whpx = Whpx::new().expect("failed to create whpx");
    let vm = WhpxVm::new(&whpx, 1, guest_mem, CpuId::new(0), false).expect("failed to create vm");

    let mut vcpu = vm.create_vcpu(0).expect("new vcpu failed");
    let mut vcpu_sregs = vcpu.get_sregs().expect("get sregs failed");
    vcpu_sregs.cs.base = 0;
    vcpu_sregs.cs.selector = 0;

    vcpu.set_sregs(&vcpu_sregs).expect("set sregs failed");

    let vcpu_regs = Regs {
        rip: load_addr.offset() as u64,
        rflags: 2,
        rax: 0x33,
        rbx: 0x3000,
        rcx: 0x3010,
        ..Default::default()
    };
    vcpu.set_regs(&vcpu_regs).expect("set regs failed");

    // Ensure we get exactly 2 exits for the mmio read and write.
    let exits = AtomicU16::new(0);
    // Also, ensure that we have 2 "mmio" reads, one for reading execution page
    // and the second one for unmapped data page.
    let memory_reads = AtomicU16::new(0);
    // And ensure that 1 write is performed.
    let memory_writes = AtomicU16::new(0);

    let run_handle = vcpu.take_run_handle(None).unwrap();
    loop {
        match vcpu.run(&run_handle).expect("run failed") {
            VcpuExit::Mmio => {
                exits.fetch_add(1, Ordering::SeqCst);
                vcpu.handle_mmio(&mut |IoParams {
                                           address,
                                           size,
                                           operation,
                                       }| {
                    match operation {
                        IoOperation::Read => {
                            memory_reads.fetch_add(1, Ordering::SeqCst);
                            match (address, size) {
                                // First MMIO read from the WHV_EMULATOR asks to
                                // load the first 8 bytes of a new execution
                                // page, when an instruction crosses page
                                // boundary.
                                // Return the rest of instructions that are
                                // supposed to be on the second page.
                                (0x1000, 8) => {
                                    // Ensure this instruction is the first read
                                    // in the sequence.
                                    assert_eq!(memory_reads.load(Ordering::SeqCst), 1);
                                    Some([0x88, 0x03, 0x67, 0x8a, 0x01, 0xf4, 0, 0])
                                }
                                // Second MMIO read is a regular read from an
                                // unmapped memory.
                                (0x3010, 1) => Some([0x66, 0, 0, 0, 0, 0, 0, 0]),
                                _ => {
                                    panic!("invalid address({:#x})/size({})", address, size)
                                }
                            }
                        }
                        IoOperation::Write { data } => {
                            assert_eq!(address, 0x3000);
                            assert_eq!(data[0], 0x33);
                            assert_eq!(size, 1);
                            memory_writes.fetch_add(1, Ordering::SeqCst);
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

    assert_eq!(exits.load(Ordering::SeqCst), 2);
    assert_eq!(memory_reads.load(Ordering::SeqCst), 2);
    assert_eq!(memory_writes.load(Ordering::SeqCst), 1);
    let regs = vcpu.get_regs().expect("get_regs() failed");
    assert_eq!(regs.rax, 0x66);
}

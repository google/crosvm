// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(b/237714823): Currently, only kvm is enabled for this test once LUCI can run windows.
#![cfg(any(target_os = "android", target_os = "linux"))]
#![cfg(target_arch = "x86_64")]

use std::arch::x86_64::_rdtsc;

use hypervisor::*;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

macro_rules! assert_wrapping_close {
    ($value:expr, $expected: expr, $threshold: expr, $type: expr) => {
        let e = $expected;
        let v = $value;
        let wrapping_diff = std::cmp::min(v.wrapping_sub(e), e.wrapping_sub(v));
        assert!(
            wrapping_diff < $threshold,
            "{} value {} too far from {}",
            $type,
            $value,
            $expected
        );
    };
}

#[test]
#[cfg(any(target_os = "android", target_os = "linux"))]
fn test_kvm_tsc_offsets() {
    use hypervisor::kvm::*;
    test_tsc_offsets(|guest_mem| {
        let kvm = Kvm::new().expect("failed to create kvm");
        let vm = KvmVm::new(&kvm, guest_mem, Default::default()).expect("failed to create vm");
        (kvm, vm)
    });
}

#[test]
#[cfg(all(windows, feature = "haxm"))]
fn test_haxm_tsc_offsets() {
    use hypervisor::haxm::*;
    test_tsc_offsets(|guest_mem| {
        let haxm = Haxm::new().expect("failed to create haxm");
        let vm = HaxmVm::new(&haxm, guest_mem).expect("failed to create vm");
        (haxm, vm)
    });
}

#[test]
#[cfg(feature = "gvm")]
fn test_gvm_tsc_offsets() {
    use hypervisor::gvm::*;
    test_tsc_offsets(|guest_mem| {
        let gvm = Gvm::new().expect("failed to create gvm");
        let vm = GvmVm::new(&gvm, guest_mem).expect("failed to create vm");
        (gvm, vm)
    });
}

#[test]
#[cfg(all(windows, feature = "whpx"))]
fn test_whpx_tsc_offsets() {
    use hypervisor::whpx::*;
    if !Whpx::is_enabled() {
        return;
    }
    test_tsc_offsets(|guest_mem| {
        let whpx = Whpx::new().expect("failed to create whpx");
        let vm =
            WhpxVm::new(&whpx, 1, guest_mem, CpuId::new(0), false).expect("failed to create vm");
        (whpx, vm)
    });
}

fn test_tsc_offsets<CreateVm, HypervisorT, VmT>(create_vm: CreateVm)
where
    CreateVm: FnOnce(GuestMemory) -> (HypervisorT, VmT),
    HypervisorT: Hypervisor,
    VmT: VmX86_64,
{
    // We're in real mode, so we need to do two memory operations to get a 64 bit value into
    // memory.
    /*
    0x0000000000000000:  0F 31             rdtsc
    0x0000000000000002:  67 66 89 51 04    mov   dword ptr [ecx + 4], edx
    0x0000000000000007:  67 66 89 01       mov   dword ptr [ecx], eax
    0x000000000000000b:  F4                hlt
    */

    let code: [u8; 12] = [
        0x0f, 0x31, 0x67, 0x66, 0x89, 0x51, 0x04, 0x67, 0x66, 0x89, 0x01, 0xf4,
    ];
    let mem_size = 0x4000;
    let load_addr = GuestAddress(0x1000);

    let guest_mem =
        GuestMemory::new(&[(GuestAddress(0), mem_size)]).expect("failed to create guest mem");
    guest_mem
        .write_at_addr(&code[..], load_addr)
        .expect("failed to write to guest memory");

    let mem_clone = guest_mem.clone();

    let (_, vm) = create_vm(guest_mem);
    let mut vcpu = vm.create_vcpu(0).expect("new vcpu failed");
    let mut vcpu_sregs = vcpu.get_sregs().expect("get sregs failed");
    vcpu_sregs.cs.base = 0;
    vcpu_sregs.cs.selector = 0;

    vcpu.set_sregs(&vcpu_sregs).expect("set sregs failed");

    // basic case, we set MSR to 0
    // SAFETY: trivially safe
    let tsc_now = unsafe { _rdtsc() };
    test_tsc_offset_run(
        &mut vcpu,
        &mem_clone,
        load_addr,
        Some(0),
        None,
        u64::MAX - tsc_now + 1,
        0,
    );
    // set offset to 0
    // SAFETY: trivially safe
    let tsc_now = unsafe { _rdtsc() };
    test_tsc_offset_run(&mut vcpu, &mem_clone, load_addr, None, Some(0), 0, tsc_now);
    // some moderately sized offset
    // SAFETY: trivially safe
    let tsc_now = unsafe { _rdtsc() };
    let ten_seconds = 2_500_000_000 * 10;
    test_tsc_offset_run(
        &mut vcpu,
        &mem_clone,
        load_addr,
        None,
        Some(ten_seconds),
        ten_seconds,
        tsc_now + ten_seconds,
    );
    // set offset to u64::MAX - tsc_now + 1
    // SAFETY: trivially safe
    let tsc_now = unsafe { _rdtsc() };
    test_tsc_offset_run(
        &mut vcpu,
        &mem_clone,
        load_addr,
        None,
        Some(u64::MAX - tsc_now + 1),
        u64::MAX - tsc_now + 1,
        0,
    );
}

fn test_tsc_offset_run(
    vcpu: &mut Box<dyn hypervisor::VcpuX86_64>,
    mem_clone: &GuestMemory,
    load_addr: GuestAddress,
    set_msr: Option<u64>,
    set_offset: Option<u64>,
    expected_get_offset: u64,
    expected_rdtsc: u64,
) {
    // typical TSC frequency is like 2.5GHz so if we say the threshold is within 100ms then our
    // threshold is 250_000_000
    let threshold = 250_000_000;

    let vcpu_regs = Regs {
        rip: load_addr.offset(),
        rflags: 2,
        rcx: 0x3000,
        ..Default::default()
    };
    vcpu.set_regs(&vcpu_regs).expect("set regs failed");

    if let Some(value) = set_msr {
        vcpu.set_msr(0x00000010, value)
            .expect("set_msr should not fail");
    }

    if let Some(offset) = set_offset {
        vcpu.set_tsc_offset(offset)
            .expect("set offset should not fail");
    }

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

    assert_wrapping_close!(
        mem_clone
            .read_obj_from_addr::<u64>(GuestAddress(0x3000))
            .expect("guest mem read should be ok"),
        expected_rdtsc,
        threshold,
        "rdtsc written to memory"
    );

    assert_wrapping_close!(
        vcpu.get_tsc_offset().expect("get offset should not fail"),
        expected_get_offset,
        threshold,
        "tsc offset"
    );
}

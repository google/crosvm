// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(all(unix, target_arch = "x86_64"))]

use std::arch::x86_64::CpuidResult;
use std::arch::x86_64::__cpuid;
use std::arch::x86_64::__cpuid_count;

use hypervisor::CpuConfigX86_64;
use x86_64::cpuid::filter_cpuid;
use x86_64::cpuid::EBX_CLFLUSH_CACHELINE;
use x86_64::cpuid::EBX_CLFLUSH_SIZE_SHIFT;
use x86_64::cpuid::EBX_CPUID_SHIFT;
use x86_64::cpuid::EBX_CPU_COUNT_SHIFT;
use x86_64::cpuid::ECX_HYPERVISOR_SHIFT;
use x86_64::cpuid::EDX_HTT_SHIFT;
use x86_64::CpuIdContext;

#[test]
fn feature_and_vendor_name() {
    let mut cpuid = hypervisor::CpuId::new(2);
    let guest_mem = vm_memory::GuestMemory::new(&[(vm_memory::GuestAddress(0), 0x10000)]).unwrap();
    let kvm = hypervisor::kvm::Kvm::new().unwrap();
    let vm = hypervisor::kvm::KvmVm::new(&kvm, guest_mem, Default::default()).unwrap();
    let irq_chip = devices::KvmKernelIrqChip::new(vm, 1).unwrap();

    let entries = &mut cpuid.cpu_id_entries;
    entries.push(hypervisor::CpuIdEntry {
        function: 0,
        index: 0,
        flags: 0,
        cpuid: CpuidResult {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        },
    });
    entries.push(hypervisor::CpuIdEntry {
        function: 1,
        index: 0,
        flags: 0,
        cpuid: CpuidResult {
            eax: 0,
            ebx: 0,
            ecx: 0x10,
            edx: 0,
        },
    });

    let cpu_config = CpuConfigX86_64::new(false, false, false, false, false, None);
    filter_cpuid(
        &mut cpuid,
        &CpuIdContext::new(
            1,
            2,
            Some(&irq_chip),
            cpu_config,
            false,
            __cpuid_count,
            __cpuid,
        ),
    );

    let entries = &mut cpuid.cpu_id_entries;
    assert_eq!(entries[0].function, 0);
    assert_eq!(1, (entries[1].cpuid.ebx >> EBX_CPUID_SHIFT) & 0x000000ff);
    assert_eq!(
        2,
        (entries[1].cpuid.ebx >> EBX_CPU_COUNT_SHIFT) & 0x000000ff
    );
    assert_eq!(
        EBX_CLFLUSH_CACHELINE,
        (entries[1].cpuid.ebx >> EBX_CLFLUSH_SIZE_SHIFT) & 0x000000ff
    );
    assert_ne!(0, entries[1].cpuid.ecx & (1 << ECX_HYPERVISOR_SHIFT));
    assert_ne!(0, entries[1].cpuid.edx & (1 << EDX_HTT_SHIFT));
}

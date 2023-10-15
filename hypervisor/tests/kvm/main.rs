// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(any(target_os = "android", target_os = "linux"))]

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
mod aarch64;

#[cfg(target_arch = "x86_64")]
mod x86_64;

use std::thread;

use base::pagesize;
use base::Event;
use base::FromRawDescriptor;
use base::MappedRegion;
use base::MemoryMappingArena;
use base::MemoryMappingBuilder;
use hypervisor::kvm::dirty_log_bitmap_size;
use hypervisor::kvm::Kvm;
use hypervisor::kvm::KvmVm;
use hypervisor::Datamatch;
use hypervisor::Hypervisor;
use hypervisor::HypervisorCap;
use hypervisor::IoEventAddress;
use hypervisor::Vm;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use hypervisor::VmAArch64;
#[cfg(target_arch = "riscv64")]
use hypervisor::VmRiscv64;
#[cfg(target_arch = "x86_64")]
use hypervisor::VmX86_64;
use kvm::Cap;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

#[test]
fn dirty_log_size() {
    let page_size = pagesize();
    assert_eq!(dirty_log_bitmap_size(0), 0);
    assert_eq!(dirty_log_bitmap_size(page_size), 1);
    assert_eq!(dirty_log_bitmap_size(page_size * 8), 1);
    assert_eq!(dirty_log_bitmap_size(page_size * 8 + 1), 2);
    assert_eq!(dirty_log_bitmap_size(page_size * 100), 13);
}

#[test]
fn new() {
    Kvm::new().unwrap();
}

#[test]
fn check_capability() {
    let kvm = Kvm::new().unwrap();
    assert!(kvm.check_capability(HypervisorCap::UserMemory));
    assert!(!kvm.check_capability(HypervisorCap::S390UserSigp));
}

#[test]
fn create_vm() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), pagesize() as u64)]).unwrap();
    KvmVm::new(&kvm, gm, Default::default()).unwrap();
}

#[test]
fn clone_vm() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), pagesize() as u64)]).unwrap();
    let vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    vm.try_clone().unwrap();
}

#[test]
fn send_vm() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), pagesize() as u64)]).unwrap();
    let vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    thread::spawn(move || {
        let _vm = vm;
    })
    .join()
    .unwrap();
}

#[test]
fn check_vm_capability() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), pagesize() as u64)]).unwrap();
    let vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    assert!(vm.check_raw_capability(Cap::UserMemory));
    // I assume nobody is testing this on s390
    assert!(!vm.check_raw_capability(Cap::S390UserSigp));
}

#[test]
fn create_vcpu() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    vm.create_vcpu(0).unwrap();
}

#[test]
fn get_memory() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), pagesize() as u64)]).unwrap();
    let vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    let obj_addr = GuestAddress(0xf0);
    vm.get_memory().write_obj_at_addr(67u8, obj_addr).unwrap();
    let read_val: u8 = vm.get_memory().read_obj_from_addr(obj_addr).unwrap();
    assert_eq!(read_val, 67u8);
}

#[test]
fn add_memory() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[
        (GuestAddress(0), pagesize() as u64),
        (GuestAddress(pagesize() as u64 * 5), pagesize() as u64 * 5),
    ])
    .unwrap();
    let mut vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    let mem_size = 0x1000;
    let mem = MemoryMappingBuilder::new(mem_size).build().unwrap();
    vm.add_memory_region(GuestAddress(pagesize() as u64), Box::new(mem), false, false)
        .unwrap();
    let mem = MemoryMappingBuilder::new(mem_size).build().unwrap();
    vm.add_memory_region(
        GuestAddress(0x10 * pagesize() as u64),
        Box::new(mem),
        false,
        false,
    )
    .unwrap();
}

#[test]
fn add_memory_ro() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), pagesize() as u64)]).unwrap();
    let mut vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    let mem_size = 0x1000;
    let mem = MemoryMappingBuilder::new(mem_size).build().unwrap();
    vm.add_memory_region(GuestAddress(pagesize() as u64), Box::new(mem), true, false)
        .unwrap();
}

#[test]
fn remove_memory() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), pagesize() as u64)]).unwrap();
    let mut vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    let mem_size = 0x1000;
    let mem = MemoryMappingBuilder::new(mem_size).build().unwrap();
    let mem_ptr = mem.as_ptr();
    let slot = vm
        .add_memory_region(GuestAddress(pagesize() as u64), Box::new(mem), false, false)
        .unwrap();
    let removed_mem = vm.remove_memory_region(slot).unwrap();
    assert_eq!(removed_mem.size(), mem_size);
    assert_eq!(removed_mem.as_ptr(), mem_ptr);
}

#[test]
fn remove_invalid_memory() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), pagesize() as u64)]).unwrap();
    let mut vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    assert!(vm.remove_memory_region(0).is_err());
}

#[test]
fn overlap_memory() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10 * pagesize() as u64)]).unwrap();
    let mut vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    let mem_size = 2 * pagesize();
    let mem = MemoryMappingBuilder::new(mem_size).build().unwrap();
    assert!(vm
        .add_memory_region(
            GuestAddress(2 * pagesize() as u64),
            Box::new(mem),
            false,
            false
        )
        .is_err());
}

#[test]
fn sync_memory() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[
        (GuestAddress(0), pagesize() as u64),
        (GuestAddress(5 * pagesize() as u64), 5 * pagesize() as u64),
    ])
    .unwrap();
    let mut vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    let mem_size = pagesize();
    let mem = MemoryMappingArena::new(mem_size).unwrap();
    let slot = vm
        .add_memory_region(GuestAddress(pagesize() as u64), Box::new(mem), false, false)
        .unwrap();
    vm.msync_memory_region(slot, mem_size, 0).unwrap();
    assert!(vm.msync_memory_region(slot, mem_size + 1, 0).is_err());
    assert!(vm.msync_memory_region(slot + 1, mem_size, 0).is_err());
}

#[test]
fn register_irqfd() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), pagesize() as u64)]).unwrap();
    let vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    let evtfd1 = Event::new().unwrap();
    let evtfd2 = Event::new().unwrap();
    let evtfd3 = Event::new().unwrap();
    vm.create_irq_chip().unwrap();
    vm.register_irqfd(4, &evtfd1, None).unwrap();
    vm.register_irqfd(8, &evtfd2, None).unwrap();
    vm.register_irqfd(4, &evtfd3, None).unwrap();
    vm.register_irqfd(4, &evtfd3, None).unwrap_err();
}

#[test]
fn unregister_irqfd() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), pagesize() as u64)]).unwrap();
    let vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    let evtfd1 = Event::new().unwrap();
    let evtfd2 = Event::new().unwrap();
    let evtfd3 = Event::new().unwrap();
    vm.create_irq_chip().unwrap();
    vm.register_irqfd(4, &evtfd1, None).unwrap();
    vm.register_irqfd(8, &evtfd2, None).unwrap();
    vm.register_irqfd(4, &evtfd3, None).unwrap();
    vm.unregister_irqfd(4, &evtfd1).unwrap();
    vm.unregister_irqfd(8, &evtfd2).unwrap();
    vm.unregister_irqfd(4, &evtfd3).unwrap();
}

#[test]
fn irqfd_resample() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), pagesize() as u64)]).unwrap();
    let vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    let evtfd1 = Event::new().unwrap();
    let evtfd2 = Event::new().unwrap();
    vm.create_irq_chip().unwrap();
    vm.register_irqfd(4, &evtfd1, Some(&evtfd2)).unwrap();
    vm.unregister_irqfd(4, &evtfd1).unwrap();
    // Ensures the ioctl is actually reading the resamplefd.
    vm.register_irqfd(4, &evtfd1, Some(unsafe { &Event::from_raw_descriptor(-1) }))
        .unwrap_err();
}

#[test]
fn vcpu_mmap_size() {
    let kvm = Kvm::new().unwrap();
    let mmap_size = kvm.get_vcpu_mmap_size().unwrap();
    let page_size = pagesize();
    assert!(mmap_size >= page_size);
    assert!(mmap_size % page_size == 0);
}

#[test]
fn register_ioevent() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), pagesize() as u64)]).unwrap();
    let mut vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    let evtfd = Event::new().unwrap();
    vm.register_ioevent(&evtfd, IoEventAddress::Pio(0xf4), Datamatch::AnyLength)
        .unwrap();
    vm.register_ioevent(&evtfd, IoEventAddress::Mmio(0x1000), Datamatch::AnyLength)
        .unwrap();
    vm.register_ioevent(
        &evtfd,
        IoEventAddress::Pio(0xc1),
        Datamatch::U8(Some(0x7fu8)),
    )
    .unwrap();
    vm.register_ioevent(
        &evtfd,
        IoEventAddress::Pio(0xc2),
        Datamatch::U16(Some(0x1337u16)),
    )
    .unwrap();
    vm.register_ioevent(
        &evtfd,
        IoEventAddress::Pio(0xc4),
        Datamatch::U32(Some(0xdeadbeefu32)),
    )
    .unwrap();
    vm.register_ioevent(
        &evtfd,
        IoEventAddress::Pio(0xc8),
        Datamatch::U64(Some(0xdeadbeefdeadbeefu64)),
    )
    .unwrap();
}

#[test]
fn unregister_ioevent() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), pagesize() as u64)]).unwrap();
    let mut vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    let evtfd = Event::new().unwrap();
    vm.register_ioevent(&evtfd, IoEventAddress::Pio(0xf4), Datamatch::AnyLength)
        .unwrap();
    vm.register_ioevent(&evtfd, IoEventAddress::Mmio(0x1000), Datamatch::AnyLength)
        .unwrap();
    vm.register_ioevent(
        &evtfd,
        IoEventAddress::Mmio(0x1004),
        Datamatch::U8(Some(0x7fu8)),
    )
    .unwrap();
    vm.unregister_ioevent(&evtfd, IoEventAddress::Pio(0xf4), Datamatch::AnyLength)
        .unwrap();
    vm.unregister_ioevent(&evtfd, IoEventAddress::Mmio(0x1000), Datamatch::AnyLength)
        .unwrap();
    vm.unregister_ioevent(
        &evtfd,
        IoEventAddress::Mmio(0x1004),
        Datamatch::U8(Some(0x7fu8)),
    )
    .unwrap();
}

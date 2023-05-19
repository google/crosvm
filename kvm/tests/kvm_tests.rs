// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(unix)]

use base::pagesize;
use base::Event;
#[cfg(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "arm",
    target_arch = "aarch64"
))]
use base::FromRawDescriptor;
use base::MappedRegion;
use base::MemoryMappingBuilder;
use base::SIGRTMIN;
use kvm::dirty_log_bitmap_size;
use kvm::Cap;
use kvm::Datamatch;
use kvm::IoeventAddress;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use kvm::IrqRoute;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use kvm::IrqSource;
use kvm::Kvm;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use kvm::PicId;
use kvm::Vcpu;
use kvm::Vm;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use kvm_sys::kvm_enable_cap;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use kvm_sys::kvm_msr_entry;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use kvm_sys::KVM_CAP_HYPERV_SYNIC;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use kvm_sys::KVM_IRQCHIP_IOAPIC;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use libc::EINVAL;
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
fn create_vm() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();
    Vm::new(&kvm, gm).unwrap();
}

#[test]
fn check_extension() {
    let kvm = Kvm::new().unwrap();
    assert!(kvm.check_extension(Cap::UserMemory));
    // I assume nobody is testing this on s390
    assert!(!kvm.check_extension(Cap::S390UserSigp));
}

#[test]
fn check_vm_extension() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();
    let vm = Vm::new(&kvm, gm).unwrap();
    assert!(vm.check_extension(Cap::UserMemory));
    // I assume nobody is testing this on s390
    assert!(!vm.check_extension(Cap::S390UserSigp));
}

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn get_supported_cpuid() {
    let kvm = Kvm::new().unwrap();
    let mut cpuid = kvm.get_supported_cpuid().unwrap();
    let cpuid_entries = cpuid.mut_entries_slice();
    assert!(!cpuid_entries.is_empty());
}

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn get_emulated_cpuid() {
    let kvm = Kvm::new().unwrap();
    kvm.get_emulated_cpuid().unwrap();
}

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn get_msr_index_list() {
    let kvm = Kvm::new().unwrap();
    let msr_list = kvm.get_msr_index_list().unwrap();
    assert!(msr_list.len() >= 2);
}

#[test]
fn add_memory() {
    let kvm = Kvm::new().unwrap();
    let gm =
        GuestMemory::new(&[(GuestAddress(0), 0x1000), (GuestAddress(0x5000), 0x5000)]).unwrap();
    let mut vm = Vm::new(&kvm, gm).unwrap();
    let mem_size = 0x1000;
    let mem = MemoryMappingBuilder::new(mem_size).build().unwrap();
    vm.add_memory_region(GuestAddress(0x1000), Box::new(mem), false, false)
        .unwrap();
    let mem = MemoryMappingBuilder::new(mem_size).build().unwrap();
    vm.add_memory_region(GuestAddress(0x10000), Box::new(mem), false, false)
        .unwrap();
}

#[test]
fn add_memory_ro() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();
    let mut vm = Vm::new(&kvm, gm).unwrap();
    let mem_size = 0x1000;
    let mem = MemoryMappingBuilder::new(mem_size).build().unwrap();
    vm.add_memory_region(GuestAddress(0x1000), Box::new(mem), true, false)
        .unwrap();
}

#[test]
fn remove_memory_region() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();
    let mut vm = Vm::new(&kvm, gm).unwrap();
    let mem_size = 0x1000;
    let mem = MemoryMappingBuilder::new(mem_size).build().unwrap();
    let mem_ptr = mem.as_ptr();
    let slot = vm
        .add_memory_region(GuestAddress(0x1000), Box::new(mem), false, false)
        .unwrap();
    let removed_mem = vm.remove_memory_region(slot).unwrap();
    assert_eq!(removed_mem.size(), mem_size);
    assert_eq!(removed_mem.as_ptr(), mem_ptr);
}

#[test]
fn remove_invalid_memory() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();
    let mut vm = Vm::new(&kvm, gm).unwrap();
    assert!(vm.remove_memory_region(0).is_err());
}

#[test]
fn overlap_memory() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let mut vm = Vm::new(&kvm, gm).unwrap();
    let mem_size = 0x2000;
    let mem = MemoryMappingBuilder::new(mem_size).build().unwrap();
    assert!(vm
        .add_memory_region(GuestAddress(0x2000), Box::new(mem), false, false)
        .is_err());
}

#[test]
fn get_memory() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();
    let vm = Vm::new(&kvm, gm).unwrap();
    let obj_addr = GuestAddress(0xf0);
    vm.get_memory().write_obj_at_addr(67u8, obj_addr).unwrap();
    let read_val: u8 = vm.get_memory().read_obj_from_addr(obj_addr).unwrap();
    assert_eq!(read_val, 67u8);
}

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn clock_handling() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = Vm::new(&kvm, gm).unwrap();
    let mut clock_data = vm.get_clock().unwrap();
    clock_data.clock += 1000;
    vm.set_clock(&clock_data).unwrap();
}

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn pic_handling() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = Vm::new(&kvm, gm).unwrap();
    vm.create_irq_chip().unwrap();
    let pic_state = vm.get_pic_state(PicId::Secondary).unwrap();
    vm.set_pic_state(PicId::Secondary, &pic_state).unwrap();
}

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn ioapic_handling() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = Vm::new(&kvm, gm).unwrap();
    vm.create_irq_chip().unwrap();
    let ioapic_state = vm.get_ioapic_state().unwrap();
    vm.set_ioapic_state(&ioapic_state).unwrap();
}

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn pit_handling() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = Vm::new(&kvm, gm).unwrap();
    vm.create_irq_chip().unwrap();
    vm.create_pit().unwrap();
    let pit_state = vm.get_pit_state().unwrap();
    vm.set_pit_state(&pit_state).unwrap();
}

#[test]
fn register_ioevent() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = Vm::new(&kvm, gm).unwrap();
    let evtfd = Event::new().unwrap();
    vm.register_ioevent(&evtfd, IoeventAddress::Pio(0xf4), Datamatch::AnyLength)
        .unwrap();
    vm.register_ioevent(&evtfd, IoeventAddress::Mmio(0x1000), Datamatch::AnyLength)
        .unwrap();
    vm.register_ioevent(
        &evtfd,
        IoeventAddress::Pio(0xc1),
        Datamatch::U8(Some(0x7fu8)),
    )
    .unwrap();
    vm.register_ioevent(
        &evtfd,
        IoeventAddress::Pio(0xc2),
        Datamatch::U16(Some(0x1337u16)),
    )
    .unwrap();
    vm.register_ioevent(
        &evtfd,
        IoeventAddress::Pio(0xc4),
        Datamatch::U32(Some(0xdeadbeefu32)),
    )
    .unwrap();
    vm.register_ioevent(
        &evtfd,
        IoeventAddress::Pio(0xc8),
        Datamatch::U64(Some(0xdeadbeefdeadbeefu64)),
    )
    .unwrap();
}

#[test]
fn unregister_ioevent() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = Vm::new(&kvm, gm).unwrap();
    let evtfd = Event::new().unwrap();
    vm.register_ioevent(&evtfd, IoeventAddress::Pio(0xf4), Datamatch::AnyLength)
        .unwrap();
    vm.register_ioevent(&evtfd, IoeventAddress::Mmio(0x1000), Datamatch::AnyLength)
        .unwrap();
    vm.register_ioevent(
        &evtfd,
        IoeventAddress::Mmio(0x1004),
        Datamatch::U8(Some(0x7fu8)),
    )
    .unwrap();
    vm.unregister_ioevent(&evtfd, IoeventAddress::Pio(0xf4), Datamatch::AnyLength)
        .unwrap();
    vm.unregister_ioevent(&evtfd, IoeventAddress::Mmio(0x1000), Datamatch::AnyLength)
        .unwrap();
    vm.unregister_ioevent(
        &evtfd,
        IoeventAddress::Mmio(0x1004),
        Datamatch::U8(Some(0x7fu8)),
    )
    .unwrap();
}

#[test]
#[cfg(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "arm",
    target_arch = "aarch64"
))]
fn irqfd_resample() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = Vm::new(&kvm, gm).unwrap();
    let evtfd1 = Event::new().unwrap();
    let evtfd2 = Event::new().unwrap();
    vm.create_irq_chip().unwrap();
    vm.register_irqfd_resample(&evtfd1, &evtfd2, 4).unwrap();
    vm.unregister_irqfd(&evtfd1, 4).unwrap();
    // Ensures the ioctl is actually reading the resamplefd.
    vm.register_irqfd_resample(&evtfd1, unsafe { &Event::from_raw_descriptor(-1) }, 4)
        .unwrap_err();
}

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn set_gsi_routing() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = Vm::new(&kvm, gm).unwrap();
    vm.create_irq_chip().unwrap();
    vm.set_gsi_routing(&[]).unwrap();
    vm.set_gsi_routing(&[IrqRoute {
        gsi: 1,
        source: IrqSource::Irqchip {
            chip: KVM_IRQCHIP_IOAPIC,
            pin: 3,
        },
    }])
    .unwrap();
    vm.set_gsi_routing(&[IrqRoute {
        gsi: 1,
        source: IrqSource::Msi {
            address: 0xf000000,
            data: 0xa0,
        },
    }])
    .unwrap();
    vm.set_gsi_routing(&[
        IrqRoute {
            gsi: 1,
            source: IrqSource::Irqchip {
                chip: KVM_IRQCHIP_IOAPIC,
                pin: 3,
            },
        },
        IrqRoute {
            gsi: 2,
            source: IrqSource::Msi {
                address: 0xf000000,
                data: 0xa0,
            },
        },
    ])
    .unwrap();
}

#[test]
fn create_vcpu() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = Vm::new(&kvm, gm).unwrap();
    Vcpu::new(0, &kvm, &vm).unwrap();
}

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn debugregs() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = Vm::new(&kvm, gm).unwrap();
    let vcpu = Vcpu::new(0, &kvm, &vm).unwrap();
    let mut dregs = vcpu.get_debugregs().unwrap();
    dregs.dr7 = 13;
    vcpu.set_debugregs(&dregs).unwrap();
    let dregs2 = vcpu.get_debugregs().unwrap();
    assert_eq!(dregs.dr7, dregs2.dr7);
}

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn xcrs() {
    let kvm = Kvm::new().unwrap();
    if !kvm.check_extension(Cap::Xcrs) {
        return;
    }

    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = Vm::new(&kvm, gm).unwrap();
    let vcpu = Vcpu::new(0, &kvm, &vm).unwrap();
    let mut xcrs = vcpu.get_xcrs().unwrap();
    xcrs.xcrs[0].value = 1;
    vcpu.set_xcrs(&xcrs).unwrap();
    let xcrs2 = vcpu.get_xcrs().unwrap();
    assert_eq!(xcrs.xcrs[0].value, xcrs2.xcrs[0].value);
}

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn get_msrs() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = Vm::new(&kvm, gm).unwrap();
    let vcpu = Vcpu::new(0, &kvm, &vm).unwrap();
    let mut msrs = vec![
        // This one should succeed
        kvm_msr_entry {
            index: 0x0000011e,
            ..Default::default()
        },
        // This one will fail to fetch
        kvm_msr_entry {
            index: 0xffffffff,
            ..Default::default()
        },
    ];
    vcpu.get_msrs(&mut msrs).unwrap();
    assert_eq!(msrs.len(), 1);
}

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn get_hyperv_cpuid() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = Vm::new(&kvm, gm).unwrap();
    let vcpu = Vcpu::new(0, &kvm, &vm).unwrap();
    let cpuid = vcpu.get_hyperv_cpuid();
    // Older kernels don't support so tolerate this kind of failure.
    match cpuid {
        Ok(_) => {}
        Err(e) => {
            assert_eq!(e.errno(), EINVAL);
        }
    }
}

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn enable_feature() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = Vm::new(&kvm, gm).unwrap();
    vm.create_irq_chip().unwrap();
    let vcpu = Vcpu::new(0, &kvm, &vm).unwrap();
    let cap: kvm_enable_cap = kvm_sys::kvm_enable_cap {
        cap: KVM_CAP_HYPERV_SYNIC,
        ..Default::default()
    };
    unsafe { vcpu.kvm_enable_cap(&cap) }.unwrap();
}

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn mp_state() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = Vm::new(&kvm, gm).unwrap();
    vm.create_irq_chip().unwrap();
    let vcpu = Vcpu::new(0, &kvm, &vm).unwrap();
    let state = vcpu.get_mp_state().unwrap();
    vcpu.set_mp_state(&state).unwrap();
}

#[test]
fn set_signal_mask() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = Vm::new(&kvm, gm).unwrap();
    let vcpu = Vcpu::new(0, &kvm, &vm).unwrap();
    vcpu.set_signal_mask(&[SIGRTMIN() + 0]).unwrap();
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
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn set_identity_map_addr() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = Vm::new(&kvm, gm).unwrap();
    vm.set_identity_map_addr(GuestAddress(0x20000)).unwrap();
}

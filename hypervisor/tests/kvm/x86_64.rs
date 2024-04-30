// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use hypervisor::kvm::get_cpuid_with_initial_capacity;
use hypervisor::kvm::Kvm;
use hypervisor::kvm::KvmVcpu;
use hypervisor::kvm::KvmVm;
use hypervisor::DeliveryMode;
use hypervisor::DeliveryStatus;
use hypervisor::DestinationMode;
use hypervisor::Fpu;
use hypervisor::Hypervisor;
use hypervisor::HypervisorCap;
use hypervisor::HypervisorX86_64;
use hypervisor::IoapicRedirectionTableEntry;
use hypervisor::IoapicState;
use hypervisor::IrqRoute;
use hypervisor::IrqSource;
use hypervisor::IrqSourceChip;
use hypervisor::LapicState;
use hypervisor::PicInitState;
use hypervisor::PicState;
use hypervisor::PitChannelState;
use hypervisor::PitRWMode;
use hypervisor::PitRWState;
use hypervisor::PitState;
use hypervisor::TriggerMode;
use hypervisor::Vm;
use hypervisor::VmCap;
use hypervisor::VmX86_64;
use kvm_sys::*;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

#[test]
fn get_supported_cpuid() {
    let hypervisor = Kvm::new().unwrap();
    let cpuid = hypervisor.get_supported_cpuid().unwrap();
    assert!(!cpuid.cpu_id_entries.is_empty());
}

#[test]
fn get_emulated_cpuid() {
    let hypervisor = Kvm::new().unwrap();
    let cpuid = hypervisor.get_emulated_cpuid().unwrap();
    assert!(!cpuid.cpu_id_entries.is_empty());
}

#[test]
fn get_msr_index_list() {
    let kvm = Kvm::new().unwrap();
    let msr_list = kvm.get_msr_index_list().unwrap();
    assert!(msr_list.len() >= 2);
}

#[test]
fn entries_double_on_error() {
    let hypervisor = Kvm::new().unwrap();
    let cpuid = get_cpuid_with_initial_capacity(&hypervisor, KVM_GET_SUPPORTED_CPUID(), 4).unwrap();
    assert!(cpuid.cpu_id_entries.len() > 4);
}

#[test]
fn check_vm_arch_capability() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();
    let vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    assert!(vm.check_capability(VmCap::PvClock));
}

#[test]
fn pic_state() {
    let state = PicState {
        last_irr: 0b00000001,
        irr: 0b00000010,
        imr: 0b00000100,
        isr: 0b00001000,
        priority_add: 0b00010000,
        irq_base: 0b00100000,
        read_reg_select: false,
        poll: true,
        special_mask: true,
        init_state: PicInitState::Icw3,
        auto_eoi: true,
        rotate_on_auto_eoi: false,
        special_fully_nested_mode: true,
        use_4_byte_icw: true,
        elcr: 0b01000000,
        elcr_mask: 0b10000000,
    };

    let kvm_state = kvm_pic_state::from(&state);

    assert_eq!(kvm_state.last_irr, 0b00000001);
    assert_eq!(kvm_state.irr, 0b00000010);
    assert_eq!(kvm_state.imr, 0b00000100);
    assert_eq!(kvm_state.isr, 0b00001000);
    assert_eq!(kvm_state.priority_add, 0b00010000);
    assert_eq!(kvm_state.irq_base, 0b00100000);
    assert_eq!(kvm_state.read_reg_select, 0);
    assert_eq!(kvm_state.poll, 1);
    assert_eq!(kvm_state.special_mask, 1);
    assert_eq!(kvm_state.init_state, 0b10);
    assert_eq!(kvm_state.auto_eoi, 1);
    assert_eq!(kvm_state.rotate_on_auto_eoi, 0);
    assert_eq!(kvm_state.special_fully_nested_mode, 1);
    assert_eq!(kvm_state.auto_eoi, 1);
    assert_eq!(kvm_state.elcr, 0b01000000);
    assert_eq!(kvm_state.elcr_mask, 0b10000000);

    let orig_state = PicState::from(&kvm_state);
    assert_eq!(state, orig_state);
}

#[test]
fn ioapic_state() {
    let mut entry = IoapicRedirectionTableEntry::default();
    let noredir = IoapicRedirectionTableEntry::default();

    // default entry should be 0
    assert_eq!(entry.get(0, 64), 0);

    // set some values on our entry
    entry.set_vector(0b11111111);
    entry.set_delivery_mode(DeliveryMode::SMI);
    entry.set_dest_mode(DestinationMode::Physical);
    entry.set_delivery_status(DeliveryStatus::Pending);
    entry.set_polarity(1);
    entry.set_remote_irr(true);
    entry.set_trigger_mode(TriggerMode::Level);
    entry.set_interrupt_mask(true);
    entry.set_dest_id(0b10101010);

    // Bit repr as:  destid-reserved--------------------------------flags----vector--
    let bit_repr = 0b1010101000000000000000000000000000000000000000011111001011111111;
    // where flags is [interrupt_mask(1), trigger_mode(Level=1), remote_irr(1), polarity(1),
    //   delivery_status(Pending=1), dest_mode(Physical=0), delivery_mode(SMI=010)]

    assert_eq!(entry.get(0, 64), bit_repr);

    let mut state = IoapicState {
        base_address: 1,
        ioregsel: 2,
        ioapicid: 4,
        current_interrupt_level_bitmap: 8,
        redirect_table: [noredir; 24],
    };

    // Initialize first 24 (kvm_state limit) redirection entries
    for i in 0..24 {
        state.redirect_table[i] = entry;
    }

    let kvm_state = kvm_ioapic_state::from(&state);
    assert_eq!(kvm_state.base_address, 1);
    assert_eq!(kvm_state.ioregsel, 2);
    assert_eq!(kvm_state.id, 4);
    assert_eq!(kvm_state.irr, 8);
    assert_eq!(kvm_state.pad, 0);
    // check first 24 entries
    for i in 0..24 {
        assert_eq!(
            {
                // SAFETY: trivially safe
                unsafe { kvm_state.redirtbl[i].bits }
            },
            bit_repr
        );
    }

    // compare with a conversion back
    assert_eq!(state, IoapicState::from(&kvm_state));
}

#[test]
fn lapic_state() {
    let mut state = LapicState { regs: [0; 64] };
    // Apic id register, 4 bytes each with a different bit set
    state.regs[2] = 1 | 2 << 8 | 4 << 16 | 8 << 24;

    let kvm_state = kvm_lapic_state::from(&state);

    // check little endian bytes in kvm_state
    for i in 0..4 {
        assert_eq!(kvm_state.regs[32 + i] as u8, 2u8.pow(i as u32));
    }

    // Test converting back to a LapicState
    assert_eq!(state, LapicState::from(&kvm_state));
}

#[test]
fn pit_state() {
    let channel = PitChannelState {
        count: 256,
        latched_count: 512,
        count_latched: PitRWState::LSB,
        status_latched: false,
        status: 7,
        read_state: PitRWState::MSB,
        write_state: PitRWState::Word1,
        reload_value: 8,
        rw_mode: PitRWMode::Both,
        mode: 5,
        bcd: false,
        gate: true,
        count_load_time: 1024,
    };

    let kvm_channel = kvm_pit_channel_state::from(&channel);

    // compare the various field translations
    assert_eq!(kvm_channel.count, 256);
    assert_eq!(kvm_channel.latched_count, 512);
    assert_eq!(kvm_channel.count_latched, 1);
    assert_eq!(kvm_channel.status_latched, 0);
    assert_eq!(kvm_channel.status, 7);
    assert_eq!(kvm_channel.read_state, 2);
    assert_eq!(kvm_channel.write_state, 4);
    assert_eq!(kvm_channel.write_latch, 8);
    assert_eq!(kvm_channel.rw_mode, 3);
    assert_eq!(kvm_channel.mode, 5);
    assert_eq!(kvm_channel.bcd, 0);
    assert_eq!(kvm_channel.gate, 1);
    assert_eq!(kvm_channel.count_load_time, 1024);

    // convert back and compare
    assert_eq!(channel, PitChannelState::from(&kvm_channel));

    // convert the full pitstate
    let state = PitState {
        channels: [channel, channel, channel],
        flags: 255,
    };
    let kvm_state = kvm_pit_state2::from(&state);

    assert_eq!(kvm_state.flags, 255);

    // compare a channel
    assert_eq!(channel, PitChannelState::from(&kvm_state.channels[0]));
    // convert back and compare
    assert_eq!(state, PitState::from(&kvm_state));
}

#[test]
fn clock_handling() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    let mut clock_data = vm.get_pvclock().unwrap();
    clock_data.clock += 1000;
    vm.set_pvclock(&clock_data).unwrap();
}

#[test]
fn set_gsi_routing() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    vm.create_irq_chip().unwrap();
    vm.set_gsi_routing(&[]).unwrap();
    vm.set_gsi_routing(&[IrqRoute {
        gsi: 1,
        source: IrqSource::Irqchip {
            chip: IrqSourceChip::Ioapic,
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
                chip: IrqSourceChip::Ioapic,
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
fn set_identity_map_addr() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    vm.set_identity_map_addr(GuestAddress(0x20000)).unwrap();
}

#[test]
fn mp_state() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    vm.create_irq_chip().unwrap();
    let vcpu: KvmVcpu = vm.create_kvm_vcpu(0).unwrap();
    let state = vcpu.get_mp_state().unwrap();
    vcpu.set_mp_state(&state).unwrap();
}

#[test]
fn enable_feature() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    vm.create_irq_chip().unwrap();
    let vcpu = vm.create_vcpu(0).unwrap();
    // SAFETY: trivially safe
    unsafe { vcpu.enable_raw_capability(kvm_sys::KVM_CAP_HYPERV_SYNIC, &[0; 4]) }.unwrap();
}

#[test]
fn from_fpu() {
    // Fpu has the largest arrays in our struct adapters.  Test that they're small enough for
    // Rust to copy.
    let mut fpu: Fpu = Default::default();
    let m = fpu.xmm.len();
    let n = fpu.xmm[0].len();
    fpu.xmm[m - 1][n - 1] = 42;

    let fpu = kvm_fpu::from(&fpu);
    assert_eq!(fpu.xmm.len(), m);
    assert_eq!(fpu.xmm[0].len(), n);
    assert_eq!(fpu.xmm[m - 1][n - 1], 42);
}

#[test]
fn debugregs() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    let vcpu = vm.create_vcpu(0).unwrap();
    let mut dregs = vcpu.get_debugregs().unwrap();
    dregs.dr7 = 13;
    vcpu.set_debugregs(&dregs).unwrap();
    let dregs2 = vcpu.get_debugregs().unwrap();
    assert_eq!(dregs.dr7, dregs2.dr7);
}

#[test]
fn xcrs() {
    let kvm = Kvm::new().unwrap();
    if !kvm.check_capability(HypervisorCap::Xcrs) {
        return;
    }

    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    let vcpu = vm.create_vcpu(0).unwrap();
    vcpu.set_xcr(0, 1).unwrap();
    let xcrs = vcpu.get_xcrs().unwrap();
    let xcr0 = xcrs.get(&0).unwrap();
    assert_eq!(*xcr0, 1);
}

#[test]
fn get_msr() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    let vcpu = vm.create_vcpu(0).unwrap();

    // This one should succeed
    let _value = vcpu.get_msr(0x0000011e).unwrap();

    // This one will fail to fetch
    vcpu.get_msr(0xffffffff)
        .expect_err("invalid MSR index should fail");
}

#[test]
fn set_msr() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    let vcpu = vm.create_vcpu(0).unwrap();

    const MSR_TSC_AUX: u32 = 0xc0000103;
    vcpu.set_msr(MSR_TSC_AUX, 42).unwrap();
    let msr_tsc_aux = vcpu.get_msr(MSR_TSC_AUX).unwrap();
    assert_eq!(msr_tsc_aux, 42);
}

#[test]
fn set_msr_unsupported() {
    let kvm = Kvm::new().unwrap();
    let gm = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
    let vm = KvmVm::new(&kvm, gm, Default::default()).unwrap();
    let vcpu = vm.create_vcpu(0).unwrap();

    assert_eq!(
        vcpu.set_msr(u32::MAX, u64::MAX),
        Err(base::Error::new(libc::EPERM))
    );
}

// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(target_arch = "x86_64")]

use base::EventWaitResult;
use base::Tube;
use devices::Bus;
use devices::CrosvmDeviceId;
use devices::DeviceId;
use devices::IrqChip;
use devices::IrqChipX86_64;
use devices::IrqEdgeEvent;
use devices::IrqEventSource;
use devices::IrqLevelEvent;
use devices::KvmKernelIrqChip;
use devices::KvmSplitIrqChip;
use devices::IOAPIC_BASE_ADDRESS;
use hypervisor::kvm::Kvm;
use hypervisor::kvm::KvmVm;
use hypervisor::IoapicRedirectionTableEntry;
use hypervisor::IrqRoute;
use hypervisor::IrqSource;
use hypervisor::PicSelect;
use hypervisor::PitRWMode;
use hypervisor::TriggerMode;
use hypervisor::Vm;
use hypervisor::VmX86_64;
use resources::AddressRange;
use resources::SystemAllocator;
use resources::SystemAllocatorConfig;
use vm_memory::GuestMemory;

use crate::x86_64::test_get_ioapic;
use crate::x86_64::test_get_lapic;
use crate::x86_64::test_get_pic;
use crate::x86_64::test_get_pit;
use crate::x86_64::test_route_irq;
use crate::x86_64::test_set_ioapic;
use crate::x86_64::test_set_lapic;
use crate::x86_64::test_set_pic;
use crate::x86_64::test_set_pit;

/// Helper function for setting up a KvmKernelIrqChip
fn get_kernel_chip() -> KvmKernelIrqChip {
    let kvm = Kvm::new().expect("failed to instantiate Kvm");
    let mem = GuestMemory::new(&[]).unwrap();
    let vm = KvmVm::new(&kvm, mem, Default::default()).expect("failed tso instantiate vm");

    let mut chip = KvmKernelIrqChip::new(vm.try_clone().expect("failed to clone vm"), 1)
        .expect("failed to instantiate KvmKernelIrqChip");

    let vcpu = vm.create_vcpu(0).expect("failed to instantiate vcpu");
    chip.add_vcpu(0, vcpu.as_vcpu())
        .expect("failed to add vcpu");

    chip
}

/// Helper function for setting up a KvmSplitIrqChip
fn get_split_chip() -> KvmSplitIrqChip {
    let kvm = Kvm::new().expect("failed to instantiate Kvm");
    let mem = GuestMemory::new(&[]).unwrap();
    let vm = KvmVm::new(&kvm, mem, Default::default()).expect("failed tso instantiate vm");

    let (_, device_tube) = Tube::pair().expect("failed to create irq tube");

    let mut chip = KvmSplitIrqChip::new(
        vm.try_clone().expect("failed to clone vm"),
        1,
        device_tube,
        None,
    )
    .expect("failed to instantiate KvmKernelIrqChip");

    let vcpu = vm.create_vcpu(0).expect("failed to instantiate vcpu");
    chip.add_vcpu(0, vcpu.as_vcpu())
        .expect("failed to add vcpu");
    chip
}

#[test]
fn kernel_irqchip_pit_uses_speaker_port() {
    let chip = get_kernel_chip();
    assert!(!chip.pit_uses_speaker_port());
}

#[test]
fn kernel_irqchip_get_pic() {
    test_get_pic(get_kernel_chip());
}

#[test]
fn kernel_irqchip_set_pic() {
    test_set_pic(get_kernel_chip());
}

#[test]
fn kernel_irqchip_get_ioapic() {
    test_get_ioapic(get_kernel_chip());
}

#[test]
fn kernel_irqchip_set_ioapic() {
    test_set_ioapic(get_kernel_chip());
}

#[test]
fn kernel_irqchip_get_pit() {
    test_get_pit(get_kernel_chip());
}

#[test]
fn kernel_irqchip_set_pit() {
    test_set_pit(get_kernel_chip());
}

#[test]
fn kernel_irqchip_get_lapic() {
    test_get_lapic(get_kernel_chip())
}

#[test]
fn kernel_irqchip_set_lapic() {
    test_set_lapic(get_kernel_chip())
}

#[test]
fn kernel_irqchip_route_irq() {
    test_route_irq(get_kernel_chip());
}

#[test]
fn split_irqchip_get_pic() {
    test_get_pic(get_split_chip());
}

#[test]
fn split_irqchip_set_pic() {
    test_set_pic(get_split_chip());
}

#[test]
fn split_irqchip_get_ioapic() {
    test_get_ioapic(get_split_chip());
}

#[test]
fn split_irqchip_set_ioapic() {
    test_set_ioapic(get_split_chip());
}

#[test]
fn split_irqchip_get_pit() {
    test_get_pit(get_split_chip());
}

#[test]
fn split_irqchip_set_pit() {
    test_set_pit(get_split_chip());
}

#[test]
fn split_irqchip_route_irq() {
    test_route_irq(get_split_chip());
}

#[test]
fn split_irqchip_pit_uses_speaker_port() {
    let chip = get_split_chip();
    assert!(chip.pit_uses_speaker_port());
}

#[test]
fn split_irqchip_routes_conflict() {
    let mut chip = get_split_chip();
    chip.route_irq(IrqRoute {
        gsi: 5,
        source: IrqSource::Msi {
            address: 4276092928,
            data: 0,
        },
    })
    .expect("failed to set msi rout");
    // this second route should replace the first
    chip.route_irq(IrqRoute {
        gsi: 5,
        source: IrqSource::Msi {
            address: 4276092928,
            data: 32801,
        },
    })
    .expect("failed to set msi rout");
}

#[test]
fn irq_event_tokens() {
    let mut chip = get_split_chip();
    let tokens = chip
        .irq_event_tokens()
        .expect("could not get irq_event_tokens");

    // there should be one token on a fresh split irqchip, for the pit
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].1.device_name, "userspace PIT");

    // register another irq event
    let evt = IrqEdgeEvent::new().expect("failed to create event");
    let source = IrqEventSource {
        device_id: CrosvmDeviceId::Cmos.into(),
        queue_id: 0,
        device_name: "test".into(),
    };
    chip.register_edge_irq_event(6, &evt, source)
        .expect("failed to register irq event");

    let tokens = chip
        .irq_event_tokens()
        .expect("could not get irq_event_tokens");

    // now there should be two tokens
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0].1.device_name, "userspace PIT");
    assert_eq!(
        tokens[1].1.device_id,
        DeviceId::PlatformDeviceId(CrosvmDeviceId::Cmos)
    );
    assert_eq!(tokens[1].2, *evt.get_trigger());
}

#[test]
fn finalize_devices() {
    let mut chip = get_split_chip();

    let mmio_bus = Bus::new();
    let io_bus = Bus::new();
    let mut resources = SystemAllocator::new(
        SystemAllocatorConfig {
            io: Some(AddressRange {
                start: 0xc000,
                end: 0xffff,
            }),
            low_mmio: AddressRange {
                start: 0,
                end: 2047,
            },
            high_mmio: AddressRange {
                start: 0x1_0000_0000,
                end: 0x2_ffff_ffff,
            },
            platform_mmio: None,
            first_irq: 5,
        },
        None,
        &[],
    )
    .expect("failed to create SystemAllocator");

    // Set up a level-triggered interrupt line 1
    let evt = IrqLevelEvent::new().expect("failed to create event");

    let source = IrqEventSource {
        device_id: CrosvmDeviceId::Cmos.into(),
        device_name: "test".into(),
        queue_id: 0,
    };
    let evt_index = chip
        .register_level_irq_event(1, &evt, source)
        .expect("failed to register irq event")
        .expect("register_irq_event should not return None");

    // Once we finalize devices, the pic/pit/ioapic should be attached to io and mmio busses
    chip.finalize_devices(&mut resources, &io_bus, &mmio_bus)
        .expect("failed to finalize devices");

    // Should not be able to allocate an irq < 24 now
    assert!(resources.allocate_irq().expect("failed to allocate irq") >= 24);

    // set PIT counter 2 to "SquareWaveGen"(aka 3) mode and "Both" access mode
    io_bus.write(0x43, &[0b10110110]);

    let state = chip.get_pit().expect("failed to get pit state");
    assert_eq!(state.channels[2].mode, 3);
    assert_eq!(state.channels[2].rw_mode, PitRWMode::Both);

    // ICW1 0x11: Edge trigger, cascade mode, ICW4 needed.
    // ICW2 0x08: Interrupt vector base address 0x08.
    // ICW3 0xff: Value written does not matter.
    // ICW4 0x13: Special fully nested mode, auto EOI.
    io_bus.write(0x20, &[0x11]);
    io_bus.write(0x21, &[0x08]);
    io_bus.write(0x21, &[0xff]);
    io_bus.write(0x21, &[0x13]);

    let state = chip
        .get_pic_state(PicSelect::Primary)
        .expect("failed to get pic state");

    // auto eoi and special fully nested mode should be turned on
    assert!(state.auto_eoi);
    assert!(state.special_fully_nested_mode);

    // Need to write to the irq event before servicing it
    evt.trigger().expect("failed to write to event");

    // if we assert irq line one, and then get the resulting interrupt, an auto-eoi should
    // occur and cause the resample_event to be written to
    chip.service_irq_event(evt_index)
        .expect("failed to service irq");

    assert!(chip.interrupt_requested(0));
    assert_eq!(
        chip.get_external_interrupt(0)
            .expect("failed to get external interrupt"),
        // Vector is 9 because the interrupt vector base address is 0x08 and this is irq
        // line 1 and 8+1 = 9
        0x9
    );

    // Clone resample event because read_timeout() needs a mutable reference.
    let resample_evt = evt.get_resample().try_clone().unwrap();
    assert_eq!(
        resample_evt
            .wait_timeout(std::time::Duration::from_secs(1))
            .expect("failed to read_timeout"),
        EventWaitResult::Signaled
    );

    // setup a ioapic redirection table entry 14
    let mut entry = IoapicRedirectionTableEntry::default();
    entry.set_vector(44);

    let irq_14_offset = 0x10 + 14 * 2;
    mmio_bus.write(IOAPIC_BASE_ADDRESS, &[irq_14_offset]);
    mmio_bus.write(
        IOAPIC_BASE_ADDRESS + 0x10,
        &(entry.get(0, 32) as u32).to_ne_bytes(),
    );
    mmio_bus.write(IOAPIC_BASE_ADDRESS, &[irq_14_offset + 1]);
    mmio_bus.write(
        IOAPIC_BASE_ADDRESS + 0x10,
        &(entry.get(32, 32) as u32).to_ne_bytes(),
    );

    let state = chip.get_ioapic_state().expect("failed to get ioapic state");

    // redirection table entry 14 should have a vector of 44
    assert_eq!(state.redirect_table[14].get_vector(), 44);
}

#[test]
fn get_external_interrupt() {
    let mut chip = get_split_chip();
    assert!(!chip.interrupt_requested(0));

    chip.service_irq(0, true).expect("failed to service irq");
    assert!(chip.interrupt_requested(0));

    // Should return Some interrupt
    assert_eq!(
        chip.get_external_interrupt(0)
            .expect("failed to get external interrupt"),
        0,
    );

    // interrupt is not requested twice
    assert!(!chip.interrupt_requested(0));
}

#[test]
fn broadcast_eoi() {
    let mut chip = get_split_chip();

    let mmio_bus = Bus::new();
    let io_bus = Bus::new();
    let mut resources = SystemAllocator::new(
        SystemAllocatorConfig {
            io: Some(AddressRange {
                start: 0xc000,
                end: 0xffff,
            }),
            low_mmio: AddressRange {
                start: 0,
                end: 2047,
            },
            high_mmio: AddressRange {
                start: 0x1_0000_0000,
                end: 0x2_ffff_ffff,
            },
            platform_mmio: None,
            first_irq: 5,
        },
        None,
        &[],
    )
    .expect("failed to create SystemAllocator");

    let source = IrqEventSource {
        device_id: CrosvmDeviceId::Cmos.into(),
        device_name: "test".into(),
        queue_id: 0,
    };
    // setup an event and a resample event for irq line 1
    let evt = IrqLevelEvent::new().expect("failed to create event");

    chip.register_level_irq_event(1, &evt, source)
        .expect("failed to register_level_irq_event");

    // Once we finalize devices, the pic/pit/ioapic should be attached to io and mmio busses
    chip.finalize_devices(&mut resources, &io_bus, &mmio_bus)
        .expect("failed to finalize devices");

    // setup a ioapic redirection table entry 1 with a vector of 123
    let mut entry = IoapicRedirectionTableEntry::default();
    entry.set_vector(123);
    entry.set_trigger_mode(TriggerMode::Level);

    let irq_write_offset = 0x10 + 1 * 2;
    mmio_bus.write(IOAPIC_BASE_ADDRESS, &[irq_write_offset]);
    mmio_bus.write(
        IOAPIC_BASE_ADDRESS + 0x10,
        &(entry.get(0, 32) as u32).to_ne_bytes(),
    );
    mmio_bus.write(IOAPIC_BASE_ADDRESS, &[irq_write_offset + 1]);
    mmio_bus.write(
        IOAPIC_BASE_ADDRESS + 0x10,
        &(entry.get(32, 32) as u32).to_ne_bytes(),
    );

    // Assert line 1
    chip.service_irq(1, true).expect("failed to service irq");

    // resample event should not be written to
    assert_eq!(
        evt.get_resample()
            .wait_timeout(std::time::Duration::from_millis(10))
            .expect("failed to read_timeout"),
        EventWaitResult::TimedOut
    );

    // irq line 1 should be asserted
    let state = chip.get_ioapic_state().expect("failed to get ioapic state");
    assert_eq!(state.current_interrupt_level_bitmap, 1 << 1);

    // Now broadcast an eoi for vector 123
    chip.broadcast_eoi(123).expect("failed to broadcast eoi");

    // irq line 1 should be deasserted
    let state = chip.get_ioapic_state().expect("failed to get ioapic state");
    assert_eq!(state.current_interrupt_level_bitmap, 0);

    // resample event should be written to by ioapic
    assert_eq!(
        evt.get_resample()
            .wait_timeout(std::time::Duration::from_millis(10))
            .expect("failed to read_timeout"),
        EventWaitResult::Signaled
    );
}

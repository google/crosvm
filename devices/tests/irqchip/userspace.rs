// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(target_arch = "x86_64")]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use base::Clock;
use base::EventWaitResult;
use base::Result;
use base::Tube;
use devices::Bus;
use devices::BusAccessInfo;
use devices::BusDeviceSync;
use devices::BusType;
use devices::CrosvmDeviceId;
use devices::DestinationShorthand;
use devices::DeviceId;
use devices::Interrupt;
use devices::InterruptData;
use devices::InterruptDestination;
use devices::IrqChip;
use devices::IrqChipX86_64;
use devices::IrqEdgeEvent;
use devices::IrqEventSource;
use devices::IrqLevelEvent;
use devices::UserspaceIrqChip;
use devices::VcpuRunState;
use devices::APIC_BASE_ADDRESS;
use devices::IOAPIC_BASE_ADDRESS;
use hypervisor::CpuId;
use hypervisor::CpuIdEntry;
use hypervisor::DebugRegs;
use hypervisor::DeliveryMode;
use hypervisor::DestinationMode;
use hypervisor::Fpu;
use hypervisor::HypervHypercall;
use hypervisor::IoParams;
use hypervisor::IoapicRedirectionTableEntry;
use hypervisor::IrqRoute;
use hypervisor::IrqSource;
use hypervisor::Level;
use hypervisor::PicSelect;
use hypervisor::PitRWMode;
use hypervisor::Regs;
use hypervisor::Sregs;
use hypervisor::TriggerMode;
use hypervisor::Vcpu;
use hypervisor::VcpuExit;
use hypervisor::VcpuSnapshot;
use hypervisor::VcpuX86_64;
use hypervisor::Xsave;
use resources::AddressRange;
use resources::SystemAllocator;
use resources::SystemAllocatorConfig;
use sync::Mutex;
use vm_memory::GuestAddress;

use crate::x86_64::test_get_ioapic;
use crate::x86_64::test_get_pit;
use crate::x86_64::test_route_irq;
use crate::x86_64::test_set_ioapic;
use crate::x86_64::test_set_pic;
use crate::x86_64::test_set_pit;

const APIC_ID: u64 = 0x20;
const TPR: u64 = 0x80;
const EOI: u64 = 0xB0;
const TEST_SLEEP_DURATION: Duration = Duration::from_millis(50);

/// Helper function for setting up a UserspaceIrqChip.
fn get_chip(num_vcpus: usize) -> UserspaceIrqChip<FakeVcpu> {
    get_chip_with_clock(num_vcpus, Arc::new(Mutex::new(Clock::new())))
}

fn get_chip_with_clock(num_vcpus: usize, clock: Arc<Mutex<Clock>>) -> UserspaceIrqChip<FakeVcpu> {
    let (_, irq_tube) = Tube::pair().unwrap();
    let mut chip = UserspaceIrqChip::<FakeVcpu>::new_with_clock(num_vcpus, irq_tube, None, clock)
        .expect("failed to instantiate UserspaceIrqChip");

    for i in 0..num_vcpus {
        let vcpu = FakeVcpu {
            id: i,
            requested: Arc::new(Mutex::new(false)),
            ready: Arc::new(Mutex::new(true)),
            injected: Arc::new(Mutex::new(None)),
        };
        chip.add_vcpu(i, &vcpu).expect("failed to add vcpu");
        chip.apics[i].lock().set_enabled(true);
    }

    chip
}

/// Helper function for cloning vcpus from a UserspaceIrqChip.
fn get_vcpus(chip: &UserspaceIrqChip<FakeVcpu>) -> Vec<FakeVcpu> {
    chip.vcpus
        .lock()
        .iter()
        .map(|v| v.as_ref().unwrap().try_clone().unwrap())
        .collect()
}

#[test]
fn set_pic() {
    test_set_pic(get_chip(1));
}

#[test]
fn get_ioapic() {
    test_get_ioapic(get_chip(1));
}

#[test]
fn set_ioapic() {
    test_set_ioapic(get_chip(1));
}

#[test]
fn get_pit() {
    test_get_pit(get_chip(1));
}

#[test]
fn set_pit() {
    test_set_pit(get_chip(1));
}

#[test]
fn route_irq() {
    test_route_irq(get_chip(1));
}

#[test]
fn pit_uses_speaker_port() {
    let chip = get_chip(1);
    assert!(chip.pit_uses_speaker_port());
}

#[test]
fn routes_conflict() {
    let mut chip = get_chip(1);
    chip.route_irq(IrqRoute {
        gsi: 32,
        source: IrqSource::Msi {
            address: 4276092928,
            data: 0,
        },
    })
    .expect("failed to set msi rout");
    // this second route should replace the first
    chip.route_irq(IrqRoute {
        gsi: 32,
        source: IrqSource::Msi {
            address: 4276092928,
            data: 32801,
        },
    })
    .expect("failed to set msi rout");
}

#[test]
fn irq_event_tokens() {
    let mut chip = get_chip(1);
    let tokens = chip
        .irq_event_tokens()
        .expect("could not get irq_event_tokens");

    // there should be one token on a fresh split irqchip, for the pit
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].1.device_name, "userspace PIT");

    // register another irq event
    let evt = IrqEdgeEvent::new().expect("failed to create eventfd");
    let source = IrqEventSource {
        device_id: CrosvmDeviceId::Cmos.into(),
        queue_id: 0,
        device_name: "test".to_owned(),
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
    assert_eq!(tokens[1].2, evt.get_trigger().try_clone().unwrap());
}

// TODO(srichman): Factor out of UserspaceIrqChip and KvmSplitIrqChip.
#[test]
fn finalize_devices() {
    let mut chip = get_chip(1);

    let mmio_bus = Bus::new(BusType::Mmio);
    let io_bus = Bus::new(BusType::Io);
    let mut resources = SystemAllocator::new(
        SystemAllocatorConfig {
            io: Some(AddressRange {
                start: 0xc000,
                end: 0xFFFF,
            }),
            low_mmio: AddressRange {
                start: 0,
                end: 2047,
            },
            high_mmio: AddressRange {
                start: 2048,
                end: 6143,
            },
            platform_mmio: None,
            first_irq: 5,
        },
        None,
        &[],
    )
    .expect("failed to create SystemAllocator");

    // Setup an event and a resample event for irq line 1.
    let evt = IrqLevelEvent::new().expect("failed to create event");

    let source = IrqEventSource {
        device_id: CrosvmDeviceId::Cmos.into(),
        device_name: "test".to_owned(),
        queue_id: 0,
    };

    let evt_index = chip
        .register_level_irq_event(1, &evt, source)
        .expect("failed to register_level_irq_event")
        .expect("register_level_irq_event should not return None");

    // Once we finalize devices, the pic/pit/ioapic should be attached to io and mmio busses.
    chip.finalize_devices(&mut resources, &io_bus, &mmio_bus)
        .expect("failed to finalize devices");

    // Should not be able to allocate an irq < 24 now.
    assert!(resources.allocate_irq().expect("failed to allocate irq") >= 24);

    // Set PIT counter 2 to "SquareWaveGen" (aka 3) mode and "Both" access mode.
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

    // Auto eoi and special fully nested mode should be turned on.
    assert!(state.auto_eoi);
    assert!(state.special_fully_nested_mode);

    // Need to write to the irq event before servicing it.
    evt.trigger().expect("failed to write to eventfd");

    // If we assert irq line one, and then get the resulting interrupt, an auto-eoi should occur
    // and cause the resample_event to be written to.
    chip.service_irq_event(evt_index)
        .expect("failed to service irq");

    let vcpu = get_vcpus(&chip).remove(0);
    chip.inject_interrupts(&vcpu).unwrap();
    assert_eq!(
        vcpu.clear_injected(),
        // Vector is 9 because the interrupt vector base address is 0x08 and this is irq line 1
        // and 8+1 = 9.
        Some(0x9)
    );

    assert_eq!(
        evt.get_resample()
            .wait_timeout(std::time::Duration::from_secs(1))
            .expect("failed to read_timeout"),
        EventWaitResult::Signaled
    );

    // Setup a ioapic redirection table entry 14.
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

    // Redirection table entry 14 should have a vector of 44.
    assert_eq!(state.redirect_table[14].get_vector(), 44);
}

#[test]
fn inject_pic_interrupt() {
    let mut chip = get_chip(2);
    let vcpus = get_vcpus(&chip);

    assert_eq!(vcpus[0].clear_injected(), None);
    assert_eq!(vcpus[1].clear_injected(), None);

    chip.service_irq(0, true).expect("failed to service irq");

    // Should not inject PIC interrupt for vcpu_id != 0.
    chip.inject_interrupts(&vcpus[1]).unwrap();
    assert_eq!(vcpus[1].clear_injected(), None);

    // Should inject Some interrupt.
    chip.inject_interrupts(&vcpus[0]).unwrap();
    assert_eq!(vcpus[0].clear_injected(), Some(0));

    // Interrupt is not injected twice.
    chip.inject_interrupts(&vcpus[0]).unwrap();
    assert_eq!(vcpus[0].clear_injected(), None);
}

#[test]
fn inject_msi() {
    let mut chip = get_chip(2);
    let vcpus = get_vcpus(&chip);

    let evt = IrqEdgeEvent::new().unwrap();
    let source = IrqEventSource {
        device_id: CrosvmDeviceId::Cmos.into(),
        device_name: "test".to_owned(),
        queue_id: 0,
    };
    let event_idx = chip
        .register_edge_irq_event(30, &evt, source)
        .unwrap()
        .unwrap();
    chip.route_irq(IrqRoute {
        gsi: 30,
        source: IrqSource::Msi {
            address: 0xFEE01000, // physical addressing, send to apic 1
            data: 0x000000F1,    // edge-triggered, fixed interrupt, vector 0xF1
        },
    })
    .unwrap();
    evt.trigger().unwrap();

    assert!(!vcpus[0].window_requested());
    assert!(!vcpus[1].window_requested());
    chip.service_irq_event(event_idx).unwrap();
    assert!(!vcpus[0].window_requested());
    assert!(vcpus[1].window_requested());

    chip.inject_interrupts(&vcpus[0]).unwrap();
    assert_eq!(vcpus[0].clear_injected(), None);

    vcpus[1].set_ready(false);
    chip.inject_interrupts(&vcpus[1]).unwrap();
    assert_eq!(vcpus[1].clear_injected(), None);
    vcpus[1].set_ready(true);
    chip.inject_interrupts(&vcpus[1]).unwrap();
    assert_eq!(vcpus[1].clear_injected(), Some(0xF1));
    assert!(!vcpus[1].window_requested());
}

#[test]
fn lowest_priority_destination() {
    let chip = get_chip(2);
    let vcpus = get_vcpus(&chip);

    // Make vcpu 0 higher priority.
    chip.write(
        BusAccessInfo {
            id: 0,
            address: APIC_BASE_ADDRESS + TPR,
            offset: TPR,
        },
        &[0x10, 0, 0, 0],
    );
    chip.send_irq_to_apics(&Interrupt {
        dest: InterruptDestination {
            source_id: 0,
            dest_id: 0,
            shorthand: DestinationShorthand::All,
            mode: DestinationMode::Physical,
        },
        data: InterruptData {
            vector: 111,
            delivery: DeliveryMode::Lowest,
            trigger: TriggerMode::Edge,
            level: Level::Deassert,
        },
    });
    chip.inject_interrupts(&vcpus[0]).unwrap();
    chip.inject_interrupts(&vcpus[1]).unwrap();
    assert_eq!(vcpus[0].clear_injected(), None);
    assert_eq!(vcpus[1].clear_injected(), Some(111));
    chip.write(
        BusAccessInfo {
            id: 1,
            address: APIC_BASE_ADDRESS + EOI,
            offset: EOI,
        },
        &[0, 0, 0, 0],
    );

    // Make vcpu 1 higher priority.
    chip.write(
        BusAccessInfo {
            id: 1,
            address: APIC_BASE_ADDRESS + TPR,
            offset: TPR,
        },
        &[0x20, 0, 0, 0],
    );
    chip.send_irq_to_apics(&Interrupt {
        dest: InterruptDestination {
            source_id: 0,
            dest_id: 0,
            shorthand: DestinationShorthand::All,
            mode: DestinationMode::Physical,
        },
        data: InterruptData {
            vector: 222,
            delivery: DeliveryMode::Lowest,
            trigger: TriggerMode::Edge,
            level: Level::Deassert,
        },
    });
    chip.inject_interrupts(&vcpus[0]).unwrap();
    chip.inject_interrupts(&vcpus[1]).unwrap();
    assert_eq!(vcpus[0].clear_injected(), Some(222));
    assert_eq!(vcpus[1].clear_injected(), None);
}

// TODO(srichman): Factor out of UserspaceIrqChip and KvmSplitIrqChip.
#[test]
fn broadcast_eoi() {
    let mut chip = get_chip(1);

    let mmio_bus = Bus::new(BusType::Mmio);
    let io_bus = Bus::new(BusType::Io);
    let mut resources = SystemAllocator::new(
        SystemAllocatorConfig {
            io: Some(AddressRange {
                start: 0xc000,
                end: 0xFFFF,
            }),
            low_mmio: AddressRange {
                start: 0,
                end: 2047,
            },
            high_mmio: AddressRange {
                start: 2048,
                end: 6143,
            },
            platform_mmio: None,
            first_irq: 5,
        },
        None,
        &[],
    )
    .expect("failed to create SystemAllocator");

    // setup an event for irq line 1
    let evt = IrqLevelEvent::new().expect("failed to create event");

    let source = IrqEventSource {
        device_id: CrosvmDeviceId::Cmos.into(),
        device_name: "test".to_owned(),
        queue_id: 0,
    };

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

#[test]
fn apic_mmio() {
    let chip = get_chip(2);
    let mut data = [0u8; 4];
    chip.read(
        BusAccessInfo {
            id: 0,
            address: APIC_BASE_ADDRESS + APIC_ID,
            offset: APIC_ID,
        },
        &mut data,
    );
    assert_eq!(data, [0, 0, 0, 0]);
    chip.read(
        BusAccessInfo {
            id: 1,
            address: APIC_BASE_ADDRESS + APIC_ID,
            offset: APIC_ID,
        },
        &mut data,
    );
    assert_eq!(data, [0, 0, 0, 1]);
}

#[test]
#[ignore = "TODO(b/237977699): remove reliance on sleep"]
fn runnable_vcpu_unhalts() {
    let chip = get_chip(1);
    let vcpu = get_vcpus(&chip).remove(0);
    let chip_copy = chip.try_clone().unwrap();
    // BSP starts runnable.
    assert_eq!(chip.wait_until_runnable(&vcpu), Ok(VcpuRunState::Runnable));
    let start = Instant::now();
    let handle = thread::spawn(move || {
        thread::sleep(TEST_SLEEP_DURATION);
        chip_copy.send_irq_to_apic(
            0,
            &InterruptData {
                vector: 123,
                delivery: DeliveryMode::Fixed,
                trigger: TriggerMode::Level,
                level: Level::Assert,
            },
        );
    });
    chip.halted(0);
    assert_eq!(chip.wait_until_runnable(&vcpu), Ok(VcpuRunState::Runnable));
    assert!(Instant::now() - start > Duration::from_millis(5));
    handle.join().unwrap();
}

#[test]
#[ignore = "TODO(b/237977699): remove reliance on sleep"]
fn kicked_vcpu_unhalts() {
    let chip = get_chip(1);
    let vcpu = get_vcpus(&chip).remove(0);
    let chip_copy = chip.try_clone().unwrap();
    // BSP starts runnable.
    assert_eq!(chip.wait_until_runnable(&vcpu), Ok(VcpuRunState::Runnable));
    let start = Instant::now();
    let handle = thread::spawn(move || {
        thread::sleep(TEST_SLEEP_DURATION);
        chip_copy.kick_halted_vcpus();
    });
    chip.halted(0);
    assert_eq!(
        chip.wait_until_runnable(&vcpu),
        Ok(VcpuRunState::Interrupted)
    );
    assert!(Instant::now() - start > Duration::from_millis(5));
    handle.join().unwrap();
}

/// Mock vcpu for testing interrupt injection.
struct FakeVcpu {
    id: usize,
    requested: Arc<Mutex<bool>>,
    ready: Arc<Mutex<bool>>,
    injected: Arc<Mutex<Option<u32>>>,
}

impl FakeVcpu {
    /// Returns and clears the last interrupt set by `interrupt`.
    fn clear_injected(&self) -> Option<u32> {
        self.injected.lock().take()
    }

    /// Returns true if an interrupt window was requested with `set_interrupt_window_requested`.
    fn window_requested(&self) -> bool {
        *self.requested.lock()
    }

    /// Sets the value to be returned by `ready_for_interrupt`.
    fn set_ready(&self, val: bool) {
        *self.ready.lock() = val;
    }
}

impl Vcpu for FakeVcpu {
    fn try_clone(&self) -> Result<Self> {
        Ok(FakeVcpu {
            id: self.id,
            requested: self.requested.clone(),
            ready: self.ready.clone(),
            injected: self.injected.clone(),
        })
    }

    fn id(&self) -> usize {
        self.id
    }

    fn as_vcpu(&self) -> &dyn Vcpu {
        self
    }

    fn run(&mut self) -> Result<VcpuExit> {
        unimplemented!()
    }

    fn set_immediate_exit(&self, _exit: bool) {}

    #[cfg(any(target_os = "android", target_os = "linux"))]
    fn signal_handle(&self) -> hypervisor::VcpuSignalHandle {
        unimplemented!()
    }

    fn handle_mmio(&self, _handle_fn: &mut dyn FnMut(IoParams) -> Option<[u8; 8]>) -> Result<()> {
        unimplemented!()
    }
    fn handle_io(&self, _handle_fn: &mut dyn FnMut(IoParams) -> Option<[u8; 8]>) -> Result<()> {
        unimplemented!()
    }
    fn handle_hyperv_hypercall(&self, _func: &mut dyn FnMut(HypervHypercall) -> u64) -> Result<()> {
        unimplemented!()
    }
    fn handle_rdmsr(&self, _data: u64) -> Result<()> {
        unimplemented!()
    }
    fn handle_wrmsr(&self) {
        unimplemented!()
    }
    fn on_suspend(&self) -> Result<()> {
        unimplemented!()
    }
    unsafe fn enable_raw_capability(&self, _cap: u32, _args: &[u64; 4]) -> Result<()> {
        unimplemented!()
    }
}

impl VcpuX86_64 for FakeVcpu {
    fn set_interrupt_window_requested(&self, requested: bool) {
        *self.requested.lock() = requested;
    }

    fn ready_for_interrupt(&self) -> bool {
        *self.ready.lock()
    }

    fn interrupt(&self, irq: u32) -> Result<()> {
        *self.injected.lock() = Some(irq);
        Ok(())
    }

    fn inject_nmi(&self) -> Result<()> {
        Ok(())
    }

    fn get_regs(&self) -> Result<Regs> {
        unimplemented!()
    }
    fn set_regs(&self, _regs: &Regs) -> Result<()> {
        unimplemented!()
    }
    fn get_sregs(&self) -> Result<Sregs> {
        unimplemented!()
    }
    fn set_sregs(&self, _sregs: &Sregs) -> Result<()> {
        unimplemented!()
    }
    fn get_fpu(&self) -> Result<Fpu> {
        unimplemented!()
    }
    fn set_fpu(&self, _fpu: &Fpu) -> Result<()> {
        unimplemented!()
    }
    fn get_xsave(&self) -> Result<Xsave> {
        unimplemented!()
    }
    fn set_xsave(&self, _xsave: &Xsave) -> Result<()> {
        unimplemented!()
    }
    fn get_interrupt_state(&self) -> Result<serde_json::Value> {
        unimplemented!()
    }
    fn set_interrupt_state(&self, _data: serde_json::Value) -> Result<()> {
        unimplemented!()
    }
    fn get_debugregs(&self) -> Result<DebugRegs> {
        unimplemented!()
    }
    fn set_debugregs(&self, _debugregs: &DebugRegs) -> Result<()> {
        unimplemented!()
    }
    fn get_xcrs(&self) -> Result<BTreeMap<u32, u64>> {
        unimplemented!()
    }
    fn set_xcr(&self, _xcr_index: u32, _value: u64) -> Result<()> {
        unimplemented!()
    }
    fn get_msr(&self, _msr_index: u32) -> Result<u64> {
        unimplemented!()
    }
    fn get_all_msrs(&self) -> Result<BTreeMap<u32, u64>> {
        unimplemented!()
    }
    fn set_msr(&self, _msr_index: u32, _value: u64) -> Result<()> {
        unimplemented!()
    }
    fn set_cpuid(&self, _cpuid: &CpuId) -> Result<()> {
        unimplemented!()
    }
    fn handle_cpuid(&mut self, _entry: &CpuIdEntry) -> Result<()> {
        unimplemented!()
    }
    fn get_hyperv_cpuid(&self) -> Result<CpuId> {
        unimplemented!()
    }
    fn set_guest_debug(&self, _addrs: &[GuestAddress], _enable_singlestep: bool) -> Result<()> {
        unimplemented!()
    }
    fn snapshot(&self) -> anyhow::Result<VcpuSnapshot> {
        unimplemented!()
    }
    fn restore(
        &mut self,
        _snapshot: &VcpuSnapshot,
        _host_tsc_reference_moment: u64,
    ) -> anyhow::Result<()> {
        unimplemented!()
    }
    fn restore_timekeeping(&self, _host_tsc_reference_moment: u64, _tsc_offset: u64) -> Result<()> {
        unimplemented!()
    }
}

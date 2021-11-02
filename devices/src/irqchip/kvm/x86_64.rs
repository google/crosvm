// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use base::error;
#[cfg(not(test))]
use base::Clock;
use base::Error;
use base::Event;
#[cfg(test)]
use base::FakeClock as Clock;
use base::Result;
use base::Tube;
use hypervisor::kvm::KvmVcpu;
use hypervisor::kvm::KvmVm;
use hypervisor::HypervisorCap;
use hypervisor::IoapicState;
use hypervisor::IrqRoute;
use hypervisor::IrqSource;
use hypervisor::IrqSourceChip;
use hypervisor::LapicState;
use hypervisor::MPState;
use hypervisor::PicSelect;
use hypervisor::PicState;
use hypervisor::PitState;
use hypervisor::Vcpu;
use hypervisor::VcpuX86_64;
use hypervisor::Vm;
use hypervisor::VmX86_64;
use kvm_sys::*;
use resources::SystemAllocator;
use sync::Mutex;

use crate::irqchip::Ioapic;
use crate::irqchip::IrqEvent;
use crate::irqchip::IrqEventIndex;
use crate::irqchip::Pic;
use crate::irqchip::VcpuRunState;
use crate::irqchip::IOAPIC_BASE_ADDRESS;
use crate::irqchip::IOAPIC_MEM_LENGTH_BYTES;
use crate::Bus;
use crate::IrqChip;
use crate::IrqChipCap;
use crate::IrqChipX86_64;
use crate::IrqEdgeEvent;
use crate::IrqEventSource;
use crate::IrqLevelEvent;
use crate::Pit;
use crate::PitError;

/// PIT tube 0 timer is connected to IRQ 0
const PIT_CHANNEL0_IRQ: u32 = 0;

/// Default x86 routing table.  Pins 0-7 go to primary pic and ioapic, pins 8-15 go to secondary
/// pic and ioapic, and pins 16-23 go only to the ioapic.
fn kvm_default_irq_routing_table(ioapic_pins: usize) -> Vec<IrqRoute> {
    let mut routes: Vec<IrqRoute> = Vec::new();

    for i in 0..8 {
        routes.push(IrqRoute::pic_irq_route(IrqSourceChip::PicPrimary, i));
        routes.push(IrqRoute::ioapic_irq_route(i));
    }
    for i in 8..16 {
        routes.push(IrqRoute::pic_irq_route(IrqSourceChip::PicSecondary, i));
        routes.push(IrqRoute::ioapic_irq_route(i));
    }
    for i in 16..ioapic_pins as u32 {
        routes.push(IrqRoute::ioapic_irq_route(i));
    }

    routes
}

/// IrqChip implementation where the entire IrqChip is emulated by KVM.
///
/// This implementation will use the KVM API to create and configure the in-kernel irqchip.
pub struct KvmKernelIrqChip {
    pub(super) vm: KvmVm,
    pub(super) vcpus: Arc<Mutex<Vec<Option<KvmVcpu>>>>,
    pub(super) routes: Arc<Mutex<Vec<IrqRoute>>>,
}

impl KvmKernelIrqChip {
    /// Construct a new KvmKernelIrqchip.
    pub fn new(vm: KvmVm, num_vcpus: usize) -> Result<KvmKernelIrqChip> {
        vm.create_irq_chip()?;
        vm.create_pit()?;
        let ioapic_pins = vm.get_ioapic_num_pins()?;

        Ok(KvmKernelIrqChip {
            vm,
            vcpus: Arc::new(Mutex::new((0..num_vcpus).map(|_| None).collect())),
            routes: Arc::new(Mutex::new(kvm_default_irq_routing_table(ioapic_pins))),
        })
    }
    /// Attempt to create a shallow clone of this x86_64 KvmKernelIrqChip instance.
    pub(super) fn arch_try_clone(&self) -> Result<Self> {
        Ok(KvmKernelIrqChip {
            vm: self.vm.try_clone()?,
            vcpus: self.vcpus.clone(),
            routes: self.routes.clone(),
        })
    }
}

impl IrqChipX86_64 for KvmKernelIrqChip {
    fn try_box_clone(&self) -> Result<Box<dyn IrqChipX86_64>> {
        Ok(Box::new(self.try_clone()?))
    }

    fn as_irq_chip(&self) -> &dyn IrqChip {
        self
    }

    fn as_irq_chip_mut(&mut self) -> &mut dyn IrqChip {
        self
    }

    /// Get the current state of the PIC
    fn get_pic_state(&self, select: PicSelect) -> Result<PicState> {
        Ok(PicState::from(&self.vm.get_pic_state(select)?))
    }

    /// Set the current state of the PIC
    fn set_pic_state(&mut self, select: PicSelect, state: &PicState) -> Result<()> {
        self.vm.set_pic_state(select, &kvm_pic_state::from(state))
    }

    /// Get the current state of the IOAPIC
    fn get_ioapic_state(&self) -> Result<IoapicState> {
        Ok(IoapicState::from(&self.vm.get_ioapic_state()?))
    }

    /// Set the current state of the IOAPIC
    fn set_ioapic_state(&mut self, state: &IoapicState) -> Result<()> {
        self.vm.set_ioapic_state(&kvm_ioapic_state::from(state))
    }

    /// Get the current state of the specified VCPU's local APIC
    fn get_lapic_state(&self, vcpu_id: usize) -> Result<LapicState> {
        match self.vcpus.lock().get(vcpu_id) {
            Some(Some(vcpu)) => Ok(LapicState::from(&vcpu.get_lapic()?)),
            _ => Err(Error::new(libc::ENOENT)),
        }
    }

    /// Set the current state of the specified VCPU's local APIC
    fn set_lapic_state(&mut self, vcpu_id: usize, state: &LapicState) -> Result<()> {
        match self.vcpus.lock().get(vcpu_id) {
            Some(Some(vcpu)) => vcpu.set_lapic(&kvm_lapic_state::from(state)),
            _ => Err(Error::new(libc::ENOENT)),
        }
    }

    /// Get the lapic frequency in Hz
    fn lapic_frequency(&self) -> u32 {
        // KVM emulates the lapic to have a bus frequency of 1GHz
        1_000_000_000
    }

    /// Retrieves the state of the PIT. Gets the pit state via the KVM API.
    fn get_pit(&self) -> Result<PitState> {
        Ok(PitState::from(&self.vm.get_pit_state()?))
    }

    /// Sets the state of the PIT. Sets the pit state via the KVM API.
    fn set_pit(&mut self, state: &PitState) -> Result<()> {
        self.vm.set_pit_state(&kvm_pit_state2::from(state))
    }

    /// Returns true if the PIT uses port 0x61 for the PC speaker, false if 0x61 is unused.
    /// KVM's kernel PIT doesn't use 0x61.
    fn pit_uses_speaker_port(&self) -> bool {
        false
    }
}

/// The KvmSplitIrqsChip supports KVM's SPLIT_IRQCHIP feature, where the PIC and IOAPIC
/// are emulated in userspace, while the local APICs are emulated in the kernel.
/// The SPLIT_IRQCHIP feature only supports x86/x86_64 so we only define this IrqChip in crosvm
/// for x86/x86_64.
pub struct KvmSplitIrqChip {
    vm: KvmVm,
    vcpus: Arc<Mutex<Vec<Option<KvmVcpu>>>>,
    routes: Arc<Mutex<Vec<IrqRoute>>>,
    pit: Arc<Mutex<Pit>>,
    pic: Arc<Mutex<Pic>>,
    ioapic: Arc<Mutex<Ioapic>>,
    ioapic_pins: usize,
    /// Vec of ioapic irq events that have been delayed because the ioapic was locked when
    /// service_irq was called on the irqchip. This prevents deadlocks when a Vcpu thread has
    /// locked the ioapic and the ioapic sends a AddMsiRoute signal to the main thread (which
    /// itself may be busy trying to call service_irq).
    delayed_ioapic_irq_events: Arc<Mutex<Vec<usize>>>,
    /// Event which is meant to trigger process of any irqs events that were delayed.
    delayed_ioapic_irq_trigger: Event,
    /// Array of Events that devices will use to assert ioapic pins.
    irq_events: Arc<Mutex<Vec<Option<IrqEvent>>>>,
}

fn kvm_dummy_msi_routes(ioapic_pins: usize) -> Vec<IrqRoute> {
    let mut routes: Vec<IrqRoute> = Vec::new();
    for i in 0..ioapic_pins {
        routes.push(
            // Add dummy MSI routes to replace the default IRQChip routes.
            IrqRoute {
                gsi: i as u32,
                source: IrqSource::Msi {
                    address: 0,
                    data: 0,
                },
            },
        );
    }
    routes
}

impl KvmSplitIrqChip {
    /// Construct a new KvmSplitIrqChip.
    pub fn new(
        vm: KvmVm,
        num_vcpus: usize,
        irq_tube: Tube,
        ioapic_pins: Option<usize>,
    ) -> Result<Self> {
        let ioapic_pins = ioapic_pins.unwrap_or(vm.get_ioapic_num_pins()?);
        vm.enable_split_irqchip(ioapic_pins)?;
        let pit_evt = IrqEdgeEvent::new()?;
        let pit = Pit::new(pit_evt.try_clone()?, Arc::new(Mutex::new(Clock::new()))).map_err(
            |e| match e {
                PitError::CloneEvent(err) => err,
                PitError::CreateEvent(err) => err,
                PitError::CreateWaitContext(err) => err,
                PitError::WaitError(err) => err,
                PitError::TimerCreateError(err) => err,
                PitError::SpawnThread(_) => Error::new(libc::EIO),
            },
        )?;

        let pit_event_source = IrqEventSource::from_device(&pit);

        let mut chip = KvmSplitIrqChip {
            vm,
            vcpus: Arc::new(Mutex::new((0..num_vcpus).map(|_| None).collect())),
            routes: Arc::new(Mutex::new(Vec::new())),
            pit: Arc::new(Mutex::new(pit)),
            pic: Arc::new(Mutex::new(Pic::new())),
            ioapic: Arc::new(Mutex::new(Ioapic::new(irq_tube, ioapic_pins)?)),
            ioapic_pins,
            delayed_ioapic_irq_events: Arc::new(Mutex::new(Vec::new())),
            delayed_ioapic_irq_trigger: Event::new()?,
            irq_events: Arc::new(Mutex::new(Default::default())),
        };

        // crosvm-direct requires 1:1 GSI mapping between host and guest. The predefined IRQ
        // numbering will be exposed to the guest with no option to allocate it dynamically.
        // Tell the IOAPIC to fill in IRQ output events with 1:1 GSI mapping upfront so that
        // IOAPIC wont assign a new GSI but use the same as for host instead.
        #[cfg(feature = "direct")]
        chip.ioapic
            .lock()
            .init_direct_gsi(|gsi, event| chip.vm.register_irqfd(gsi as u32, event, None))?;

        // Setup standard x86 irq routes
        let mut routes = kvm_default_irq_routing_table(ioapic_pins);
        // Add dummy MSI routes for the first ioapic_pins GSIs
        routes.append(&mut kvm_dummy_msi_routes(ioapic_pins));

        // Set the routes so they get sent to KVM
        chip.set_irq_routes(&routes)?;

        chip.register_edge_irq_event(PIT_CHANNEL0_IRQ, &pit_evt, pit_event_source)?;
        Ok(chip)
    }
}

impl KvmSplitIrqChip {
    /// Convenience function for determining which chips the supplied irq routes to.
    fn routes_to_chips(&self, irq: u32) -> Vec<(IrqSourceChip, u32)> {
        let mut chips = Vec::new();
        for route in self.routes.lock().iter() {
            match route {
                IrqRoute {
                    gsi,
                    source: IrqSource::Irqchip { chip, pin },
                } if *gsi == irq => match chip {
                    IrqSourceChip::PicPrimary
                    | IrqSourceChip::PicSecondary
                    | IrqSourceChip::Ioapic => chips.push((*chip, *pin)),
                    IrqSourceChip::Gic => {
                        error!("gic irq should not be possible on a KvmSplitIrqChip")
                    }
                    IrqSourceChip::Aia => {
                        error!("Aia irq should not be possible on x86_64")
                    }
                },
                // Ignore MSIs and other routes
                _ => {}
            }
        }
        chips
    }

    /// Return true if there is a pending interrupt for the specified vcpu. For KvmSplitIrqChip
    /// this calls interrupt_requested on the pic.
    pub fn interrupt_requested(&self, vcpu_id: usize) -> bool {
        // Pic interrupts for the split irqchip only go to vcpu 0
        if vcpu_id != 0 {
            return false;
        }
        self.pic.lock().interrupt_requested()
    }

    /// Check if the specified vcpu has any pending interrupts. Returns None for no interrupts,
    /// otherwise Some(u32) should be the injected interrupt vector. For KvmSplitIrqChip
    /// this calls get_external_interrupt on the pic.
    pub fn get_external_interrupt(&self, vcpu_id: usize) -> Option<u32> {
        // Pic interrupts for the split irqchip only go to vcpu 0
        if vcpu_id != 0 {
            return None;
        }
        self.pic
            .lock()
            .get_external_interrupt()
            .map(|vector| vector as u32)
    }

    /// Register an event that can trigger an interrupt for a particular GSI.
    fn register_irq_event(
        &mut self,
        irq: u32,
        irq_event: &Event,
        resample_event: Option<&Event>,
        source: IrqEventSource,
    ) -> Result<Option<IrqEventIndex>> {
        if irq < self.ioapic_pins as u32 {
            let mut evt = IrqEvent {
                gsi: irq,
                event: irq_event.try_clone()?,
                resample_event: None,
                source,
            };

            if let Some(resample_event) = resample_event {
                evt.resample_event = Some(resample_event.try_clone()?);
            }

            let mut irq_events = self.irq_events.lock();
            let index = irq_events.len();
            irq_events.push(Some(evt));
            Ok(Some(index))
        } else {
            self.vm.register_irqfd(irq, irq_event, resample_event)?;
            Ok(None)
        }
    }

    /// Unregister an event for a particular GSI.
    fn unregister_irq_event(&mut self, irq: u32, irq_event: &Event) -> Result<()> {
        if irq < self.ioapic_pins as u32 {
            let mut irq_events = self.irq_events.lock();
            for (index, evt) in irq_events.iter().enumerate() {
                if let Some(evt) = evt {
                    if evt.gsi == irq && irq_event.eq(&evt.event) {
                        irq_events[index] = None;
                        break;
                    }
                }
            }
            Ok(())
        } else {
            self.vm.unregister_irqfd(irq, irq_event)
        }
    }
}

/// Convenience function for determining whether or not two irq routes conflict.
/// Returns true if they conflict.
fn routes_conflict(route: &IrqRoute, other: &IrqRoute) -> bool {
    // They don't conflict if they have different GSIs.
    if route.gsi != other.gsi {
        return false;
    }

    // If they're both MSI with the same GSI then they conflict.
    if let (IrqSource::Msi { .. }, IrqSource::Msi { .. }) = (route.source, other.source) {
        return true;
    }

    // If the route chips match and they have the same GSI then they conflict.
    if let (
        IrqSource::Irqchip {
            chip: route_chip, ..
        },
        IrqSource::Irqchip {
            chip: other_chip, ..
        },
    ) = (route.source, other.source)
    {
        return route_chip == other_chip;
    }

    // Otherwise they do not conflict.
    false
}

/// This IrqChip only works with Kvm so we only implement it for KvmVcpu.
impl IrqChip for KvmSplitIrqChip {
    /// Add a vcpu to the irq chip.
    fn add_vcpu(&mut self, vcpu_id: usize, vcpu: &dyn Vcpu) -> Result<()> {
        let vcpu: &KvmVcpu = vcpu
            .downcast_ref()
            .expect("KvmSplitIrqChip::add_vcpu called with non-KvmVcpu");
        self.vcpus.lock()[vcpu_id] = Some(vcpu.try_clone()?);
        Ok(())
    }

    /// Register an event that can trigger an interrupt for a particular GSI.
    fn register_edge_irq_event(
        &mut self,
        irq: u32,
        irq_event: &IrqEdgeEvent,
        source: IrqEventSource,
    ) -> Result<Option<IrqEventIndex>> {
        self.register_irq_event(irq, irq_event.get_trigger(), None, source)
    }

    fn unregister_edge_irq_event(&mut self, irq: u32, irq_event: &IrqEdgeEvent) -> Result<()> {
        self.unregister_irq_event(irq, irq_event.get_trigger())
    }

    fn register_level_irq_event(
        &mut self,
        irq: u32,
        irq_event: &IrqLevelEvent,
        source: IrqEventSource,
    ) -> Result<Option<IrqEventIndex>> {
        self.register_irq_event(
            irq,
            irq_event.get_trigger(),
            Some(irq_event.get_resample()),
            source,
        )
    }

    fn unregister_level_irq_event(&mut self, irq: u32, irq_event: &IrqLevelEvent) -> Result<()> {
        self.unregister_irq_event(irq, irq_event.get_trigger())
    }

    /// Route an IRQ line to an interrupt controller, or to a particular MSI vector.
    fn route_irq(&mut self, route: IrqRoute) -> Result<()> {
        let mut routes = self.routes.lock();
        routes.retain(|r| !routes_conflict(r, &route));

        routes.push(route);

        // We only call set_gsi_routing with the msi routes
        let mut msi_routes = routes.clone();
        msi_routes.retain(|r| matches!(r.source, IrqSource::Msi { .. }));

        self.vm.set_gsi_routing(&msi_routes)
    }

    /// Replace all irq routes with the supplied routes
    fn set_irq_routes(&mut self, routes: &[IrqRoute]) -> Result<()> {
        let mut current_routes = self.routes.lock();
        *current_routes = routes.to_vec();

        // We only call set_gsi_routing with the msi routes
        let mut msi_routes = routes.to_vec();
        msi_routes.retain(|r| matches!(r.source, IrqSource::Msi { .. }));

        self.vm.set_gsi_routing(&msi_routes)
    }

    /// Return a vector of all registered irq numbers and their associated events and event
    /// indices. These should be used by the main thread to wait for irq events.
    fn irq_event_tokens(&self) -> Result<Vec<(IrqEventIndex, IrqEventSource, Event)>> {
        let mut tokens = vec![];
        for (index, evt) in self.irq_events.lock().iter().enumerate() {
            if let Some(evt) = evt {
                tokens.push((index, evt.source.clone(), evt.event.try_clone()?));
            }
        }
        Ok(tokens)
    }

    /// Either assert or deassert an IRQ line.  Sends to either an interrupt controller, or does
    /// a send_msi if the irq is associated with an MSI.
    fn service_irq(&mut self, irq: u32, level: bool) -> Result<()> {
        let chips = self.routes_to_chips(irq);
        for (chip, pin) in chips {
            match chip {
                IrqSourceChip::PicPrimary | IrqSourceChip::PicSecondary => {
                    self.pic.lock().service_irq(pin as u8, level);
                }
                IrqSourceChip::Ioapic => {
                    self.ioapic.lock().service_irq(pin as usize, level);
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Service an IRQ event by asserting then deasserting an IRQ line. The associated Event
    /// that triggered the irq event will be read from. If the irq is associated with a resample
    /// Event, then the deassert will only happen after an EOI is broadcast for a vector
    /// associated with the irq line.
    /// For the KvmSplitIrqChip, this function identifies which chips the irq routes to, then
    /// attempts to call service_irq on those chips. If the ioapic is unable to be immediately
    /// locked, we add the irq to the delayed_ioapic_irq_events Vec (though we still read
    /// from the Event that triggered the irq event).
    fn service_irq_event(&mut self, event_index: IrqEventIndex) -> Result<()> {
        if let Some(evt) = &self.irq_events.lock()[event_index] {
            evt.event.wait()?;
            let chips = self.routes_to_chips(evt.gsi);

            for (chip, pin) in chips {
                match chip {
                    IrqSourceChip::PicPrimary | IrqSourceChip::PicSecondary => {
                        let mut pic = self.pic.lock();
                        pic.service_irq(pin as u8, true);
                        if evt.resample_event.is_none() {
                            pic.service_irq(pin as u8, false);
                        }
                    }
                    IrqSourceChip::Ioapic => {
                        if let Ok(mut ioapic) = self.ioapic.try_lock() {
                            ioapic.service_irq(pin as usize, true);
                            if evt.resample_event.is_none() {
                                ioapic.service_irq(pin as usize, false);
                            }
                        } else {
                            self.delayed_ioapic_irq_events.lock().push(event_index);
                            self.delayed_ioapic_irq_trigger.signal().unwrap();
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    /// Broadcast an end of interrupt. For KvmSplitIrqChip this sends the EOI to the ioapic
    fn broadcast_eoi(&self, vector: u8) -> Result<()> {
        self.ioapic.lock().end_of_interrupt(vector);
        Ok(())
    }

    /// Injects any pending interrupts for `vcpu`.
    /// For KvmSplitIrqChip this injects any PIC interrupts on vcpu_id 0.
    fn inject_interrupts(&self, vcpu: &dyn Vcpu) -> Result<()> {
        let vcpu: &KvmVcpu = vcpu
            .downcast_ref()
            .expect("KvmSplitIrqChip::add_vcpu called with non-KvmVcpu");

        let vcpu_id = vcpu.id();
        if !self.interrupt_requested(vcpu_id) || !vcpu.ready_for_interrupt() {
            return Ok(());
        }

        if let Some(vector) = self.get_external_interrupt(vcpu_id) {
            vcpu.interrupt(vector)?;
        }

        // The second interrupt request should be handled immediately, so ask vCPU to exit as soon as
        // possible.
        if self.interrupt_requested(vcpu_id) {
            vcpu.set_interrupt_window_requested(true);
        }
        Ok(())
    }

    /// Notifies the irq chip that the specified VCPU has executed a halt instruction.
    /// For KvmSplitIrqChip this is a no-op because KVM handles VCPU blocking.
    fn halted(&self, _vcpu_id: usize) {}

    /// Blocks until `vcpu` is in a runnable state or until interrupted by
    /// `IrqChip::kick_halted_vcpus`.  Returns `VcpuRunState::Runnable if vcpu is runnable, or
    /// `VcpuRunState::Interrupted` if the wait was interrupted.
    /// For KvmSplitIrqChip this is a no-op and always returns Runnable because KVM handles VCPU
    /// blocking.
    fn wait_until_runnable(&self, _vcpu: &dyn Vcpu) -> Result<VcpuRunState> {
        Ok(VcpuRunState::Runnable)
    }

    /// Makes unrunnable VCPUs return immediately from `wait_until_runnable`.
    /// For KvmSplitIrqChip this is a no-op because KVM handles VCPU blocking.
    fn kick_halted_vcpus(&self) {}

    /// Get the current MP state of the specified VCPU.
    fn get_mp_state(&self, vcpu_id: usize) -> Result<MPState> {
        match self.vcpus.lock().get(vcpu_id) {
            Some(Some(vcpu)) => Ok(MPState::from(&vcpu.get_mp_state()?)),
            _ => Err(Error::new(libc::ENOENT)),
        }
    }

    /// Set the current MP state of the specified VCPU.
    fn set_mp_state(&mut self, vcpu_id: usize, state: &MPState) -> Result<()> {
        match self.vcpus.lock().get(vcpu_id) {
            Some(Some(vcpu)) => vcpu.set_mp_state(&kvm_mp_state::from(state)),
            _ => Err(Error::new(libc::ENOENT)),
        }
    }

    /// Attempt to clone this IrqChip instance.
    fn try_clone(&self) -> Result<Self> {
        Ok(KvmSplitIrqChip {
            vm: self.vm.try_clone()?,
            vcpus: self.vcpus.clone(),
            routes: self.routes.clone(),
            pit: self.pit.clone(),
            pic: self.pic.clone(),
            ioapic: self.ioapic.clone(),
            ioapic_pins: self.ioapic_pins,
            delayed_ioapic_irq_events: self.delayed_ioapic_irq_events.clone(),
            delayed_ioapic_irq_trigger: Event::new()?,
            irq_events: self.irq_events.clone(),
        })
    }

    /// Finalize irqchip setup. Should be called once all devices have registered irq events and
    /// been added to the io_bus and mmio_bus.
    fn finalize_devices(
        &mut self,
        resources: &mut SystemAllocator,
        io_bus: &Bus,
        mmio_bus: &Bus,
    ) -> Result<()> {
        // Insert pit into io_bus
        io_bus.insert(self.pit.clone(), 0x040, 0x8).unwrap();
        io_bus.insert(self.pit.clone(), 0x061, 0x1).unwrap();

        // Insert pic into io_bus
        io_bus.insert(self.pic.clone(), 0x20, 0x2).unwrap();
        io_bus.insert(self.pic.clone(), 0xa0, 0x2).unwrap();
        io_bus.insert(self.pic.clone(), 0x4d0, 0x2).unwrap();

        // Insert ioapic into mmio_bus
        mmio_bus
            .insert(
                self.ioapic.clone(),
                IOAPIC_BASE_ADDRESS,
                IOAPIC_MEM_LENGTH_BYTES,
            )
            .unwrap();

        // At this point, all of our devices have been created and they have registered their
        // irq events, so we can clone our resample events
        let mut ioapic_resample_events: Vec<Vec<Event>> =
            (0..self.ioapic_pins).map(|_| Vec::new()).collect();
        let mut pic_resample_events: Vec<Vec<Event>> =
            (0..self.ioapic_pins).map(|_| Vec::new()).collect();

        for evt in self.irq_events.lock().iter().flatten() {
            if (evt.gsi as usize) >= self.ioapic_pins {
                continue;
            }
            if let Some(resample_evt) = &evt.resample_event {
                ioapic_resample_events[evt.gsi as usize].push(resample_evt.try_clone()?);
                pic_resample_events[evt.gsi as usize].push(resample_evt.try_clone()?);
            }
        }

        // Register resample events with the ioapic
        self.ioapic
            .lock()
            .register_resample_events(ioapic_resample_events);
        // Register resample events with the pic
        self.pic
            .lock()
            .register_resample_events(pic_resample_events);

        // Make sure all future irq numbers are beyond IO-APIC range.
        let mut irq_num = resources.allocate_irq().unwrap();
        while irq_num < self.ioapic_pins as u32 {
            irq_num = resources.allocate_irq().unwrap();
        }

        Ok(())
    }

    /// The KvmSplitIrqChip's ioapic may be locked because a vcpu thread is currently writing to
    /// the ioapic, and the ioapic may be blocking on adding MSI routes, which requires blocking
    /// socket communication back to the main thread.  Thus, we do not want the main thread to
    /// block on a locked ioapic, so any irqs that could not be serviced because the ioapic could
    /// not be immediately locked are added to the delayed_ioapic_irq_events Vec. This function
    /// processes each delayed event in the vec each time it's called. If the ioapic is still
    /// locked, we keep the queued irqs for the next time this function is called.
    fn process_delayed_irq_events(&mut self) -> Result<()> {
        self.delayed_ioapic_irq_events
            .lock()
            .retain(|&event_index| {
                if let Some(evt) = &self.irq_events.lock()[event_index] {
                    if let Ok(mut ioapic) = self.ioapic.try_lock() {
                        ioapic.service_irq(evt.gsi as usize, true);
                        if evt.resample_event.is_none() {
                            ioapic.service_irq(evt.gsi as usize, false);
                        }

                        false
                    } else {
                        true
                    }
                } else {
                    true
                }
            });

        if self.delayed_ioapic_irq_events.lock().is_empty() {
            self.delayed_ioapic_irq_trigger.wait()?;
        }

        Ok(())
    }

    fn irq_delayed_event_token(&self) -> Result<Option<Event>> {
        Ok(Some(self.delayed_ioapic_irq_trigger.try_clone()?))
    }

    fn check_capability(&self, c: IrqChipCap) -> bool {
        match c {
            IrqChipCap::TscDeadlineTimer => self
                .vm
                .get_hypervisor()
                .check_capability(HypervisorCap::TscDeadlineTimer),
            IrqChipCap::X2Apic => true,
        }
    }
}

impl IrqChipX86_64 for KvmSplitIrqChip {
    fn try_box_clone(&self) -> Result<Box<dyn IrqChipX86_64>> {
        Ok(Box::new(self.try_clone()?))
    }

    fn as_irq_chip(&self) -> &dyn IrqChip {
        self
    }

    fn as_irq_chip_mut(&mut self) -> &mut dyn IrqChip {
        self
    }

    /// Get the current state of the PIC
    fn get_pic_state(&self, select: PicSelect) -> Result<PicState> {
        Ok(self.pic.lock().get_pic_state(select))
    }

    /// Set the current state of the PIC
    fn set_pic_state(&mut self, select: PicSelect, state: &PicState) -> Result<()> {
        self.pic.lock().set_pic_state(select, state);
        Ok(())
    }

    /// Get the current state of the IOAPIC
    fn get_ioapic_state(&self) -> Result<IoapicState> {
        Ok(self.ioapic.lock().get_ioapic_state())
    }

    /// Set the current state of the IOAPIC
    fn set_ioapic_state(&mut self, state: &IoapicState) -> Result<()> {
        self.ioapic.lock().set_ioapic_state(state);
        Ok(())
    }

    /// Get the current state of the specified VCPU's local APIC
    fn get_lapic_state(&self, vcpu_id: usize) -> Result<LapicState> {
        match self.vcpus.lock().get(vcpu_id) {
            Some(Some(vcpu)) => Ok(LapicState::from(&vcpu.get_lapic()?)),
            _ => Err(Error::new(libc::ENOENT)),
        }
    }

    /// Set the current state of the specified VCPU's local APIC
    fn set_lapic_state(&mut self, vcpu_id: usize, state: &LapicState) -> Result<()> {
        match self.vcpus.lock().get(vcpu_id) {
            Some(Some(vcpu)) => vcpu.set_lapic(&kvm_lapic_state::from(state)),
            _ => Err(Error::new(libc::ENOENT)),
        }
    }

    /// Get the lapic frequency in Hz
    fn lapic_frequency(&self) -> u32 {
        // KVM emulates the lapic to have a bus frequency of 1GHz
        1_000_000_000
    }

    /// Retrieves the state of the PIT. Gets the pit state via the KVM API.
    fn get_pit(&self) -> Result<PitState> {
        Ok(self.pit.lock().get_pit_state())
    }

    /// Sets the state of the PIT. Sets the pit state via the KVM API.
    fn set_pit(&mut self, state: &PitState) -> Result<()> {
        self.pit.lock().set_pit_state(state);
        Ok(())
    }

    /// Returns true if the PIT uses port 0x61 for the PC speaker, false if 0x61 is unused.
    /// devices::Pit uses 0x61.
    fn pit_uses_speaker_port(&self) -> bool {
        true
    }
}

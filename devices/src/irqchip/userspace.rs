// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt;
use std::fmt::Display;
use std::iter;
use std::sync::Arc;
use std::thread;

cfg_if::cfg_if! {
    if #[cfg(test)] {
        use base::{FakeClock as Clock, FakeTimer as Timer};
    } else {
        use base::{Clock, Timer};
    }
}
use base::error;
use base::info;
use base::warn;
use base::AsRawDescriptor;
use base::Descriptor;
use base::Error;
use base::Event;
use base::EventToken;
use base::Result;
use base::Tube;
use base::WaitContext;
use hypervisor::DeliveryMode;
use hypervisor::IoapicState;
use hypervisor::IrqRoute;
use hypervisor::IrqSource;
use hypervisor::IrqSourceChip;
use hypervisor::LapicState;
use hypervisor::MPState;
use hypervisor::MsiAddressMessage;
use hypervisor::MsiDataMessage;
use hypervisor::PicSelect;
use hypervisor::PicState;
use hypervisor::PitState;
use hypervisor::Vcpu;
use hypervisor::VcpuX86_64;
use resources::SystemAllocator;
use sync::Condvar;
use sync::Mutex;

use crate::bus::BusDeviceSync;
use crate::irqchip::Apic;
use crate::irqchip::ApicBusMsg;
use crate::irqchip::DelayedIoApicIrqEvents;
use crate::irqchip::Interrupt;
use crate::irqchip::InterruptData;
use crate::irqchip::InterruptDestination;
use crate::irqchip::Ioapic;
use crate::irqchip::IrqEvent;
use crate::irqchip::IrqEventIndex;
use crate::irqchip::Pic;
use crate::irqchip::Routes;
use crate::irqchip::VcpuRunState;
use crate::irqchip::APIC_BASE_ADDRESS;
use crate::irqchip::APIC_MEM_LENGTH_BYTES;
use crate::irqchip::IOAPIC_BASE_ADDRESS;
use crate::irqchip::IOAPIC_MEM_LENGTH_BYTES;
use crate::pci::CrosvmDeviceId;
use crate::Bus;
use crate::BusAccessInfo;
use crate::BusDevice;
use crate::DeviceId;
use crate::IrqChip;
use crate::IrqChipCap;
use crate::IrqChipX86_64;
use crate::IrqEdgeEvent;
use crate::IrqEventSource;
use crate::IrqLevelEvent;
use crate::Pit;
use crate::PitError;
use crate::Suspendable;

/// PIT channel 0 timer is connected to IRQ 0
const PIT_CHANNEL0_IRQ: u32 = 0;
/// CR0 extension type bit
const X86_CR0_ET: u64 = 0x00000010;
/// CR0 not write through bit
const X86_CR0_NW: u64 = 0x20000000;
/// CR0 cache disable bit
const X86_CR0_CD: u64 = 0x40000000;
/// Default power on state of CR0 register, according to the Intel manual.
const X86_CR0_INIT: u64 = X86_CR0_ET | X86_CR0_NW | X86_CR0_CD;

/// An `IrqChip` with all interrupt devices emulated in userspace.  `UserspaceIrqChip` works with
/// any hypervisor, but only supports x86.
pub struct UserspaceIrqChip<V: VcpuX86_64> {
    vcpus: Arc<Mutex<Vec<Option<V>>>>,
    routes: Arc<Mutex<Routes>>,
    pit: Arc<Mutex<Pit>>,
    pic: Arc<Mutex<Pic>>,
    ioapic: Arc<Mutex<Ioapic>>,
    ioapic_pins: usize,
    apics: Vec<Arc<Mutex<Apic>>>,
    // Condition variables used by wait_until_runnable.
    waiters: Vec<Arc<Waiter>>,
    // Raw descriptors of the apic Timers.
    timer_descriptors: Vec<Descriptor>,
    /// Delayed ioapic irq object, that contains the delayed events because the ioapic was locked
    /// when service_irq was called on the irqchip. This prevents deadlocks when a Vcpu thread has
    /// locked the ioapic and the ioapic sends a AddMsiRoute signal to the main thread (which
    /// itself may be busy trying to call service_irq).
    ///
    /// ## Note:
    /// This lock may be locked by itself to access the `DelayedIoApicIrqEvents`. If accessed in
    /// conjunction with the `irq_events` field, that lock should be taken first to prevent
    /// deadlocks stemming from lock-ordering issues.
    delayed_ioapic_irq_events: Arc<Mutex<DelayedIoApicIrqEvents>>,
    // Array of Events that devices will use to assert ioapic pins.
    irq_events: Arc<Mutex<Vec<Option<IrqEvent>>>>,
    dropper: Arc<Mutex<Dropper>>,
}

/// Helper that implements `Drop` on behalf of `UserspaceIrqChip`.  The many cloned copies of an irq
/// chip share a single arc'ed `Dropper`, which only runs its drop when the last irq chip copy is
/// dropped.
struct Dropper {
    /// Worker threads that deliver timer events to the APICs.
    workers: Vec<thread::JoinHandle<TimerWorkerResult<()>>>,
    /// Events for telling timer workers to exit.
    kill_evts: Vec<Event>,
}

impl<V: VcpuX86_64 + 'static> UserspaceIrqChip<V> {
    /// Constructs a new `UserspaceIrqChip`.
    pub fn new(num_vcpus: usize, irq_tube: Tube, ioapic_pins: Option<usize>) -> Result<Self> {
        let clock = Arc::new(Mutex::new(Clock::new()));
        Self::new_with_clock(num_vcpus, irq_tube, ioapic_pins, clock)
    }

    /// Constructs a new `UserspaceIrqChip`, with a clock.  Used for testing.
    pub fn new_with_clock(
        num_vcpus: usize,
        irq_tube: Tube,
        ioapic_pins: Option<usize>,
        clock: Arc<Mutex<Clock>>,
    ) -> Result<Self> {
        let pit_evt = IrqEdgeEvent::new()?;
        // For test only, this clock instance is FakeClock. It needs to be cloned for every Timer
        // instance, so make a clone for it now.
        #[cfg(test)]
        let test_clock = clock.clone();
        let pit = Pit::new(pit_evt.try_clone()?, clock).map_err(|e| match e {
            PitError::CloneEvent(err) => err,
            PitError::CreateEvent(err) => err,
            PitError::CreateWaitContext(err) => err,
            PitError::TimerCreateError(err) => err,
            PitError::WaitError(err) => err,
            PitError::SpawnThread(_) => Error::new(libc::EIO),
        })?;
        let pit_event_source = IrqEventSource::from_device(&pit);

        let ioapic_pins = ioapic_pins.unwrap_or(hypervisor::NUM_IOAPIC_PINS);
        let ioapic = Ioapic::new(irq_tube, ioapic_pins)?;

        let mut timer_descriptors: Vec<Descriptor> = Vec::with_capacity(num_vcpus);
        let mut apics: Vec<Arc<Mutex<Apic>>> = Vec::with_capacity(num_vcpus);
        for id in 0..num_vcpus {
            cfg_if::cfg_if! {
                if #[cfg(test)] {
                    let timer = Timer::new(test_clock.clone());
                } else {
                    let timer = Timer::new()?;
                }
            }
            // Timers are owned by the apics, which outlive the raw descriptors stored here and in
            // the worker threads.
            timer_descriptors.push(Descriptor(timer.as_raw_descriptor()));

            let id: u8 = id.try_into().or(Err(Error::new(libc::EINVAL)))?;
            let apic = Apic::new(id, timer);
            apics.push(Arc::new(Mutex::new(apic)));
        }
        let dropper = Dropper {
            workers: Vec::new(),
            kill_evts: Vec::new(),
        };

        let mut chip = UserspaceIrqChip {
            vcpus: Arc::new(Mutex::new(
                iter::repeat_with(|| None).take(num_vcpus).collect(),
            )),
            waiters: iter::repeat_with(Default::default)
                .take(num_vcpus)
                .collect(),
            routes: Arc::new(Mutex::new(Routes::new())),
            pit: Arc::new(Mutex::new(pit)),
            pic: Arc::new(Mutex::new(Pic::new())),
            ioapic: Arc::new(Mutex::new(ioapic)),
            ioapic_pins,
            apics,
            timer_descriptors,
            delayed_ioapic_irq_events: Arc::new(Mutex::new(DelayedIoApicIrqEvents::new()?)),
            irq_events: Arc::new(Mutex::new(Vec::new())),
            dropper: Arc::new(Mutex::new(dropper)),
        };

        // Setup standard x86 irq routes
        chip.set_irq_routes(&Routes::default_pic_ioapic_routes(ioapic_pins))?;

        chip.register_edge_irq_event(PIT_CHANNEL0_IRQ, &pit_evt, pit_event_source)?;
        Ok(chip)
    }

    /// Handles a message from an APIC.
    fn handle_msg(&self, msg: ApicBusMsg) {
        match msg {
            ApicBusMsg::Eoi(vector) => {
                let _ = self.broadcast_eoi(vector);
            }
            ApicBusMsg::Ipi(interrupt) => self.send_irq_to_apics(&interrupt),
        }
    }

    /// Sends a Message Signaled Interrupt to one or more APICs.  MSIs are a 64-bit address and
    /// 32-bit data, but in the Intel spec we're implementing, only the low 32 bits of the address
    /// are used.
    fn send_msi(&self, addr: u32, data: u32) {
        let mut msi_addr = MsiAddressMessage::new();
        msi_addr.set(0, 32, addr as u64);
        let dest = match InterruptDestination::try_from(&msi_addr) {
            Ok(dest) => dest,
            Err(e) => {
                warn!("Invalid MSI message: {}", e);
                return;
            }
        };

        let mut msi_data = MsiDataMessage::new();
        msi_data.set(0, 32, data as u64);
        let data = InterruptData::from(&msi_data);

        self.send_irq_to_apics(&Interrupt { dest, data });
    }

    fn send_irq_to_apic(&self, id: usize, irq: &InterruptData) {
        // id can come from the guest, so check bounds.
        if let Some(apic) = self.apics.get(id) {
            apic.lock().accept_irq(irq);
        } else {
            error!("Interrupt for non-existent apic {}: {:?}", id, irq);
        }
        if let Some(Some(vcpu)) = self.vcpus.lock().get(id) {
            vcpu.set_interrupt_window_requested(true);
        } else {
            error!("Interrupt for non-existent vcpu {}: {:?}", id, irq);
        }
        self.waiters[id].notify();
    }

    /// Sends an interrupt to one or more APICs.  Used for sending MSIs and IPIs.
    fn send_irq_to_apics(&self, irq: &Interrupt) {
        match irq.data.delivery {
            DeliveryMode::Fixed | DeliveryMode::Lowest | DeliveryMode::RemoteRead => {}
            _ => info!("UserspaceIrqChip received special irq: {:?}", irq),
        }

        // First try the fast path, where the destination is a single APIC we can send to directly.
        if let Some(apic_id) = Apic::single_dest_fast(&irq.dest) {
            self.send_irq_to_apic(apic_id as usize, &irq.data);
            return;
        }

        let lowest_mode = irq.data.delivery == DeliveryMode::Lowest;
        let mut lowest_priority = u8::MAX;
        let mut lowest_apic: Option<usize> = None;

        for (i, apic) in self.apics.iter().enumerate() {
            let send = {
                let apic = apic.lock();
                if !apic.match_dest(&irq.dest) {
                    false
                } else if lowest_mode {
                    let priority = apic.get_processor_priority();
                    if priority <= lowest_priority {
                        lowest_priority = priority;
                        lowest_apic = Some(i);
                    }
                    false
                } else {
                    true
                }
            };
            if send {
                self.send_irq_to_apic(i, &irq.data);
            }
        }

        if lowest_mode {
            if let Some(index) = lowest_apic {
                self.send_irq_to_apic(index, &irq.data);
            } else {
                // According to sections 10.6.2.1 and 10.6.2.2 of the SDM, the OS should not let
                // this happen.  If the OS is misconfigured then drop the interrupt and log a
                // warning.
                warn!(
                    "Lowest priority interrupt sent, but no apics configured as valid target: {:?}",
                    irq
                );
            }
        }
    }

    /// Delivers a startup IPI to `vcpu`.
    fn deliver_startup(&self, vcpu: &V, vector: u8) -> Result<()> {
        // This comes from Intel SDM volume 3, chapter 8.4.  The vector specifies a page aligned
        // address where execution should start.  cs.base is the offset for the code segment with an
        // RIP of 0.  The cs.selector is just the base shifted right by 4 bits.
        let mut sregs = vcpu.get_sregs()?;
        sregs.cs.base = (vector as u64) << 12;
        sregs.cs.selector = (vector as u16) << 8;

        // Set CR0 to its INIT value per the manual.  Application processors won't boot with the CR0
        // protected mode and paging bits set by setup_sregs().  Kernel APIC doesn't have this
        // issue, probably because it uses MSRs instead of MMIO, so it's less affected when the AP's
        // state (CR3 etc.) doesn't reflect changes that Linux made while booting vcpu 0.
        sregs.cr0 = X86_CR0_INIT;
        vcpu.set_sregs(&sregs)?;

        let mut regs = vcpu.get_regs()?;
        regs.rip = 0;
        vcpu.set_regs(&regs)?;

        Ok(())
    }

    /// Checks if the specified VCPU is in a runnable state.
    fn is_runnable(&self, vcpu_id: usize) -> bool {
        self.apics[vcpu_id].lock().get_mp_state() == MPState::Runnable
    }
}

impl Drop for Dropper {
    fn drop(&mut self) {
        for evt in self.kill_evts.split_off(0).into_iter() {
            if let Err(e) = evt.signal() {
                error!("Failed to kill UserspaceIrqChip worker thread: {}", e);
                return;
            }
        }
        for thread in self.workers.split_off(0).into_iter() {
            match thread.join() {
                Ok(r) => {
                    if let Err(e) = r {
                        error!("UserspaceIrqChip worker thread exited with error: {}", e);
                    }
                }
                Err(e) => error!("UserspaceIrqChip worker thread panicked: {:?}", e),
            }
        }
    }
}

impl<V: VcpuX86_64 + 'static> UserspaceIrqChip<V> {
    fn register_irq_event(
        &mut self,
        irq: u32,
        irq_event: &Event,
        resample_event: Option<&Event>,
        source: IrqEventSource,
    ) -> Result<Option<IrqEventIndex>> {
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
    }

    fn unregister_irq_event(&mut self, irq: u32, irq_event: &Event) -> Result<()> {
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
    }
}

impl<V: VcpuX86_64 + 'static> IrqChip for UserspaceIrqChip<V> {
    fn add_vcpu(&mut self, vcpu_id: usize, vcpu: &dyn Vcpu) -> Result<()> {
        let vcpu: &V = vcpu
            .downcast_ref()
            .expect("UserspaceIrqChip::add_vcpu called with incorrect vcpu type");
        self.vcpus.lock()[vcpu_id] = Some(vcpu.try_clone()?);
        Ok(())
    }

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

    fn route_irq(&mut self, route: IrqRoute) -> Result<()> {
        self.routes.lock().add(route)
    }

    fn set_irq_routes(&mut self, routes: &[IrqRoute]) -> Result<()> {
        self.routes.lock().replace_all(routes)
    }

    fn irq_event_tokens(&self) -> Result<Vec<(IrqEventIndex, IrqEventSource, Event)>> {
        let mut tokens: Vec<(IrqEventIndex, IrqEventSource, Event)> = Vec::new();
        for (index, evt) in self.irq_events.lock().iter().enumerate() {
            if let Some(evt) = evt {
                tokens.push((index, evt.source.clone(), evt.event.try_clone()?));
            }
        }
        Ok(tokens)
    }

    fn service_irq(&mut self, irq: u32, level: bool) -> Result<()> {
        for route in self.routes.lock()[irq as usize].iter() {
            match *route {
                IrqSource::Irqchip {
                    chip: IrqSourceChip::PicPrimary,
                    pin,
                }
                | IrqSource::Irqchip {
                    chip: IrqSourceChip::PicSecondary,
                    pin,
                } => {
                    self.pic.lock().service_irq(pin as u8, level);
                }
                IrqSource::Irqchip {
                    chip: IrqSourceChip::Ioapic,
                    pin,
                } => {
                    self.ioapic.lock().service_irq(pin as usize, level);
                }
                // service_irq's level parameter is ignored for MSIs.  MSI data specifies the level.
                IrqSource::Msi { address, data } => self.send_msi(address as u32, data),
                _ => {
                    error!("Unexpected route source {:?}", route);
                    return Err(Error::new(libc::EINVAL));
                }
            }
        }
        Ok(())
    }

    /// Services an IRQ event by asserting then deasserting an IRQ line.  The associated Event
    /// that triggered the irq event will be read from.  If the irq is associated with a resample
    /// Event, then the deassert will only happen after an EOI is broadcast for a vector
    /// associated with the irq line.
    /// For UserspaceIrqChip, this function identifies the destination(s) of the irq: PIC, IOAPIC,
    /// or APIC (MSI).  If it's a PIC or IOAPIC route, we attempt to call service_irq on those
    /// chips.  If the IOAPIC is unable to be immediately locked, we add the irq to the
    /// delayed_ioapic_irq_events (though we still read from the Event that triggered the irq
    /// event).  If it's an MSI route, we call send_msi to decode the MSI and send it to the
    /// destination APIC(s).
    fn service_irq_event(&mut self, event_index: IrqEventIndex) -> Result<()> {
        let irq_events = self.irq_events.lock();
        let evt = if let Some(evt) = &irq_events[event_index] {
            evt
        } else {
            return Ok(());
        };
        evt.event.wait()?;

        for route in self.routes.lock()[evt.gsi as usize].iter() {
            match *route {
                IrqSource::Irqchip {
                    chip: IrqSourceChip::PicPrimary,
                    pin,
                }
                | IrqSource::Irqchip {
                    chip: IrqSourceChip::PicSecondary,
                    pin,
                } => {
                    let mut pic = self.pic.lock();
                    if evt.resample_event.is_some() {
                        pic.service_irq(pin as u8, true);
                    } else {
                        pic.service_irq(pin as u8, true);
                        pic.service_irq(pin as u8, false);
                    }
                }
                IrqSource::Irqchip {
                    chip: IrqSourceChip::Ioapic,
                    pin,
                } => {
                    if let Ok(mut ioapic) = self.ioapic.try_lock() {
                        if evt.resample_event.is_some() {
                            ioapic.service_irq(pin as usize, true);
                        } else {
                            ioapic.service_irq(pin as usize, true);
                            ioapic.service_irq(pin as usize, false);
                        }
                    } else {
                        let mut delayed_events = self.delayed_ioapic_irq_events.lock();
                        delayed_events.events.push(event_index);
                        delayed_events.trigger.signal().unwrap();
                    }
                }
                IrqSource::Msi { address, data } => self.send_msi(address as u32, data),
                _ => {
                    error!("Unexpected route source {:?}", route);
                    return Err(Error::new(libc::EINVAL));
                }
            }
        }

        Ok(())
    }

    /// Broadcasts an end of interrupt.  For UserspaceIrqChip this sends the EOI to the ioapic.
    fn broadcast_eoi(&self, vector: u8) -> Result<()> {
        self.ioapic.lock().end_of_interrupt(vector);
        Ok(())
    }

    /// Injects any pending interrupts for `vcpu`.
    ///
    /// For UserspaceIrqChip this:
    ///   * Injects a PIC interrupt, if vcpu_id is 0 and vcpu is ready for interrupt
    ///   * Injects an APIC fixed interrupt, if vcpu is ready for interrupt and PIC didn't inject
    ///   * Injects APIC NMIs
    ///   * Handles APIC INIT IPIs
    ///   * Handles APIC SIPIs
    ///   * Requests an interrupt window, if PIC or APIC still has pending interrupts for this vcpu
    fn inject_interrupts(&self, vcpu: &dyn Vcpu) -> Result<()> {
        let vcpu: &V = vcpu
            .downcast_ref()
            .expect("UserspaceIrqChip::add_vcpu called with incorrect vcpu type");
        let vcpu_id = vcpu.id();
        let mut vcpu_ready = vcpu.ready_for_interrupt();

        let mut pic_needs_window = false;
        if vcpu_id == 0 {
            let mut pic = self.pic.lock();
            if vcpu_ready {
                if let Some(vector) = pic.get_external_interrupt() {
                    vcpu.interrupt(vector as u32)?;
                    self.apics[vcpu_id].lock().set_mp_state(&MPState::Runnable);
                    // Already injected a PIC interrupt, so APIC fixed interrupt can't be injected.
                    vcpu_ready = false;
                }
            }
            pic_needs_window = pic.interrupt_requested();
        }

        let irqs = self.apics[vcpu_id].lock().get_pending_irqs(vcpu_ready);
        if let Some(vector) = irqs.fixed {
            let do_interrupt = {
                let mut apic = self.apics[vcpu_id].lock();
                match apic.get_mp_state() {
                    MPState::Runnable | MPState::Halted => {
                        // APIC interrupts should only be injectable when the MPState is
                        // Halted or Runnable.
                        apic.set_mp_state(&MPState::Runnable);
                        true
                    }
                    s => {
                        // This shouldn't happen, but log a helpful error if it does.
                        error!("Interrupt cannot be injected while in state: {:?}", s);
                        false
                    }
                }
            };

            if do_interrupt {
                vcpu.interrupt(vector as u32)?;
            }
        }
        for _ in 0..irqs.nmis {
            let prev_state = self.apics[vcpu_id].lock().get_mp_state();
            vcpu.inject_nmi()?;
            self.apics[vcpu_id].lock().set_mp_state(&MPState::Runnable);
            info!(
                "Delivered NMI to cpu {}, mp_state was {:?}, now is {:?}",
                vcpu_id,
                prev_state,
                MPState::Runnable
            );
        }
        if irqs.init {
            {
                let mut apic = self.apics[vcpu_id].lock();
                apic.load_reset_state();
                apic.set_mp_state(&MPState::InitReceived);
            }
            info!("Delivered INIT IPI to cpu {}", vcpu_id);
        }
        if let Some(vector) = irqs.startup {
            // If our state is not MPState::InitReceived then this is probably
            // the second SIPI in the INIT-SIPI-SIPI sequence; ignore.
            if self.apics[vcpu_id].lock().get_mp_state() == MPState::InitReceived {
                self.deliver_startup(vcpu, vector)?;
                self.apics[vcpu_id].lock().set_mp_state(&MPState::Runnable);
                info!("Delivered SIPI to cpu {}", vcpu_id);
            }
        }

        let needs_window = pic_needs_window || irqs.needs_window;
        vcpu.set_interrupt_window_requested(needs_window);

        Ok(())
    }

    /// Notifies the irq chip that the specified VCPU has executed a halt instruction.
    /// For `UserspaceIrqChip`, it sets the APIC's mp_state to `MPState::Halted`.
    fn halted(&self, vcpu_id: usize) {
        self.apics[vcpu_id].lock().set_mp_state(&MPState::Halted)
    }

    /// Blocks until `vcpu` is in a runnable state or until interrupted by
    /// `IrqChip::kick_halted_vcpus`.  Returns `VcpuRunState::Runnable if vcpu is runnable, or
    /// `VcpuRunState::Interrupted` if the wait was interrupted.
    /// For `UserspaceIrqChip`, if the APIC isn't `MPState::Runnable`, sleep until there are new
    /// interrupts pending on the APIC, inject the interrupts, and go back to sleep if still not
    /// runnable.
    fn wait_until_runnable(&self, vcpu: &dyn Vcpu) -> Result<VcpuRunState> {
        let vcpu_id = vcpu.id();
        let waiter = &self.waiters[vcpu_id];
        let mut interrupted_lock = waiter.mtx.lock();
        loop {
            if *interrupted_lock {
                *interrupted_lock = false;
                info!("wait_until_runnable interrupted on cpu {}", vcpu_id);
                return Ok(VcpuRunState::Interrupted);
            }
            if self.is_runnable(vcpu_id) {
                return Ok(VcpuRunState::Runnable);
            }

            self.inject_interrupts(vcpu)?;
            if self.is_runnable(vcpu_id) {
                return Ok(VcpuRunState::Runnable);
            }
            interrupted_lock = waiter.cvar.wait(interrupted_lock);
        }
    }

    /// Makes unrunnable VCPUs return immediately from `wait_until_runnable`.
    /// For UserspaceIrqChip, every vcpu gets kicked so its current or next call to
    /// `wait_until_runnable` will immediately return false.  After that one kick, subsequent
    /// `wait_until_runnable` calls go back to waiting for runnability normally.
    fn kick_halted_vcpus(&self) {
        for waiter in self.waiters.iter() {
            waiter.set_and_notify(/*interrupted=*/ true);
        }
    }

    fn get_mp_state(&self, vcpu_id: usize) -> Result<MPState> {
        Ok(self.apics[vcpu_id].lock().get_mp_state())
    }

    fn set_mp_state(&mut self, vcpu_id: usize, state: &MPState) -> Result<()> {
        self.apics[vcpu_id].lock().set_mp_state(state);
        Ok(())
    }

    fn try_clone(&self) -> Result<Self> {
        // kill_evts and timer_descriptors don't change, so they could be a plain Vec with each
        // element cloned.  But the Arc<Mutex> avoids a quadratic number of open descriptors from
        // cloning, and those fields aren't performance critical.
        Ok(UserspaceIrqChip {
            vcpus: self.vcpus.clone(),
            waiters: self.waiters.clone(),
            routes: self.routes.clone(),
            pit: self.pit.clone(),
            pic: self.pic.clone(),
            ioapic: self.ioapic.clone(),
            ioapic_pins: self.ioapic_pins,
            apics: self.apics.clone(),
            timer_descriptors: self.timer_descriptors.clone(),
            delayed_ioapic_irq_events: self.delayed_ioapic_irq_events.clone(),
            irq_events: self.irq_events.clone(),
            dropper: self.dropper.clone(),
        })
    }

    // TODO(srichman): factor out UserspaceIrqChip and KvmSplitIrqChip::finalize_devices
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

        // Insert self into mmio_bus for handling APIC mmio
        mmio_bus
            .insert_sync(
                Arc::new(self.try_clone()?),
                APIC_BASE_ADDRESS,
                APIC_MEM_LENGTH_BYTES,
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

        // Make sure all future irq numbers are >= self.ioapic_pins
        let mut irq_num = resources.allocate_irq().unwrap();
        while irq_num < self.ioapic_pins as u32 {
            irq_num = resources.allocate_irq().unwrap();
        }

        // Spawn timer threads here instead of in new(), in case crosvm is in sandbox mode.
        let mut dropper = self.dropper.lock();
        for (i, descriptor) in self.timer_descriptors.iter().enumerate() {
            let mut worker = TimerWorker {
                id: i,
                apic: self.apics[i].clone(),
                descriptor: *descriptor,
                vcpus: self.vcpus.clone(),
                waiter: self.waiters[i].clone(),
            };
            dropper.kill_evts.push(Event::new()?);
            let evt = dropper.kill_evts[i].try_clone()?;
            let worker_thread = thread::Builder::new()
                .name(format!("UserspaceIrqChip timer worker {}", i))
                .spawn(move || worker.run(evt))?;
            dropper.workers.push(worker_thread);
        }

        Ok(())
    }

    /// The UserspaceIrqChip's ioapic may be locked because a vcpu thread is currently writing to
    /// the ioapic, and the ioapic may be blocking on adding MSI routes, which requires blocking
    /// tube communication back to the main thread.  Thus, we do not want the main thread to
    /// block on a locked ioapic, so any irqs that could not be serviced because the ioapic could
    /// not be immediately locked are added to the delayed_ioapic_irq_events Vec. This function
    /// processes each delayed event in the vec each time it's called. If the ioapic is still
    /// locked, we keep the queued irqs for the next time this function is called.
    fn process_delayed_irq_events(&mut self) -> Result<()> {
        let irq_events = self.irq_events.lock();
        let mut delayed_events = self.delayed_ioapic_irq_events.lock();
        delayed_events.events.retain(|&event_index| {
            if let Some(evt) = &irq_events[event_index] {
                if let Ok(mut ioapic) = self.ioapic.try_lock() {
                    if evt.resample_event.is_some() {
                        ioapic.service_irq(evt.gsi as usize, true);
                    } else {
                        ioapic.service_irq(evt.gsi as usize, true);
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

        if delayed_events.events.is_empty() {
            delayed_events.trigger.wait()?;
        }
        Ok(())
    }

    fn irq_delayed_event_token(&self) -> Result<Option<Event>> {
        Ok(Some(
            self.delayed_ioapic_irq_events.lock().trigger.try_clone()?,
        ))
    }

    fn check_capability(&self, c: IrqChipCap) -> bool {
        match c {
            IrqChipCap::TscDeadlineTimer => false,
            IrqChipCap::X2Apic => false,
        }
    }
}

impl<V: VcpuX86_64 + 'static> BusDevice for UserspaceIrqChip<V> {
    fn debug_label(&self) -> String {
        "UserspaceIrqChip APIC".to_string()
    }
    fn device_id(&self) -> DeviceId {
        CrosvmDeviceId::UserspaceIrqChip.into()
    }
}

impl<V: VcpuX86_64 + 'static> Suspendable for UserspaceIrqChip<V> {}

impl<V: VcpuX86_64 + 'static> BusDeviceSync for UserspaceIrqChip<V> {
    fn read(&self, info: BusAccessInfo, data: &mut [u8]) {
        self.apics[info.id].lock().read(info.offset, data)
    }
    fn write(&self, info: BusAccessInfo, data: &[u8]) {
        let msg = self.apics[info.id].lock().write(info.offset, data);
        if let Some(m) = msg {
            self.handle_msg(m);
        }
    }
}

impl<V: VcpuX86_64 + 'static> IrqChipX86_64 for UserspaceIrqChip<V> {
    fn try_box_clone(&self) -> Result<Box<dyn IrqChipX86_64>> {
        Ok(Box::new(self.try_clone()?))
    }

    fn as_irq_chip(&self) -> &dyn IrqChip {
        self
    }

    fn as_irq_chip_mut(&mut self) -> &mut dyn IrqChip {
        self
    }

    fn get_pic_state(&self, select: PicSelect) -> Result<PicState> {
        Ok(self.pic.lock().get_pic_state(select))
    }

    fn set_pic_state(&mut self, select: PicSelect, state: &PicState) -> Result<()> {
        self.pic.lock().set_pic_state(select, state);
        Ok(())
    }

    fn get_ioapic_state(&self) -> Result<IoapicState> {
        Ok(self.ioapic.lock().get_ioapic_state())
    }

    fn set_ioapic_state(&mut self, state: &IoapicState) -> Result<()> {
        self.ioapic.lock().set_ioapic_state(state);
        Ok(())
    }

    fn get_lapic_state(&self, vcpu_id: usize) -> Result<LapicState> {
        Ok(self.apics[vcpu_id].lock().get_state())
    }

    fn set_lapic_state(&mut self, vcpu_id: usize, state: &LapicState) -> Result<()> {
        self.apics[vcpu_id].lock().set_state(state);
        Ok(())
    }

    /// Get the lapic frequency in Hz
    fn lapic_frequency(&self) -> u32 {
        Apic::frequency()
    }

    fn get_pit(&self) -> Result<PitState> {
        Ok(self.pit.lock().get_pit_state())
    }

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

/// Condition variable used by `UserspaceIrqChip::wait_until_runnable`.
#[derive(Default)]
struct Waiter {
    // mtx stores an "interrupted" bool that's true if `kick_halted_vcpus` has been called.
    mtx: Mutex<bool>,
    cvar: Condvar,
}

impl Waiter {
    /// Wakes up `wait_until_runnable` to recheck the interrupted flag and vcpu runnable state.
    pub fn notify(&self) {
        let _lock = self.mtx.lock();
        self.cvar.notify_all();
    }

    /// Sets the interrupted flag, and wakes up `wait_until_runnable` to recheck the interrupted
    /// flag and vcpu runnable state.  If `interrupted` is true, then `wait_until_runnable` should
    /// stop waiting for a runnable vcpu and return immediately.
    pub fn set_and_notify(&self, interrupted: bool) {
        let mut interrupted_lock = self.mtx.lock();
        *interrupted_lock = interrupted;
        self.cvar.notify_all();
    }
}

/// Worker thread for polling timer events and sending them to an APIC.
struct TimerWorker<V: VcpuX86_64> {
    id: usize,
    apic: Arc<Mutex<Apic>>,
    vcpus: Arc<Mutex<Vec<Option<V>>>>,
    descriptor: Descriptor,
    waiter: Arc<Waiter>,
}

impl<V: VcpuX86_64> TimerWorker<V> {
    fn run(&mut self, kill_evt: Event) -> TimerWorkerResult<()> {
        #[derive(EventToken)]
        enum Token {
            // The timer expired.
            TimerExpire,
            // The parent thread requested an exit.
            Kill,
        }

        let wait_ctx: WaitContext<Token> = WaitContext::build_with(&[
            (&self.descriptor, Token::TimerExpire),
            (&kill_evt, Token::Kill),
        ])
        .map_err(TimerWorkerError::CreateWaitContext)?;

        loop {
            let events = wait_ctx.wait().map_err(TimerWorkerError::WaitError)?;
            for event in events.iter().filter(|e| e.is_readable) {
                match event.token {
                    Token::TimerExpire => {
                        self.apic.lock().handle_timer_expiration();
                        if let Some(Some(vcpu)) = self.vcpus.lock().get(self.id) {
                            vcpu.set_interrupt_window_requested(true);
                        }
                        self.waiter.notify();
                    }
                    Token::Kill => return Ok(()),
                }
            }
        }
    }
}

#[derive(Debug)]
enum TimerWorkerError {
    /// Creating WaitContext failed.
    CreateWaitContext(Error),
    /// Error while waiting for events.
    WaitError(Error),
}

impl Display for TimerWorkerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::TimerWorkerError::*;

        match self {
            CreateWaitContext(e) => write!(f, "failed to create event context: {}", e),
            WaitError(e) => write!(f, "failed to wait for events: {}", e),
        }
    }
}

impl std::error::Error for TimerWorkerError {}

type TimerWorkerResult<T> = std::result::Result<T, TimerWorkerError>;

// TODO(b/237977699): remove once test are re-enabled.
#[allow(unused)]
#[cfg(test)]
mod tests {
    use std::os::raw::c_int;
    use std::time::Duration;
    use std::time::Instant;

    use base::EventWaitResult;
    use hypervisor::CpuId;
    use hypervisor::CpuIdEntry;
    use hypervisor::DebugRegs;
    use hypervisor::DestinationMode;
    use hypervisor::Fpu;
    use hypervisor::HypervHypercall;
    use hypervisor::IoParams;
    use hypervisor::IoapicRedirectionTableEntry;
    use hypervisor::Level;
    use hypervisor::PitRWMode;
    use hypervisor::Register;
    use hypervisor::Regs;
    use hypervisor::Sregs;
    use hypervisor::TriggerMode;
    use hypervisor::Vcpu;
    use hypervisor::VcpuExit;
    use hypervisor::VcpuRunHandle;
    use resources::AddressRange;
    use resources::SystemAllocatorConfig;
    use vm_memory::GuestAddress;

    use super::super::tests::*;
    use super::super::DestinationShorthand;
    use super::*;

    const APIC_ID: u64 = 0x20;
    const TPR: u64 = 0x80;
    const EOI: u64 = 0xB0;
    const LOCAL_TIMER: u64 = 0x320;
    const TIMER_INITIAL_COUNT: u64 = 0x380;
    const TIMER_DIVIDE_CONTROL: u64 = 0x3E0;
    const TIMER_MODE_PERIODIC: u32 = 1 << 17;
    const TIMER_FREQ_DIVIDE_BY_1: u8 = 0b1011;
    const TEST_SLEEP_DURATION: Duration = Duration::from_millis(50);

    /// Helper function for setting up a UserspaceIrqChip.
    fn get_chip(num_vcpus: usize) -> UserspaceIrqChip<FakeVcpu> {
        get_chip_with_clock(num_vcpus, Arc::new(Mutex::new(Clock::new())))
    }

    fn get_chip_with_clock(
        num_vcpus: usize,
        clock: Arc<Mutex<Clock>>,
    ) -> UserspaceIrqChip<FakeVcpu> {
        let (_, irq_tube) = Tube::pair().unwrap();
        let mut chip =
            UserspaceIrqChip::<FakeVcpu>::new_with_clock(num_vcpus, irq_tube, None, clock)
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

        let mmio_bus = Bus::new();
        let io_bus = Bus::new();
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

        let mmio_bus = Bus::new();
        let io_bus = Bus::new();
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

    // TODO(b/237977699): remove reliance on sleep
    // #[test]
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

    // TODO(b/237977699): remove reliance on sleep
    // #[test]
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

    // TODO(b/237977699): remove reliance on sleep
    // #[test]
    fn apic_timer() {
        let clock = Arc::new(Mutex::new(Clock::new()));
        let mut chip = get_chip_with_clock(2, clock.clone());
        let vcpus = get_vcpus(&chip);
        let cycle_length = chip.apics[0].lock().get_cycle_length();
        assert_eq!(chip.apics[1].lock().get_cycle_length(), cycle_length);

        // finalize_devices() starts the timer worker threads.
        let mmio_bus = Bus::new();
        let io_bus = Bus::new();
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
        chip.finalize_devices(&mut resources, &io_bus, &mmio_bus)
            .expect("failed to finalize devices");

        let val = TIMER_MODE_PERIODIC | 111;
        chip.write(
            BusAccessInfo {
                id: 0,
                address: APIC_BASE_ADDRESS + LOCAL_TIMER,
                offset: LOCAL_TIMER,
            },
            &val.to_le_bytes(),
        );
        chip.write(
            BusAccessInfo {
                id: 0,
                address: APIC_BASE_ADDRESS + TIMER_DIVIDE_CONTROL,
                offset: TIMER_DIVIDE_CONTROL,
            },
            &[TIMER_FREQ_DIVIDE_BY_1, 0, 0, 0],
        );
        chip.write(
            BusAccessInfo {
                id: 0,
                address: APIC_BASE_ADDRESS + TIMER_INITIAL_COUNT,
                offset: TIMER_INITIAL_COUNT,
            },
            &10u32.to_le_bytes(),
        );
        let val = TIMER_MODE_PERIODIC | 222;
        chip.write(
            BusAccessInfo {
                id: 1,
                address: APIC_BASE_ADDRESS + LOCAL_TIMER,
                offset: LOCAL_TIMER,
            },
            &val.to_le_bytes(),
        );
        chip.write(
            BusAccessInfo {
                id: 1,
                address: APIC_BASE_ADDRESS + TIMER_DIVIDE_CONTROL,
                offset: TIMER_DIVIDE_CONTROL,
            },
            &[TIMER_FREQ_DIVIDE_BY_1, 0, 0, 0],
        );
        chip.write(
            BusAccessInfo {
                id: 1,
                address: APIC_BASE_ADDRESS + TIMER_INITIAL_COUNT,
                offset: TIMER_INITIAL_COUNT,
            },
            &20u32.to_le_bytes(),
        );

        // Neither timer should fire after 9ns.
        clock.lock().add_ns(9 * cycle_length.as_nanos() as u64);
        thread::sleep(TEST_SLEEP_DURATION);
        chip.inject_interrupts(&vcpus[0]).unwrap();
        chip.inject_interrupts(&vcpus[1]).unwrap();
        assert_eq!(vcpus[0].clear_injected(), None);
        assert_eq!(vcpus[1].clear_injected(), None);

        // Apic 0 should fire after 10ns.
        clock.lock().add_ns(1 * cycle_length.as_nanos() as u64);
        thread::sleep(TEST_SLEEP_DURATION);
        chip.inject_interrupts(&vcpus[0]).unwrap();
        chip.inject_interrupts(&vcpus[1]).unwrap();
        assert_eq!(vcpus[0].clear_injected(), Some(111));
        assert_eq!(vcpus[1].clear_injected(), None);
        chip.write(
            BusAccessInfo {
                id: 0,
                address: APIC_BASE_ADDRESS + EOI,
                offset: EOI,
            },
            &[0; 4],
        );

        clock.lock().add_ns(9 * cycle_length.as_nanos() as u64);
        thread::sleep(TEST_SLEEP_DURATION);
        chip.inject_interrupts(&vcpus[0]).unwrap();
        chip.inject_interrupts(&vcpus[1]).unwrap();
        assert_eq!(vcpus[0].clear_injected(), None);
        assert_eq!(vcpus[1].clear_injected(), None);

        // Apic 1 should fire after 20ns, and apic 0 should fire again.
        clock.lock().add_ns(1 * cycle_length.as_nanos() as u64);
        thread::sleep(TEST_SLEEP_DURATION);
        chip.inject_interrupts(&vcpus[0]).unwrap();
        chip.inject_interrupts(&vcpus[1]).unwrap();
        assert_eq!(vcpus[0].clear_injected(), Some(111));
        assert_eq!(vcpus[1].clear_injected(), Some(222));
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

        fn take_run_handle(&self, _signal_num: Option<c_int>) -> Result<VcpuRunHandle> {
            unimplemented!()
        }
        fn run(&mut self, _run_handle: &VcpuRunHandle) -> Result<VcpuExit> {
            unimplemented!()
        }
        fn set_immediate_exit(&self, _exit: bool) {}
        fn set_local_immediate_exit(_exit: bool) {}
        fn set_local_immediate_exit_fn(&self) -> extern "C" fn() {
            extern "C" fn f() {
                FakeVcpu::set_local_immediate_exit(true);
            }
            f
        }
        fn handle_mmio(
            &self,
            _handle_fn: &mut dyn FnMut(IoParams) -> Option<[u8; 8]>,
        ) -> Result<()> {
            unimplemented!()
        }
        fn handle_io(&self, _handle_fn: &mut dyn FnMut(IoParams) -> Option<[u8; 8]>) -> Result<()> {
            unimplemented!()
        }
        fn handle_hyperv_hypercall(
            &self,
            _func: &mut dyn FnMut(HypervHypercall) -> u64,
        ) -> Result<()> {
            unimplemented!()
        }
        fn handle_rdmsr(&self, _data: u64) -> Result<()> {
            unimplemented!()
        }
        fn handle_wrmsr(&self) {
            unimplemented!()
        }
        fn pvclock_ctrl(&self) -> Result<()> {
            unimplemented!()
        }
        fn set_signal_mask(&self, _signals: &[c_int]) -> Result<()> {
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
        fn get_debugregs(&self) -> Result<DebugRegs> {
            unimplemented!()
        }
        fn set_debugregs(&self, _debugregs: &DebugRegs) -> Result<()> {
            unimplemented!()
        }
        fn get_xcrs(&self) -> Result<Vec<Register>> {
            unimplemented!()
        }
        fn set_xcrs(&self, _xcrs: &[Register]) -> Result<()> {
            unimplemented!()
        }
        fn get_msrs(&self, _msrs: &mut Vec<Register>) -> Result<()> {
            unimplemented!()
        }
        fn set_msrs(&self, _msrs: &[Register]) -> Result<()> {
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
        fn get_tsc_offset(&self) -> Result<u64> {
            unimplemented!()
        }
        fn set_tsc_offset(&self, _offset: u64) -> Result<()> {
            unimplemented!()
        }
    }
}

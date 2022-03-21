// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::marker::{Send, Sized};

use crate::{Bus, IrqEdgeEvent, IrqLevelEvent};
use base::{Event, Result};
use hypervisor::{IrqRoute, MPState, Vcpu};
use resources::SystemAllocator;

mod kvm;
pub use self::kvm::KvmKernelIrqChip;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub use self::kvm::{AARCH64_GIC_NR_IRQS, AARCH64_GIC_NR_SPIS};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use self::kvm::KvmSplitIrqChip;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86_64;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use x86_64::*;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
mod aarch64;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub use aarch64::*;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod pic;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use pic::*;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod ioapic;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use ioapic::*;

pub type IrqEventIndex = usize;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
struct IrqEvent {
    event: Event,
    gsi: u32,
    resample_event: Option<Event>,
}

/// Trait that abstracts interactions with interrupt controllers.
///
/// Each VM will have one IrqChip instance which is responsible for routing IRQ lines and
/// registering IRQ events. Depending on the implementation, the IrqChip may interact with an
/// underlying hypervisor API or emulate devices in userspace.
///
/// This trait is generic over a Vcpu type because some IrqChip implementations can support
/// multiple hypervisors with a single implementation.
pub trait IrqChip: Send {
    /// Add a vcpu to the irq chip.
    fn add_vcpu(&mut self, vcpu_id: usize, vcpu: &dyn Vcpu) -> Result<()>;

    /// Register an event with edge-trigger semantic that can trigger an interrupt for a particular GSI.
    fn register_edge_irq_event(
        &mut self,
        irq: u32,
        irq_event: &IrqEdgeEvent,
    ) -> Result<Option<IrqEventIndex>>;

    /// Unregister an event with edge-trigger semantic for a particular GSI.
    fn unregister_edge_irq_event(&mut self, irq: u32, irq_event: &IrqEdgeEvent) -> Result<()>;

    /// Register an event with level-trigger semantic that can trigger an interrupt for a particular GSI.
    fn register_level_irq_event(
        &mut self,
        irq: u32,
        irq_event: &IrqLevelEvent,
    ) -> Result<Option<IrqEventIndex>>;

    /// Unregister an event with level-trigger semantic for a particular GSI.
    fn unregister_level_irq_event(&mut self, irq: u32, irq_event: &IrqLevelEvent) -> Result<()>;

    /// Route an IRQ line to an interrupt controller, or to a particular MSI vector.
    fn route_irq(&mut self, route: IrqRoute) -> Result<()>;

    /// Replace all irq routes with the supplied routes
    fn set_irq_routes(&mut self, routes: &[IrqRoute]) -> Result<()>;

    /// Return a vector of all registered irq numbers and their associated events and event
    /// indices. These should be used by the main thread to wait for irq events.
    fn irq_event_tokens(&self) -> Result<Vec<(IrqEventIndex, u32, Event)>>;

    /// Either assert or deassert an IRQ line.  Sends to either an interrupt controller, or does
    /// a send_msi if the irq is associated with an MSI.
    fn service_irq(&mut self, irq: u32, level: bool) -> Result<()>;

    /// Service an IRQ event by asserting then deasserting an IRQ line. The associated Event
    /// that triggered the irq event will be read from. If the irq is associated with a resample
    /// Event, then the deassert will only happen after an EOI is broadcast for a vector
    /// associated with the irq line.
    fn service_irq_event(&mut self, event_index: IrqEventIndex) -> Result<()>;

    /// Broadcast an end of interrupt.
    fn broadcast_eoi(&self, vector: u8) -> Result<()>;

    /// Injects any pending interrupts for `vcpu`.
    fn inject_interrupts(&self, vcpu: &dyn Vcpu) -> Result<()>;

    /// Notifies the irq chip that the specified VCPU has executed a halt instruction.
    fn halted(&self, vcpu_id: usize);

    /// Blocks until `vcpu` is in a runnable state or until interrupted by
    /// `IrqChip::kick_halted_vcpus`.  Returns `VcpuRunState::Runnable if vcpu is runnable, or
    /// `VcpuRunState::Interrupted` if the wait was interrupted.
    fn wait_until_runnable(&self, vcpu: &dyn Vcpu) -> Result<VcpuRunState>;

    /// Makes unrunnable VCPUs return immediately from `wait_until_runnable`.
    /// For UserspaceIrqChip, every vcpu gets kicked so its current or next call to
    /// `wait_until_runnable` will immediately return false.  After that one kick, subsequent
    /// `wait_until_runnable` calls go back to waiting for runnability normally.
    fn kick_halted_vcpus(&self);

    /// Get the current MP state of the specified VCPU.
    fn get_mp_state(&self, vcpu_id: usize) -> Result<MPState>;

    /// Set the current MP state of the specified VCPU.
    fn set_mp_state(&mut self, vcpu_id: usize, state: &MPState) -> Result<()>;

    /// Attempt to create a shallow clone of this IrqChip instance.
    fn try_clone(&self) -> Result<Self>
    where
        Self: Sized;

    /// Finalize irqchip setup. Should be called once all devices have registered irq events and
    /// been added to the io_bus and mmio_bus.
    fn finalize_devices(
        &mut self,
        resources: &mut SystemAllocator,
        io_bus: &Bus,
        mmio_bus: &Bus,
    ) -> Result<()>;

    /// Process any irqs events that were delayed because of any locking issues.
    fn process_delayed_irq_events(&mut self) -> Result<()>;

    /// Return an event which is meant to trigger process of any irqs events that were delayed
    /// by calling process_delayed_irq_events(). This should be used by the main thread to wait
    /// for delayed irq event kick. It is process_delayed_irq_events() responsibility to read
    /// the event as long as there is no more irqs to be serviced.
    fn irq_delayed_event_token(&self) -> Result<Option<Event>>;

    /// Checks if a particular `IrqChipCap` is available.
    fn check_capability(&self, c: IrqChipCap) -> bool;
}

/// A capability the `IrqChip` can possibly expose.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum IrqChipCap {
    /// APIC TSC-deadline timer mode.
    TscDeadlineTimer,
    /// Extended xAPIC (x2APIC) standard.
    X2Apic,
}

/// A capability the `IrqChip` can possibly expose.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum VcpuRunState {
    Runnable,
    Interrupted,
}

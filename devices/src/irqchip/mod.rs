// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod kvm;
pub use self::kvm::KvmKernelIrqChip;

use std::marker::{Send, Sized};

use hypervisor::{IrqRoute, Vcpu};
use sys_util::{EventFd, Result};

/// Trait that abstracts interactions with interrupt controllers.
///
/// Each VM will have one IrqChip instance which is responsible for routing IRQ lines and
/// registering IRQ events. Depending on the implementation, the IrqChip may interact with an
/// underlying hypervisor API or emulate devices in userspace.
///
/// This trait is generic over a Vcpu type because some IrqChip implementations can support
/// multiple hypervisors with a single implementation.
pub trait IrqChip<V: Vcpu>: Send + Sized {
    /// Add a vcpu to the irq chip.
    fn add_vcpu(&mut self, vcpu_id: usize, vcpu: V) -> Result<()>;

    /// Register an event that can trigger an interrupt for a particular GSI.
    fn register_irq_event(
        &mut self,
        irq: u32,
        irq_event: &EventFd,
        resample_event: Option<&EventFd>,
    ) -> Result<()>;

    /// Unregister an event for a particular GSI.
    fn unregister_irq_event(
        &mut self,
        irq: u32,
        irq_event: &EventFd,
        resample_event: Option<&EventFd>,
    ) -> Result<()>;

    /// Route an IRQ line to an interrupt controller, or to a particular MSI vector.
    fn route_irq(&mut self, route: IrqRoute) -> Result<()>;

    /// Return a vector of all registered irq numbers and their associated events.  To be used by
    /// the main thread to wait for irq events to be triggered.
    fn irq_event_tokens(&self) -> Result<Vec<(u32, EventFd)>>;

    /// Either assert or deassert an IRQ line.  Sends to either an interrupt controller, or does
    /// a send_msi if the irq is associated with an MSI.
    fn service_irq(&mut self, irq: u32, level: bool) -> Result<()>;

    /// Broadcast an end of interrupt.
    fn broadcast_eoi(&mut self, vector: u8) -> Result<()>;

    /// Return true if there is a pending interrupt for the specified vcpu.
    fn interrupt_requested(&self, vcpu_id: usize) -> bool;

    /// Check if the specified vcpu has any pending interrupts. Returns None for no interrupts,
    /// otherwise Some(u32) should be the injected interrupt vector.
    fn get_external_interrupt(&mut self, vcpu_id: usize) -> Result<Option<u32>>;

    /// Attempt to clone this IrqChip instance.
    fn try_clone(&self) -> Result<Self>;
}

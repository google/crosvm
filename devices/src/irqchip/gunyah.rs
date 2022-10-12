// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::Event;
use base::Result;
use hypervisor::gunyah::GunyahVm;
use hypervisor::DeviceKind;
use hypervisor::IrqRoute;
use hypervisor::MPState;
use hypervisor::Vcpu;

use crate::IrqChip;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use crate::IrqChipAArch64;
use crate::IrqChipCap;
use crate::IrqEdgeEvent;
use crate::IrqEventIndex;
use crate::IrqEventSource;
use crate::IrqLevelEvent;
use crate::VcpuRunState;

pub struct GunyahIrqChip {
    vm: GunyahVm,
}

impl GunyahIrqChip {
    pub fn new(vm: GunyahVm) -> Result<GunyahIrqChip> {
        Ok(GunyahIrqChip { vm })
    }
}

impl IrqChip for GunyahIrqChip {
    // GunyahIrqChip doesn't need to track VCPUs.
    fn add_vcpu(&mut self, _vcpu_id: usize, _vcpu: &dyn Vcpu) -> Result<()> {
        Ok(())
    }

    fn register_edge_irq_event(
        &mut self,
        irq: u32,
        irq_event: &IrqEdgeEvent,
        _source: IrqEventSource,
    ) -> Result<Option<IrqEventIndex>> {
        self.vm
            .register_irqfd(irq, irq_event.get_trigger(), false)?;
        Ok(None)
    }

    fn unregister_edge_irq_event(&mut self, irq: u32, irq_event: &IrqEdgeEvent) -> Result<()> {
        self.vm.unregister_irqfd(irq, irq_event.get_trigger())?;
        Ok(())
    }

    fn register_level_irq_event(
        &mut self,
        irq: u32,
        irq_event: &IrqLevelEvent,
        _source: IrqEventSource,
    ) -> Result<Option<IrqEventIndex>> {
        self.vm.register_irqfd(irq, irq_event.get_trigger(), true)?;
        Ok(None)
    }

    fn unregister_level_irq_event(&mut self, irq: u32, irq_event: &IrqLevelEvent) -> Result<()> {
        self.vm.unregister_irqfd(irq, irq_event.get_trigger())?;
        Ok(())
    }

    fn route_irq(&mut self, _route: IrqRoute) -> Result<()> {
        unimplemented!()
    }

    fn set_irq_routes(&mut self, _routes: &[IrqRoute]) -> Result<()> {
        unimplemented!()
    }

    /// Return a vector of all registered irq numbers and their associated events and event
    /// indices. These should be used by the main thread to wait for irq events.
    /// For the GunyahIrqChip, the kernel handles listening to irq events being triggered by
    /// devices, so this function always returns an empty Vec.
    fn irq_event_tokens(&self) -> Result<Vec<(IrqEventIndex, IrqEventSource, Event)>> {
        Ok(Vec::new())
    }

    fn service_irq(&mut self, _irq: u32, _level: bool) -> Result<()> {
        unimplemented!()
    }

    /// Service an IRQ event by asserting then deasserting an IRQ line. The associated Event
    /// that triggered the irq event will be read from. If the irq is associated with a resample
    /// Event, then the deassert will only happen after an EOI is broadcast for a vector
    /// associated with the irq line.
    /// This function should never be called on GunyahIrqChip.
    fn service_irq_event(&mut self, _event_index: IrqEventIndex) -> Result<()> {
        unreachable!();
    }

    /// Broadcast an end of interrupt.
    /// This should never be called on a GunyahIrqChip because a Gunyah vcpu should never exit
    /// with VcpuExit::IoapicEoi.
    fn broadcast_eoi(&self, _vector: u8) -> Result<()> {
        unreachable!();
    }

    /// Injects any pending interrupts for `vcpu`.
    /// For GunyahIrqChip this is a no-op because Gunyah is responsible for injecting all
    /// interrupts.
    fn inject_interrupts(&self, _vcpu: &dyn Vcpu) -> Result<()> {
        Ok(())
    }

    /// Notifies the irq chip that the specified VCPU has executed a halt instruction.
    /// For GunyahIrqChip this is a no-op because Gunyah handles VCPU blocking.
    fn halted(&self, _vcpu_id: usize) {}

    fn wait_until_runnable(&self, _vcpu: &dyn Vcpu) -> Result<VcpuRunState> {
        // Gunyah handles vCPU blocking. From userspace perspective, vCPU is always runnable.
        Ok(VcpuRunState::Runnable)
    }

    /// Makes unrunnable VCPUs return immediately from `wait_until_runnable`.
    /// For GunyahIrqChip this is a no-op because Gunyah handles VCPU blocking.
    fn kick_halted_vcpus(&self) {}

    fn get_mp_state(&self, _vcpu_id: usize) -> Result<MPState> {
        unimplemented!()
    }

    fn set_mp_state(&mut self, _vcpu_id: usize, _state: &MPState) -> Result<()> {
        unimplemented!()
    }

    fn try_clone(&self) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            vm: self.vm.try_clone()?,
        })
    }

    fn finalize_devices(
        &mut self,
        _resources: &mut resources::SystemAllocator,
        _io_bus: &crate::Bus,
        _mmio_bus: &crate::Bus,
    ) -> Result<()> {
        Ok(())
    }

    /// The GunyahIrqChip doesn't process irq events itself so this function does nothing.
    fn process_delayed_irq_events(&mut self) -> Result<()> {
        Ok(())
    }

    fn irq_delayed_event_token(&self) -> Result<Option<Event>> {
        Ok(None)
    }

    fn check_capability(&self, _c: IrqChipCap) -> bool {
        false
    }
}

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
impl IrqChipAArch64 for GunyahIrqChip {
    fn try_box_clone(&self) -> Result<Box<dyn IrqChipAArch64>> {
        Ok(Box::new(self.try_clone()?))
    }

    fn as_irq_chip(&self) -> &dyn IrqChip {
        self
    }

    fn as_irq_chip_mut(&mut self) -> &mut dyn IrqChip {
        self
    }

    fn get_vgic_version(&self) -> DeviceKind {
        DeviceKind::ArmVgicV3
    }

    fn finalize(&self) -> Result<()> {
        Ok(())
    }
}

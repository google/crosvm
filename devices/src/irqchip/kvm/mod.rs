// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::Bus;
use hypervisor::kvm::KvmVcpu;
use hypervisor::{IrqRoute, MPState};
use kvm_sys::kvm_mp_state;
use resources::SystemAllocator;
use sys_util::{error, Error, EventFd, Result};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86_64;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use x86_64::*;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
mod aarch64;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub use aarch64::*;

use crate::IrqChip;

/// This IrqChip only works with Kvm so we only implement it for KvmVcpu.
impl IrqChip<KvmVcpu> for KvmKernelIrqChip {
    /// Add a vcpu to the irq chip.
    fn add_vcpu(&mut self, vcpu_id: usize, vcpu: KvmVcpu) -> Result<()> {
        self.vcpus.lock()[vcpu_id] = Some(vcpu);
        Ok(())
    }

    /// Register an event that can trigger an interrupt for a particular GSI.
    fn register_irq_event(
        &mut self,
        irq: u32,
        irq_event: &EventFd,
        resample_event: Option<&EventFd>,
    ) -> Result<()> {
        self.vm.register_irqfd(irq, irq_event, resample_event)
    }

    /// Unregister an event for a particular GSI.
    fn unregister_irq_event(&mut self, irq: u32, irq_event: &EventFd) -> Result<()> {
        self.vm.unregister_irqfd(irq, irq_event)
    }

    /// Route an IRQ line to an interrupt controller, or to a particular MSI vector.
    fn route_irq(&mut self, route: IrqRoute) -> Result<()> {
        let mut routes = self.routes.lock();
        routes.retain(|r| r.gsi != route.gsi);

        routes.push(route);

        self.vm.set_gsi_routing(&*routes)
    }

    /// Replace all irq routes with the supplied routes
    fn set_irq_routes(&mut self, routes: &[IrqRoute]) -> Result<()> {
        let mut current_routes = self.routes.lock();
        *current_routes = routes.to_vec();

        self.vm.set_gsi_routing(&*current_routes)
    }

    /// Return a vector of all registered irq numbers and their associated events.  To be used by
    /// the main thread to wait for irq events to be triggered.
    /// For the KvmKernelIrqChip, the kernel handles listening to irq events being triggered by
    /// devices, so this function always returns an empty Vec.
    fn irq_event_tokens(&self) -> Result<Vec<(u32, EventFd)>> {
        Ok(Vec::new())
    }

    /// Either assert or deassert an IRQ line.  Sends to either an interrupt controller, or does
    /// a send_msi if the irq is associated with an MSI.
    /// For the KvmKernelIrqChip this simply calls the KVM_SET_IRQ_LINE ioctl.
    fn service_irq(&mut self, irq: u32, level: bool) -> Result<()> {
        self.vm.set_irq_line(irq, level)
    }

    /// Service an IRQ event by asserting then deasserting an IRQ line. The associated EventFd
    /// that triggered the irq event will be read from. If the irq is associated with a resample
    /// EventFd, then the deassert will only happen after an EOI is broadcast for a vector
    /// associated with the irq line.
    /// This function should never be called on KvmKernelIrqChip.
    fn service_irq_event(&mut self, _irq: u32) -> Result<()> {
        error!("service_irq_event should never be called for KvmKernelIrqChip");
        Ok(())
    }

    /// Broadcast an end of interrupt.
    /// This should never be called on a KvmKernelIrqChip because a KVM vcpu should never exit
    /// with the KVM_EXIT_EOI_BROADCAST reason when an in-kernel irqchip exists.
    fn broadcast_eoi(&mut self, _vector: u8) -> Result<()> {
        error!("broadcast_eoi should never be called for KvmKernelIrqChip");
        Ok(())
    }

    /// Return true if there is a pending interrupt for the specified vcpu.
    /// For the KvmKernelIrqChip this should always return false because KVM is responsible for
    /// injecting all interrupts.
    fn interrupt_requested(&self, _vcpu_id: usize) -> bool {
        false
    }

    /// Check if the specified vcpu has any pending interrupts. Returns None for no interrupts,
    /// otherwise Some(u32) should be the injected interrupt vector.
    /// For the KvmKernelIrqChip this should always return None because KVM is responsible for
    /// injecting all interrupts.
    fn get_external_interrupt(&mut self, _vcpu_id: usize) -> Result<Option<u32>> {
        Ok(None)
    }

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
        // Because the KvmKernelIrqchip struct contains arch-specific fields we leave the
        // cloning to arch-specific implementations
        self.arch_try_clone()
    }

    /// Finalize irqchip setup. Should be called once all devices have registered irq events and
    /// been added to the io_bus and mmio_bus.
    /// KvmKernelIrqChip does not need to do anything here.
    fn finalize_devices(
        &mut self,
        _resources: &mut SystemAllocator,
        _io_bus: &mut Bus,
        _mmio_bus: &mut Bus,
    ) -> Result<()> {
        Ok(())
    }

    /// The KvmKernelIrqChip doesn't process irq events itself so this function does nothing.
    fn process_delayed_irq_events(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use hypervisor::kvm::{Kvm, KvmVm};
    use hypervisor::{MPState, Vm};
    use sys_util::GuestMemory;

    use crate::irqchip::{IrqChip, KvmKernelIrqChip};

    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    use hypervisor::VmAarch64;
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    use hypervisor::VmX86_64;

    #[test]
    fn create_kvm_kernel_irqchip() {
        let kvm = Kvm::new().expect("failed to instantiate Kvm");
        let mem = GuestMemory::new(&[]).unwrap();
        let vm = KvmVm::new(&kvm, mem).expect("failed to instantiate vm");

        let mut chip = KvmKernelIrqChip::new(vm.try_clone().expect("failed to clone vm"), 1)
            .expect("failed to instantiate KvmKernelIrqChip");

        let vcpu = vm.create_vcpu(0).expect("failed to instantiate vcpu");
        chip.add_vcpu(0, vcpu).expect("failed to add vcpu");
    }

    #[test]
    fn mp_state() {
        let kvm = Kvm::new().expect("failed to instantiate Kvm");
        let mem = GuestMemory::new(&[]).unwrap();
        let vm = KvmVm::new(&kvm, mem).expect("failed to instantiate vm");

        let mut chip = KvmKernelIrqChip::new(vm.try_clone().expect("failed to clone vm"), 1)
            .expect("failed to instantiate KvmKernelIrqChip");

        let vcpu = vm.create_vcpu(0).expect("failed to instantiate vcpu");
        chip.add_vcpu(0, vcpu).expect("failed to add vcpu");

        let state = chip.get_mp_state(0).expect("failed to get mp state");
        assert_eq!(state, MPState::Runnable);

        chip.set_mp_state(0, &MPState::Stopped)
            .expect("failed to set mp state");

        let state = chip.get_mp_state(0).expect("failed to get mp state");
        assert_eq!(state, MPState::Stopped);
    }
}

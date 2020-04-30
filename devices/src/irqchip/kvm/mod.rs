// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use hypervisor::kvm::{KvmVcpu, KvmVm};
use hypervisor::IrqRoute;
use std::sync::Arc;
use sync::Mutex;
use sys_util::{EventFd, Result};

use crate::IrqChip;

/// IrqChip implementation where the entire IrqChip is emulated by KVM.
///
/// This implementation will use the KVM API to create and configure the in-kernel irqchip.
pub struct KvmKernelIrqChip {
    _vm: KvmVm,
    vcpus: Arc<Mutex<Vec<Option<KvmVcpu>>>>,
}

impl KvmKernelIrqChip {
    /// Construct a new KvmKernelIrqchip.
    pub fn new(vm: KvmVm, num_vcpus: usize) -> Result<KvmKernelIrqChip> {
        Ok(KvmKernelIrqChip {
            _vm: vm,
            vcpus: Arc::new(Mutex::new((0..num_vcpus).map(|_| None).collect())),
        })
    }
}

/// This IrqChip only works with Kvm so we only implement it for KvmVcpu.
impl IrqChip<KvmVcpu> for KvmKernelIrqChip {
    /// Add a vcpu to the irq chip.
    fn add_vcpu(&mut self, vcpu_id: usize, vcpu: KvmVcpu) -> Result<()> {
        self.vcpus.lock().insert(vcpu_id, Some(vcpu));
        Ok(())
    }

    /// Register an event that can trigger an interrupt for a particular GSI.
    fn register_irq_event(
        &mut self,
        _irq: u32,
        _irq_event: &EventFd,
        _resample_event: Option<&EventFd>,
    ) -> Result<()> {
        unimplemented!("register_irq_event for KvmKernelIrqChip is not yet implemented");
    }

    /// Unregister an event for a particular GSI.
    fn unregister_irq_event(
        &mut self,
        _irq: u32,
        _irq_event: &EventFd,
        _resample_event: Option<&EventFd>,
    ) -> Result<()> {
        unimplemented!("unregister_irq_event for KvmKernelIrqChip is not yet implemented");
    }

    /// Route an IRQ line to an interrupt controller, or to a particular MSI vector.
    fn route_irq(&mut self, _route: IrqRoute) -> Result<()> {
        unimplemented!("route_irq for KvmKernelIrqChip is not yet implemented");
    }

    /// Return a vector of all registered irq numbers and their associated events.  To be used by
    /// the main thread to wait for irq events to be triggered.
    fn irq_event_tokens(&self) -> Result<Vec<(u32, EventFd)>> {
        unimplemented!("irq_event_tokens for KvmKernelIrqChip is not yet implemented");
    }

    /// Either assert or deassert an IRQ line.  Sends to either an interrupt controller, or does
    /// a send_msi if the irq is associated with an MSI.
    fn service_irq(&mut self, _irq: u32, _level: bool) -> Result<()> {
        unimplemented!("service_irq for KvmKernelIrqChip is not yet implemented");
    }

    /// Broadcast an end of interrupt.
    fn broadcast_eoi(&mut self, _vector: u8) -> Result<()> {
        unimplemented!("broadcast_eoi for KvmKernelIrqChip is not yet implemented");
    }

    /// Return true if there is a pending interrupt for the specified vcpu.
    fn interrupt_requested(&self, _vcpu_id: usize) -> bool {
        unimplemented!("interrupt_requested for KvmKernelIrqChip is not yet implemented");
    }

    /// Check if the specified vcpu has any pending interrupts. Returns None for no interrupts,
    /// otherwise Some(u32) should be the injected interrupt vector.
    fn get_external_interrupt(&mut self, _vcpu_id: usize) -> Result<Option<u32>> {
        unimplemented!("get_external_interrupt for KvmKernelIrqChip is not yet implemented");
    }

    /// Attempt to clone this IrqChip instance.
    fn try_clone(&self) -> Result<Self> {
        unimplemented!("try_clone for KvmKernelIrqChip is not yet implemented");
    }
}

#[cfg(test)]
mod tests {

    use hypervisor::kvm::{Kvm, KvmVm};
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
        let vcpu = vm.create_vcpu(0).expect("failed to instantiate vcpu");

        let mut chip =
            KvmKernelIrqChip::new(vm, 1).expect("failed to instantiate KvmKernelIrqChip");

        chip.add_vcpu(0, vcpu).expect("failed to add vcpu");
    }
}

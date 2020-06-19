// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;
use sync::Mutex;

use hypervisor::kvm::{KvmVcpu, KvmVm};
use hypervisor::{
    IoapicState, IrqRoute, IrqSourceChip, LapicState, PicSelect, PicState, PitState, Vm,
    NUM_IOAPIC_PINS,
};
use kvm_sys::*;
use sys_util::Result;

use crate::{Bus, IrqChipX86_64};

/// Default x86 routing table.  Pins 0-7 go to primary pic and ioapic, pins 8-15 go to secondary
/// pic and ioapic, and pins 16-23 go only to the ioapic.
fn kvm_default_irq_routing_table() -> Vec<IrqRoute> {
    let mut routes: Vec<IrqRoute> = Vec::new();

    for i in 0..8 {
        routes.push(IrqRoute::pic_irq_route(IrqSourceChip::PicPrimary, i));
        routes.push(IrqRoute::ioapic_irq_route(i));
    }
    for i in 8..16 {
        routes.push(IrqRoute::pic_irq_route(IrqSourceChip::PicSecondary, i));
        routes.push(IrqRoute::ioapic_irq_route(i));
    }
    for i in 16..NUM_IOAPIC_PINS as u32 {
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

        Ok(KvmKernelIrqChip {
            vm,
            vcpus: Arc::new(Mutex::new((0..num_vcpus).map(|_| None).collect())),
            routes: Arc::new(Mutex::new(kvm_default_irq_routing_table())),
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

impl IrqChipX86_64<KvmVcpu> for KvmKernelIrqChip {
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
    fn get_lapic_state(&self, _vcpu_id: usize) -> Result<LapicState> {
        unimplemented!("get_lapic_state for KvmKernelIrqChip is not yet implemented");
    }

    /// Set the current state of the specified VCPU's local APIC
    fn set_lapic_state(&mut self, _vcpu_id: usize, _state: &LapicState) -> Result<()> {
        unimplemented!("set_lapic_state for KvmKernelIrqChip is not yet implemented");
    }

    /// Create a PIT (Programmable Interval Timer) for this VM.
    /// The KvmKernelIrqchip creates the PIT by calling the KVM_CREATE_PIT2 KVM API. The
    /// io_bus is not used in this case because KVM handles intercepting port-mapped io intended
    /// for the PIT.
    fn create_pit(&mut self, _io_bus: &mut Bus) -> Result<()> {
        self.vm.create_pit()
    }

    /// Retrieves the state of the PIT. Gets the pit state via the KVM API.
    fn get_pit(&self) -> Result<PitState> {
        Ok(PitState::from(&self.vm.get_pit_state()?))
    }

    /// Sets the state of the PIT. Sets the pit state via the KVM API.
    fn set_pit(&mut self, state: &PitState) -> Result<()> {
        self.vm.set_pit_state(&kvm_pit_state2::from(state))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use hypervisor::kvm::Kvm;
    use sys_util::GuestMemory;

    use hypervisor::{Vm, VmX86_64};

    use super::super::super::tests::*;
    use crate::IrqChip;

    /// Helper function for setting up a KvmKernelIrqChip
    fn get_kernel_chip() -> KvmKernelIrqChip {
        let kvm = Kvm::new().expect("failed to instantiate Kvm");
        let mem = GuestMemory::new(&[]).unwrap();
        let vm = KvmVm::new(&kvm, mem).expect("failed tso instantiate vm");

        let mut chip = KvmKernelIrqChip::new(vm.try_clone().expect("failed to clone vm"), 1)
            .expect("failed to instantiate KvmKernelIrqChip");

        let vcpu = vm.create_vcpu(0).expect("failed to instantiate vcpu");
        chip.add_vcpu(0, vcpu).expect("failed to add vcpu");

        let mut bus = Bus::new();
        chip.create_pit(&mut bus).expect("failed to create pit");

        chip
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
    fn kernel_irqchip_route_irq() {
        test_route_irq(get_kernel_chip());
    }
}

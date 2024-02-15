// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

use base::error;
use base::Error;
use base::Event;
use base::Result;
use hypervisor::geniezone::geniezone_sys::*;
use hypervisor::geniezone::GeniezoneVcpu;
use hypervisor::geniezone::GeniezoneVm;
use hypervisor::DeviceKind;
use hypervisor::IrqRoute;
use hypervisor::MPState;
use hypervisor::Vcpu;
use hypervisor::Vm;
use resources::SystemAllocator;
use sync::Mutex;

use crate::Bus;
use crate::IrqChip;
use crate::IrqChipAArch64;
use crate::IrqChipCap;
use crate::IrqEdgeEvent;
use crate::IrqEventIndex;
use crate::IrqEventSource;
use crate::IrqLevelEvent;
use crate::VcpuRunState;

/// Default ARM routing table.  AARCH64_GIC_NR_SPIS pins go to VGIC.
fn default_irq_routing_table() -> Vec<IrqRoute> {
    let mut routes: Vec<IrqRoute> = Vec::new();

    for i in 0..AARCH64_GIC_NR_SPIS {
        routes.push(IrqRoute::gic_irq_route(i));
    }

    routes
}

/// IrqChip implementation where the entire IrqChip is emulated by GZVM.
///
/// This implementation will use the GZVM API to create and configure the in-kernel irqchip.
pub struct GeniezoneKernelIrqChip {
    pub(super) vm: GeniezoneVm,
    pub(super) vcpus: Arc<Mutex<Vec<Option<GeniezoneVcpu>>>>,
    device_kind: DeviceKind,
    pub(super) routes: Arc<Mutex<Vec<IrqRoute>>>,
}

// These constants indicate the address space used by the ARM vGIC.
const AARCH64_GIC_DIST_SIZE: u64 = 0x10000;

// These constants indicate the placement of the GIC registers in the physical
// address space.
const AARCH64_GIC_DIST_BASE: u64 = AARCH64_AXI_BASE - AARCH64_GIC_DIST_SIZE;
const AARCH64_GIC_REDIST_SIZE: u64 = 0x20000;

// This is the minimum number of SPI interrupts aligned to 32 + 32 for the
// PPI (16) and GSI (16).
// pub const AARCH64_GIC_NR_IRQS: u32 = 64;
// Number of SPIs (32), which is the NR_IRQS (64) minus the number of PPIs (16) and GSIs (16)
pub const AARCH64_GIC_NR_SPIS: u32 = 32;

const AARCH64_AXI_BASE: u64 = 0x40000000;

impl GeniezoneKernelIrqChip {
    /// Construct a new GzvmKernelIrqchip.
    pub fn new(vm: GeniezoneVm, num_vcpus: usize) -> Result<GeniezoneKernelIrqChip> {
        let dist_if_addr: u64 = AARCH64_GIC_DIST_BASE;
        let redist_addr: u64 = dist_if_addr - (AARCH64_GIC_REDIST_SIZE * num_vcpus as u64);
        let device_kind = DeviceKind::ArmVgicV3;

        // prepare gzvm_create_device and call ioctl
        let device_dis = gzvm_create_device {
            dev_type: gzvm_device_type_GZVM_DEV_TYPE_ARM_VGIC_V3_DIST,
            id: 0,
            flags: 0,
            dev_addr: dist_if_addr,
            dev_reg_size: AARCH64_GIC_DIST_SIZE,
            attr_addr: 0_u64,
            attr_size: 0_u64,
        };

        match vm.create_geniezone_device(device_dis) {
            Ok(()) => {}
            Err(e) => {
                error!("failed to create geniezone device with err: {}", e);
                return Err(e);
            }
        };

        let device_redis = gzvm_create_device {
            dev_type: gzvm_device_type_GZVM_DEV_TYPE_ARM_VGIC_V3_REDIST,
            id: 0,
            flags: 0,
            dev_addr: redist_addr,
            dev_reg_size: AARCH64_GIC_REDIST_SIZE,
            attr_addr: 0_u64,
            attr_size: 0_u64,
        };

        match vm.create_geniezone_device(device_redis) {
            Ok(()) => {}
            Err(e) => {
                error!("failed to create geniezone device with err: {}", e);
                return Err(e);
            }
        };

        Ok(GeniezoneKernelIrqChip {
            vm,
            vcpus: Arc::new(Mutex::new((0..num_vcpus).map(|_| None).collect())),
            device_kind,
            routes: Arc::new(Mutex::new(default_irq_routing_table())),
        })
    }
    /// Attempt to create a shallow clone of this aarch64 GzvmKernelIrqChip instance.
    pub(super) fn arch_try_clone(&self) -> Result<Self> {
        Ok(GeniezoneKernelIrqChip {
            vm: self.vm.try_clone()?,
            vcpus: self.vcpus.clone(),
            device_kind: self.device_kind,
            routes: self.routes.clone(),
        })
    }
}

impl IrqChipAArch64 for GeniezoneKernelIrqChip {
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
        self.device_kind
    }

    fn finalize(&self) -> Result<()> {
        Ok(())
    }
}

/// This IrqChip only works with Geniezone so we only implement it for GeniezoneVcpu.
impl IrqChip for GeniezoneKernelIrqChip {
    /// Add a vcpu to the irq chip.
    fn add_vcpu(&mut self, vcpu_id: usize, vcpu: &dyn Vcpu) -> Result<()> {
        let vcpu: &GeniezoneVcpu = vcpu
            .downcast_ref()
            .expect("GeniezoneKernelIrqChip::add_vcpu called with non-GeniezoneVcpu");
        self.vcpus.lock()[vcpu_id] = Some(vcpu.try_clone()?);
        Ok(())
    }

    /// Register an event with edge-trigger semantic that can trigger an interrupt
    /// for a particular GSI.
    fn register_edge_irq_event(
        &mut self,
        irq: u32,
        irq_event: &IrqEdgeEvent,
        _source: IrqEventSource,
    ) -> Result<Option<IrqEventIndex>> {
        self.vm.register_irqfd(irq, irq_event.get_trigger(), None)?;
        Ok(None)
    }

    /// Unregister an event with edge-trigger semantic for a particular GSI.
    fn unregister_edge_irq_event(&mut self, irq: u32, irq_event: &IrqEdgeEvent) -> Result<()> {
        self.vm.unregister_irqfd(irq, irq_event.get_trigger())
    }

    /// Register an event with level-trigger semantic that can trigger an interrupt
    /// for a particular GSI.
    fn register_level_irq_event(
        &mut self,
        irq: u32,
        irq_event: &IrqLevelEvent,
        _source: IrqEventSource,
    ) -> Result<Option<IrqEventIndex>> {
        self.vm
            .register_irqfd(irq, irq_event.get_trigger(), Some(irq_event.get_resample()))?;
        Ok(None)
    }

    /// Unregister an event with level-trigger semantic for a particular GSI.
    fn unregister_level_irq_event(&mut self, irq: u32, irq_event: &IrqLevelEvent) -> Result<()> {
        self.vm.unregister_irqfd(irq, irq_event.get_trigger())
    }

    /// Route an IRQ line to an interrupt controller, or to a particular MSI vector.
    fn route_irq(&mut self, route: IrqRoute) -> Result<()> {
        let mut routes = self.routes.lock();
        routes.retain(|r| r.gsi != route.gsi);

        routes.push(route);
        Ok(())
    }

    /// Replace all irq routes with the supplied routes
    fn set_irq_routes(&mut self, routes: &[IrqRoute]) -> Result<()> {
        let mut current_routes = self.routes.lock();
        *current_routes = routes.to_vec();
        Ok(())
    }

    /// Return a vector of all registered irq numbers and their associated events and event
    /// indices. These should be used by the main thread to wait for irq events.
    /// For the GeniezoneKernelIrqChip, the kernel handles listening to irq events being triggered
    /// by devices, so this function always returns an empty Vec.
    fn irq_event_tokens(&self) -> Result<Vec<(IrqEventIndex, IrqEventSource, Event)>> {
        Ok(Vec::new())
    }

    /// Either assert or deassert an IRQ line.  Sends to either an interrupt controller, or does
    /// a send_msi if the irq is associated with an MSI.
    /// For the GeniezoneKernelIrqChip this simply calls the GZVM_SET_IRQ_LINE ioctl.
    fn service_irq(&mut self, irq: u32, level: bool) -> Result<()> {
        self.vm.set_irq_line(irq, level)
    }

    /// Service an IRQ event by asserting then deasserting an IRQ line. The associated Event
    /// that triggered the irq event will be read from. If the irq is associated with a resample
    /// Event, then the deassert will only happen after an EOI is broadcast for a vector
    /// associated with the irq line.
    /// This function should never be called on GeniezoneKernelIrqChip.
    fn service_irq_event(&mut self, _event_index: IrqEventIndex) -> Result<()> {
        error!("service_irq_event should never be called for GeniezoneKernelIrqChip");
        Ok(())
    }

    /// Broadcast an end of interrupt.
    /// This should never be called on a GeniezoneKernelIrqChip because a Geniezone vcpu should
    /// never exit with the GZVM_EXIT_EOI_BROADCAST reason when an in-kernel irqchip exists.
    fn broadcast_eoi(&self, _vector: u8) -> Result<()> {
        error!("broadcast_eoi should never be called for GeniezoneKernelIrqChip");
        Ok(())
    }

    /// Injects any pending interrupts for `vcpu`.
    /// For GeniezoneKernelIrqChip this is a no-op because Geniezone is responsible for injecting
    /// all interrupts.
    fn inject_interrupts(&self, _vcpu: &dyn Vcpu) -> Result<()> {
        Ok(())
    }

    /// Notifies the irq chip that the specified VCPU has executed a halt instruction.
    /// For GeniezoneKernelIrqChip this is a no-op because Geniezone handles VCPU blocking.
    fn halted(&self, _vcpu_id: usize) {}

    /// Blocks until `vcpu` is in a runnable state or until interrupted by
    /// `IrqChip::kick_halted_vcpus`.  Returns `VcpuRunState::Runnable if vcpu is runnable, or
    /// `VcpuRunState::Interrupted` if the wait was interrupted.
    /// For GeniezoneKernelIrqChip this is a no-op and always returns Runnable because Geniezone
    /// handles VCPU blocking.
    fn wait_until_runnable(&self, _vcpu: &dyn Vcpu) -> Result<VcpuRunState> {
        Ok(VcpuRunState::Runnable)
    }

    /// Makes unrunnable VCPUs return immediately from `wait_until_runnable`.
    /// For GeniezoneKernelIrqChip this is a no-op because Geniezone handles VCPU blocking.
    fn kick_halted_vcpus(&self) {}

    /// Get the current MP state of the specified VCPU.
    fn get_mp_state(&self, _vcpu_id: usize) -> Result<MPState> {
        Err(Error::new(libc::ENOENT))
    }

    /// Set the current MP state of the specified VCPU.
    fn set_mp_state(&mut self, _vcpu_id: usize, _state: &MPState) -> Result<()> {
        Err(Error::new(libc::ENOENT))
    }

    /// Attempt to clone this IrqChip instance.
    fn try_clone(&self) -> Result<Self> {
        // Because the GeniezoneKernelIrqChip struct contains arch-specific fields we leave the
        // cloning to arch-specific implementations
        self.arch_try_clone()
    }

    /// Finalize irqchip setup. Should be called once all devices have registered irq events and
    /// been added to the io_bus and mmio_bus.
    /// GeniezoneKernelIrqChip does not need to do anything here.
    fn finalize_devices(
        &mut self,
        _resources: &mut SystemAllocator,
        _io_bus: &Bus,
        _mmio_bus: &Bus,
    ) -> Result<()> {
        Ok(())
    }

    /// The GeniezoneKernelIrqChip doesn't process irq events itself so this function does nothing.
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

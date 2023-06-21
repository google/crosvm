// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::marker::Send;
use std::marker::Sized;

use base::Event;
use base::Result;
use hypervisor::IrqRoute;
use hypervisor::MPState;
use hypervisor::Vcpu;
use resources::SystemAllocator;
use serde::Deserialize;
use serde::Serialize;

use crate::pci::CrosvmDeviceId;
use crate::pci::PciId;
use crate::Bus;
use crate::BusDevice;
use crate::IrqEdgeEvent;
use crate::IrqLevelEvent;

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        mod kvm;
        pub use self::kvm::KvmKernelIrqChip;
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        pub use self::kvm::KvmSplitIrqChip;
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        pub use self::kvm::{AARCH64_GIC_NR_IRQS, AARCH64_GIC_NR_SPIS};
    } else if #[cfg(all(windows, feature = "whpx"))] {
        mod whpx;
        pub use self::whpx::WhpxSplitIrqChip;
    }
}

cfg_if::cfg_if! {
    if #[cfg(all(unix, any(target_arch = "arm", target_arch = "aarch64"), feature = "gunyah"))] {
        mod gunyah;
        pub use self::gunyah::GunyahIrqChip;
    }
}

cfg_if::cfg_if! {
    if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        mod x86_64;
        pub use x86_64::*;
        mod pic;
        pub use pic::*;
        mod ioapic;
        pub use ioapic::*;
        mod apic;
        pub use apic::*;
        mod userspace;
        pub use userspace::*;
    } else if #[cfg(any(target_arch = "arm", target_arch = "aarch64"))] {
        mod aarch64;
        pub use aarch64::*;
    } else if #[cfg(target_arch = "riscv64")] {
        mod riscv64;
        pub use riscv64::*;
        pub use self::kvm::aia_addr_imsic;
        pub use self::kvm::aia_aplic_addr;
        pub use self::kvm::aia_imsic_addr;
        pub use self::kvm::aia_imsic_size;
        pub use self::kvm::AIA_APLIC_SIZE;
        pub use self::kvm::AIA_IMSIC_BASE;
        pub use self::kvm::IMSIC_MAX_INT_IDS;
    }

}

#[cfg(all(target_arch = "aarch64", feature = "geniezone"))]
mod geniezone;
#[cfg(all(target_arch = "aarch64", feature = "geniezone"))]
pub use self::geniezone::GeniezoneKernelIrqChip;

pub type IrqEventIndex = usize;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
struct IrqEvent {
    event: Event,
    gsi: u32,
    resample_event: Option<Event>,
    source: IrqEventSource,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceId {
    /// PCI Device, use its PciId directly.
    PciDeviceId(PciId),
    /// Platform device, use a unique Id.
    PlatformDeviceId(CrosvmDeviceId),
}

impl From<PciId> for DeviceId {
    fn from(v: PciId) -> Self {
        Self::PciDeviceId(v)
    }
}

impl From<CrosvmDeviceId> for DeviceId {
    fn from(v: CrosvmDeviceId) -> Self {
        Self::PlatformDeviceId(v)
    }
}

impl TryFrom<u32> for DeviceId {
    type Error = base::Error;

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        let device_id = (value & 0xFFFF) as u16;
        let vendor_id = ((value & 0xFFFF_0000) >> 16) as u16;
        if vendor_id == 0xFFFF {
            Ok(DeviceId::PlatformDeviceId(CrosvmDeviceId::try_from(
                device_id,
            )?))
        } else {
            Ok(DeviceId::PciDeviceId(PciId::new(vendor_id, device_id)))
        }
    }
}

impl From<DeviceId> for u32 {
    fn from(id: DeviceId) -> Self {
        match id {
            DeviceId::PciDeviceId(pci_id) => pci_id.into(),
            DeviceId::PlatformDeviceId(id) => 0xFFFF0000 | id as u32,
        }
    }
}

/// Identification information about the source of an IrqEvent
#[derive(Clone, Serialize, Deserialize)]
pub struct IrqEventSource {
    pub device_id: DeviceId,
    pub queue_id: usize,
    pub device_name: String,
}

impl IrqEventSource {
    pub fn from_device(device: &dyn BusDevice) -> Self {
        Self {
            device_id: device.device_id(),
            queue_id: 0,
            device_name: device.debug_label(),
        }
    }
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
        source: IrqEventSource,
    ) -> Result<Option<IrqEventIndex>>;

    /// Unregister an event with edge-trigger semantic for a particular GSI.
    fn unregister_edge_irq_event(&mut self, irq: u32, irq_event: &IrqEdgeEvent) -> Result<()>;

    /// Register an event with level-trigger semantic that can trigger an interrupt for a particular GSI.
    fn register_level_irq_event(
        &mut self,
        irq: u32,
        irq_event: &IrqLevelEvent,
        source: IrqEventSource,
    ) -> Result<Option<IrqEventIndex>>;

    /// Unregister an event with level-trigger semantic for a particular GSI.
    fn unregister_level_irq_event(&mut self, irq: u32, irq_event: &IrqLevelEvent) -> Result<()>;

    /// Route an IRQ line to an interrupt controller, or to a particular MSI vector.
    fn route_irq(&mut self, route: IrqRoute) -> Result<()>;

    /// Replace all irq routes with the supplied routes
    fn set_irq_routes(&mut self, routes: &[IrqRoute]) -> Result<()>;

    /// Return a vector of all registered irq numbers and their associated events and event
    /// sources. These should be used by the main thread to wait for irq events.
    fn irq_event_tokens(&self) -> Result<Vec<(IrqEventIndex, IrqEventSource, Event)>>;

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrqChipCap {
    /// APIC TSC-deadline timer mode.
    TscDeadlineTimer,
    /// Extended xAPIC (x2APIC) standard.
    X2Apic,
    /// Irqchip exposes mp_state_get/set methods. Calling these methods on chips
    /// without this capability will result in undefined behavior.
    MpStateGetSet,
}

/// A capability the `IrqChip` can possibly expose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VcpuRunState {
    Runnable,
    Interrupted,
}

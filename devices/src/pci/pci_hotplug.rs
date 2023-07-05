// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Trait definitions and implementations for PCI hotplug.

#![deny(missing_docs)]

use base::AsRawDescriptor;
use base::AsRawDescriptors;
use base::RawDescriptor;
use base::Tube;
use resources::Alloc;
use serde::Deserialize;
use serde::Serialize;
use vm_control::api::VmMemoryClient;

use crate::virtio::NetParameters;
use crate::IrqLevelEvent;
use crate::PciAddress;
use crate::PciDevice;
use crate::PciDeviceError;
use crate::PciInterruptPin;

pub type Result<T> = std::result::Result<T, PciDeviceError>;

/// A ResourceCarrier moves resources for PCI device across process boundary.
///
/// ResourceCarrier can be sent across processes using De/Serialize. All the variants shall be able
/// to convert into a HotPlugPluggable device.
#[derive(Serialize, Deserialize)]
pub enum ResourceCarrier {
    /// virtio-net device.
    VirtioNet(NetResourceCarrier),
}

impl ResourceCarrier {
    /// Returns debug label for the target device.
    pub fn debug_label(&self) -> String {
        match self {
            ResourceCarrier::VirtioNet(c) => c.debug_label(),
        }
    }

    /// A vector of device-specific file descriptors that must be kept open
    /// after jailing. Must be called before the process is jailed.
    pub fn keep_rds(&self) -> Vec<RawDescriptor> {
        match self {
            ResourceCarrier::VirtioNet(c) => c.keep_rds(),
        }
    }
    /// Allocate the preferred address to the device.
    pub fn allocate_address(
        &mut self,
        preferred_address: PciAddress,
        resources: &mut resources::SystemAllocator,
    ) -> Result<()> {
        match self {
            ResourceCarrier::VirtioNet(c) => c.allocate_address(preferred_address, resources),
        }
    }
    /// Assign a legacy PCI IRQ to this device.
    /// The device may write to `irq_evt` to trigger an interrupt.
    /// When `irq_resample_evt` is signaled, the device should re-assert `irq_evt` if necessary.
    pub fn assign_irq(&mut self, irq_evt: IrqLevelEvent, pin: PciInterruptPin, irq_num: u32) {
        match self {
            ResourceCarrier::VirtioNet(c) => c.assign_irq(irq_evt, pin, irq_num),
        }
    }
}

/// Additional requirements for a PciDevice to support hotplug.
/// A hotplug device can be configured without access to the SystemAllocator.
pub trait HotPluggable: PciDevice {
    /// Sets PciAddress to pci_addr. Replaces allocate_address.
    fn set_pci_address(&mut self, pci_addr: PciAddress) -> Result<()>;

    /// Configures IO BAR layout without memory alloc. Replaces allocate_io_bars.
    fn configure_io_bars(&mut self) -> Result<()>;

    /// Configure device BAR layout without memory alloc. Replaces allocate_device_bars.
    fn configure_device_bars(&mut self) -> Result<()>;
}

impl<T: HotPluggable + ?Sized> HotPluggable for Box<T> {
    fn set_pci_address(&mut self, pci_addr: PciAddress) -> Result<()> {
        (**self).set_pci_address(pci_addr)
    }

    fn configure_io_bars(&mut self) -> Result<()> {
        (**self).configure_io_bars()
    }

    fn configure_device_bars(&mut self) -> Result<()> {
        (**self).configure_device_bars()
    }
}

/// A NetResourceCarrier is a ResourceCarrier specialization for virtio-net devices.
///
/// TODO(b/289155315): make members private.
#[derive(Serialize, Deserialize)]
pub struct NetResourceCarrier {
    /// NetParameters for constructing tap device
    pub net_param: NetParameters,
    /// msi_device_tube for VirtioPciDevice constructor
    pub msi_device_tube: Tube,
    /// ioevent_vm_memory_client for VirtioPciDevice constructor
    pub ioevent_vm_memory_client: VmMemoryClient,
    /// pci_address for the hotplugged device
    pub pci_address: Option<PciAddress>,
    /// intx_parameter for assign_irq
    pub intx_parameter: Option<IntxParameter>,
    /// vm_control_tube for VirtioPciDevice constructor
    pub vm_control_tube: Tube,
}

impl NetResourceCarrier {
    ///Constructs NetResourceCarrier.
    pub fn new(
        net_param: NetParameters,
        msi_device_tube: Tube,
        ioevent_vm_memory_client: VmMemoryClient,
        vm_control_tube: Tube,
    ) -> Self {
        Self {
            net_param,
            msi_device_tube,
            ioevent_vm_memory_client,
            pci_address: None,
            intx_parameter: None,
            vm_control_tube,
        }
    }

    fn debug_label(&self) -> String {
        "virtio-net".to_owned()
    }

    fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut keep_rds = vec![
            self.msi_device_tube.as_raw_descriptor(),
            self.ioevent_vm_memory_client.as_raw_descriptor(),
        ];
        if let Some(intx_parameter) = &self.intx_parameter {
            keep_rds.extend(intx_parameter.irq_evt.as_raw_descriptors());
        }
        keep_rds
    }

    fn allocate_address(
        &mut self,
        preferred_address: PciAddress,
        resources: &mut resources::SystemAllocator,
    ) -> Result<()> {
        match self.pci_address {
            None => {
                if resources.reserve_pci(
                    Alloc::PciBar {
                        bus: preferred_address.bus,
                        dev: preferred_address.dev,
                        func: preferred_address.func,
                        bar: 0,
                    },
                    self.debug_label(),
                ) {
                    self.pci_address = Some(preferred_address);
                } else {
                    return Err(PciDeviceError::PciAllocationFailed);
                }
            }
            Some(pci_address) => {
                if pci_address != preferred_address {
                    return Err(PciDeviceError::PciAllocationFailed);
                }
            }
        }
        Ok(())
    }

    fn assign_irq(&mut self, irq_evt: IrqLevelEvent, pin: PciInterruptPin, irq_num: u32) {
        self.intx_parameter = Some(IntxParameter {
            irq_evt,
            pin,
            irq_num,
        });
    }
}

/// Parameters for legacy INTx interrrupt.
#[derive(Serialize, Deserialize)]
pub struct IntxParameter {
    /// interrupt level event
    pub irq_evt: IrqLevelEvent,
    /// INTx interrupt pin
    pub pin: PciInterruptPin,
    /// irq num
    pub irq_num: u32,
}

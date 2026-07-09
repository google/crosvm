// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Helper functions for PCI hotplug.

#![deny(missing_docs)]

use anyhow::Context;
use anyhow::Result;
use base::RawDescriptor;
use device_virtio_net::NetPciHotplugResourceCarrier;
use devices::HotPluggable;
use devices::IntxParameter;
use devices::IrqLevelEvent;
use devices::PciAddress;
use devices::PciDevice;
use devices::PciDeviceError;
use devices::PciInterruptPin;
use devices::VirtioPciDevice;
use hypervisor::ProtectionType;
use serde::Deserialize;
use serde::Serialize;
use vm_memory::GuestMemory;

/// A PciHotplugResourceCarrier moves resources for PCI device across process boundary.
///
/// PciHotplugResourceCarrier can be sent across processes using De/Serialize. All the variants
/// shall be able to convert into a HotPluggable device.
#[derive(Serialize, Deserialize)]
pub enum PciHotplugResourceCarrier {
    /// virtio-net device.
    VirtioNet(NetPciHotplugResourceCarrier),
}

impl PciHotplugResourceCarrier {
    /// Returns debug label for the target device.
    #[allow(dead_code)]
    pub fn debug_label(&self) -> String {
        match self {
            PciHotplugResourceCarrier::VirtioNet(c) => c.debug_label(),
        }
    }

    /// A vector of device-specific file descriptors that must be kept open
    /// after jailing. Must be called before the process is jailed.
    #[allow(dead_code)]
    pub fn keep_rds(&self) -> Vec<RawDescriptor> {
        match self {
            PciHotplugResourceCarrier::VirtioNet(c) => c.keep_rds(),
        }
    }
    /// Allocate the preferred address to the device.
    pub fn allocate_address(
        &mut self,
        preferred_address: PciAddress,
        resources: &mut resources::SystemAllocator,
    ) -> std::result::Result<(), PciDeviceError> {
        match self {
            PciHotplugResourceCarrier::VirtioNet(c) => {
                c.allocate_address(preferred_address, resources)
            }
        }
    }
    /// Assign a legacy PCI IRQ to this device.
    /// The device may write to `irq_evt` to trigger an interrupt.
    /// When `irq_resample_evt` is signaled, the device should re-assert `irq_evt` if necessary.
    pub fn assign_irq(&mut self, irq_evt: IrqLevelEvent, pin: PciInterruptPin, irq_num: u32) {
        match self {
            PciHotplugResourceCarrier::VirtioNet(c) => c.assign_irq(irq_evt, pin, irq_num),
        }
    }
}

/// Builds HotPlugPci from NetPciHotplugResourceCarrier and NetLocalParameters.
pub fn build_hotplug_net_device(
    net_carrier_device: NetPciHotplugResourceCarrier,
    net_local_parameters: NetLocalParameters,
) -> Result<Box<dyn HotPluggable>> {
    let pci_address = net_carrier_device
        .pci_address
        .context("PCI address not allocated")?;
    let virtio_device = net_carrier_device
        .net_param
        .create_net_device(net_local_parameters.protection_type)
        .context("create virtio device")?;
    let mut virtio_pci_device = VirtioPciDevice::new(
        net_local_parameters.guest_memory,
        virtio_device,
        net_carrier_device.msi_device_tube,
        true,
        None,
        net_carrier_device.ioevent_vm_memory_client,
        net_carrier_device.vm_control_tube,
    )
    .context("create virtio PCI device")?;
    virtio_pci_device
        .set_pci_address(pci_address)
        .context("set PCI address")?;
    virtio_pci_device
        .configure_io_bars()
        .context("configure IO BAR")?;
    virtio_pci_device
        .configure_device_bars()
        .context("configure device BAR")?;
    let IntxParameter {
        irq_evt,
        irq_num,
        pin,
    } = net_carrier_device
        .intx_parameter
        .context("Missing INTx parameter.")?;
    virtio_pci_device.assign_irq(irq_evt, pin, irq_num);
    Ok(Box::new(virtio_pci_device))
}

/// Additional parameters required on the destination process to configure net VirtioPciDevice.
pub struct NetLocalParameters {
    guest_memory: GuestMemory,
    protection_type: ProtectionType,
}

impl NetLocalParameters {
    /// Constructs NetLocalParameters.
    pub fn new(guest_memory: GuestMemory, protection_type: ProtectionType) -> Self {
        Self {
            guest_memory,
            protection_type,
        }
    }
}

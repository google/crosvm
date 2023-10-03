// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Helper functions for PCI hotplug.

#![deny(missing_docs)]

use anyhow::Context;
use anyhow::Result;
use devices::HotPluggable;
use devices::IntxParameter;
use devices::NetResourceCarrier;
use devices::PciDevice;
use devices::VirtioPciDevice;
use hypervisor::ProtectionType;
use vm_memory::GuestMemory;

use crate::crosvm::sys::linux::VirtioDeviceBuilder;

/// Builds HotPlugPci from NetResourceCarrier and NetLocalParameters.
pub fn build_hotplug_net_device(
    net_carrier_device: NetResourceCarrier,
    net_local_parameters: NetLocalParameters,
) -> Result<Box<dyn HotPluggable>> {
    let pci_address = net_carrier_device
        .pci_address
        .context("PCI address not allocated")?;
    let virtio_device = net_carrier_device
        .net_param
        .create_virtio_device(net_local_parameters.protection_type)
        .context("create virtio device")?;
    let mut virtio_pci_device = VirtioPciDevice::new(
        net_local_parameters.guest_memory,
        virtio_device,
        net_carrier_device.msi_device_tube,
        true,
        None,
        net_carrier_device.ioevent_vm_memory_client,
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

// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::AsRawDescriptor;
use base::AsRawDescriptors;
use base::RawDescriptor;
use base::Tube;
use devices::IntxParameter;
use devices::IrqLevelEvent;
use devices::PciAddress;
use devices::PciDeviceError;
use devices::PciInterruptPin;
use serde::Deserialize;
use serde::Serialize;
use vm_control::api::VmMemoryClient;

use crate::NetParameters;

pub type Result<T> = std::result::Result<T, PciDeviceError>;

/// A NetPciHotplugResourceCarrier is a ResourceCarrier specialization for virtio-net devices.
///
/// TODO(b/289155315): make members private.
#[derive(Serialize, Deserialize)]
pub struct NetPciHotplugResourceCarrier {
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

impl NetPciHotplugResourceCarrier {
    ///Constructs NetPciHotplugResourceCarrier.
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

    pub fn debug_label(&self) -> String {
        "virtio-net".to_owned()
    }

    pub fn keep_rds(&self) -> Vec<RawDescriptor> {
        let mut keep_rds = vec![
            self.msi_device_tube.as_raw_descriptor(),
            self.ioevent_vm_memory_client.as_raw_descriptor(),
        ];
        if let Some(intx_parameter) = &self.intx_parameter {
            keep_rds.extend(intx_parameter.irq_evt.as_raw_descriptors());
        }
        keep_rds
    }

    pub fn allocate_address(
        &mut self,
        preferred_address: PciAddress,
        resources: &mut resources::SystemAllocator,
    ) -> Result<()> {
        match self.pci_address {
            None => {
                if resources.reserve_pci(preferred_address, self.debug_label()) {
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

    pub fn assign_irq(&mut self, irq_evt: IrqLevelEvent, pin: PciInterruptPin, irq_num: u32) {
        self.intx_parameter = Some(IntxParameter {
            irq_evt,
            pin,
            irq_num,
        });
    }
}

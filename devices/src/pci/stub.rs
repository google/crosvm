// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements a stub PCI device. This can be used to put a device on the PCI bus that will
//! show up in PCI device enumeration with the configured parameters. The device will otherwise be
//! non-functional, in particular it doesn't have any BARs, IRQs etc. and neither will it handle
//! config register interactions.
//!
//! The motivation for stub PCI devices is the case of multifunction PCI devices getting passed
//! through via VFIO to the guest. Per PCI device enumeration, functions other than 0 will only be
//! scanned if function 0 is present. A stub PCI device is useful in that situation to present
//! something to the guest on function 0.

use base::RawDescriptor;
use resources::Alloc;
use resources::SystemAllocator;
use serde::Deserialize;
use serde::Serialize;

use crate::pci::pci_configuration::PciBarConfiguration;
use crate::pci::pci_configuration::PciClassCode;
use crate::pci::pci_configuration::PciConfiguration;
use crate::pci::pci_configuration::PciHeaderType;
use crate::pci::pci_configuration::PciProgrammingInterface;
use crate::pci::pci_configuration::PciSubclass;
use crate::pci::pci_device::PciDevice;
use crate::pci::pci_device::Result;
use crate::pci::PciAddress;
use crate::pci::PciDeviceError;
use crate::Suspendable;

#[derive(Serialize, Deserialize)]
pub struct StubPciParameters {
    pub address: PciAddress,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: PciClassCode,
    pub subclass: u8,
    pub programming_interface: u8,
    pub subsystem_vendor_id: u16,
    pub subsystem_device_id: u16,
    pub revision_id: u8,
}

pub struct StubPciDevice {
    requested_address: PciAddress,
    assigned_address: Option<PciAddress>,
    config_regs: PciConfiguration,
}

struct NumericPciSubClass(u8);

impl PciSubclass for NumericPciSubClass {
    fn get_register_value(&self) -> u8 {
        self.0
    }
}

struct NumericPciProgrammingInterface(u8);

impl PciProgrammingInterface for NumericPciProgrammingInterface {
    fn get_register_value(&self) -> u8 {
        self.0
    }
}

impl StubPciDevice {
    pub fn new(config: &StubPciParameters) -> StubPciDevice {
        let config_regs = PciConfiguration::new(
            config.vendor_id,
            config.device_id,
            config.class,
            &NumericPciSubClass(config.subclass),
            Some(&NumericPciProgrammingInterface(
                config.programming_interface,
            )),
            PciHeaderType::Device,
            config.subsystem_vendor_id,
            config.subsystem_device_id,
            config.revision_id,
        );

        Self {
            requested_address: config.address,
            assigned_address: None,
            config_regs,
        }
    }
}

impl PciDevice for StubPciDevice {
    fn debug_label(&self) -> String {
        "Stub".to_owned()
    }

    fn preferred_address(&self) -> Option<PciAddress> {
        Some(self.requested_address)
    }

    fn allocate_address(&mut self, resources: &mut SystemAllocator) -> Result<PciAddress> {
        if self.assigned_address.is_none() {
            if resources.reserve_pci(
                Alloc::PciBar {
                    bus: self.requested_address.bus,
                    dev: self.requested_address.dev,
                    func: self.requested_address.func,
                    bar: 0,
                },
                self.debug_label(),
            ) {
                self.assigned_address = Some(self.requested_address);
            }
        }
        self.assigned_address
            .ok_or(PciDeviceError::PciAllocationFailed)
    }

    fn keep_rds(&self) -> Vec<RawDescriptor> {
        Vec::new()
    }

    fn get_bar_configuration(&self, bar_num: usize) -> Option<PciBarConfiguration> {
        self.config_regs.get_bar_configuration(bar_num)
    }

    fn read_config_register(&self, reg_idx: usize) -> u32 {
        self.config_regs.read_reg(reg_idx)
    }

    fn write_config_register(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        (&mut self.config_regs).write_reg(reg_idx, offset, data)
    }

    fn read_bar(&mut self, _addr: u64, _data: &mut [u8]) {}

    fn write_bar(&mut self, _addr: u64, _data: &[u8]) {}
}

impl Suspendable for StubPciDevice {}

#[cfg(test)]
mod test {
    use resources::AddressRange;
    use resources::SystemAllocator;
    use resources::SystemAllocatorConfig;

    use super::*;

    const CONFIG: StubPciParameters = StubPciParameters {
        address: PciAddress {
            bus: 0x0a,
            dev: 0x0b,
            func: 0x1,
        },
        vendor_id: 2,
        device_id: 3,
        class: PciClassCode::MultimediaController,
        subclass: 5,
        programming_interface: 6,
        subsystem_vendor_id: 7,
        subsystem_device_id: 8,
        revision_id: 9,
    };

    #[test]
    fn configuration() {
        let device = StubPciDevice::new(&CONFIG);

        assert_eq!(device.read_config_register(0), 0x0003_0002);
        assert_eq!(device.read_config_register(2), 0x04_05_06_09);
        assert_eq!(device.read_config_register(11), 0x0008_0007);
    }

    #[test]
    fn address_allocation() {
        let mut allocator = SystemAllocator::new(
            SystemAllocatorConfig {
                io: Some(AddressRange {
                    start: 0x1000,
                    end: 0x2fff,
                }),
                low_mmio: AddressRange {
                    start: 0x2000_0000,
                    end: 0x2fff_ffff,
                },
                high_mmio: AddressRange {
                    start: 0x1_0000_0000,
                    end: 0x1_0fff_ffff,
                },
                platform_mmio: None,
                first_irq: 5,
            },
            None,
            &[],
        )
        .unwrap();
        let mut device = StubPciDevice::new(&CONFIG);

        assert!(device.allocate_address(&mut allocator).is_ok());
        assert!(allocator.release_pci(0xa, 0xb, 1));
    }
}

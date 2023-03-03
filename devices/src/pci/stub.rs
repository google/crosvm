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
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

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

#[derive(Debug)]
pub struct PciClassParameters {
    pub class: PciClassCode,
    pub subclass: u8,
    pub programming_interface: u8,
}

impl Default for PciClassParameters {
    fn default() -> Self {
        PciClassParameters {
            class: PciClassCode::Other,
            subclass: 0,
            programming_interface: 0,
        }
    }
}

// Deserialize the combined class, subclass, and programming interface as a single numeric value.
// This matches the numeric format used in `/sys/bus/pci/devices/*/class`.
impl<'de> Deserialize<'de> for PciClassParameters {
    fn deserialize<D>(deserializer: D) -> std::result::Result<PciClassParameters, D::Error>
    where
        D: Deserializer<'de>,
    {
        let class_numeric = u32::deserialize(deserializer)?;

        let class_code = (class_numeric >> 16) as u8;
        let class = PciClassCode::try_from(class_code as u8).map_err(|_| {
            serde::de::Error::custom(format!("Unknown class code {:#x}", class_code))
        })?;

        let subclass = (class_numeric >> 8) as u8;

        let programming_interface = class_numeric as u8;

        Ok(PciClassParameters {
            class,
            subclass,
            programming_interface,
        })
    }
}

impl Serialize for PciClassParameters {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let class_numeric: u32 = ((self.class as u32) << 16)
            | ((self.subclass as u32) << 8)
            | self.programming_interface as u32;

        serializer.serialize_u32(class_numeric)
    }
}

#[derive(Serialize, Deserialize, Debug, serde_keyvalue::FromKeyValues)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct StubPciParameters {
    pub address: PciAddress,
    #[serde(default)]
    pub vendor: u16,
    #[serde(default)]
    pub device: u16,
    #[serde(default)]
    pub class: PciClassParameters,
    #[serde(default, alias = "subsystem_vendor")]
    pub subsystem_vendor: u16,
    #[serde(default, alias = "subsystem_device")]
    pub subsystem_device: u16,
    #[serde(default)]
    pub revision: u8,
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
            config.vendor,
            config.device,
            config.class.class,
            &NumericPciSubClass(config.class.subclass),
            Some(&NumericPciProgrammingInterface(
                config.class.programming_interface,
            )),
            PciHeaderType::Device,
            config.subsystem_vendor,
            config.subsystem_device,
            config.revision,
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
        self.config_regs.write_reg(reg_idx, offset, data)
    }

    fn read_bar(&mut self, _addr: u64, _data: &mut [u8]) {}

    fn write_bar(&mut self, _addr: u64, _data: &[u8]) {}
}

impl Suspendable for StubPciDevice {
    fn sleep(&mut self) -> anyhow::Result<()> {
        // There are no workers to sleep/wake.
        Ok(())
    }

    fn wake(&mut self) -> anyhow::Result<()> {
        // There are no workers to sleep/wake.
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use resources::AddressRange;
    use resources::SystemAllocator;
    use resources::SystemAllocatorConfig;
    use serde_keyvalue::from_key_values;
    use serde_keyvalue::ErrorKind;
    use serde_keyvalue::ParseError;

    use super::*;

    const CONFIG: StubPciParameters = StubPciParameters {
        address: PciAddress {
            bus: 0x0a,
            dev: 0x0b,
            func: 0x1,
        },
        vendor: 2,
        device: 3,
        class: PciClassParameters {
            class: PciClassCode::MultimediaController,
            subclass: 5,
            programming_interface: 6,
        },
        subsystem_vendor: 7,
        subsystem_device: 8,
        revision: 9,
    };

    fn from_stub_arg(options: &str) -> std::result::Result<StubPciParameters, ParseError> {
        from_key_values(options)
    }

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

    #[test]
    fn params_missing_address() {
        // PCI address argument is mandatory.
        let err = from_stub_arg("").unwrap_err();
        assert_eq!(
            err,
            ParseError {
                kind: ErrorKind::SerdeError("missing field `address`".into()),
                pos: 0,
            }
        );
    }

    #[test]
    fn params_address_implicit() {
        // Address is the default argument.
        let params = from_stub_arg("0000:00:01.2").unwrap();
        assert_eq!(
            params.address,
            PciAddress {
                bus: 0,
                dev: 1,
                func: 2
            }
        );
    }

    #[test]
    fn params_address_explicit() {
        // Explicitly-specified address.
        let params = from_stub_arg("address=0000:00:01.2").unwrap();
        assert_eq!(
            params.address,
            PciAddress {
                bus: 0,
                dev: 1,
                func: 2
            }
        );
    }

    #[test]
    fn params_class() {
        // Class, subclass, and programming interface are encoded as a single number.
        let params = from_stub_arg("address=0000:00:01.2,class=0x012345").unwrap();
        assert_eq!(params.class.class, PciClassCode::MassStorage);
        assert_eq!(params.class.subclass, 0x23);
        assert_eq!(params.class.programming_interface, 0x45);
    }

    #[test]
    fn params_subsystem_underscores() {
        // Accept aliases with underscores rather than hyphens for compatibility.
        let params =
            from_stub_arg("address=0000:00:01.2,subsystem_vendor=0x8675,subsystem_device=0x309")
                .unwrap();
        assert_eq!(params.subsystem_vendor, 0x8675);
        assert_eq!(params.subsystem_device, 0x0309);
    }

    #[test]
    fn params_full() {
        let params = from_stub_arg(
            "address=0000:00:01.2,vendor=0x1234,device=0x5678,subsystem-vendor=0x8675,subsystem-device=0x309,class=0x012345,revision=52",
        ).unwrap();
        assert_eq!(
            params.address,
            PciAddress {
                bus: 0,
                dev: 1,
                func: 2
            }
        );
        assert_eq!(params.vendor, 0x1234);
        assert_eq!(params.device, 0x5678);
        assert_eq!(params.subsystem_vendor, 0x8675);
        assert_eq!(params.subsystem_device, 0x0309);
        assert_eq!(params.class.class, PciClassCode::MassStorage);
        assert_eq!(params.class.subclass, 0x23);
        assert_eq!(params.class.programming_interface, 0x45);
        assert_eq!(params.revision, 52);
    }
}

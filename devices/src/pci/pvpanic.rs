// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! pvpanic is a simulated device, through which a guest panic event is sent to a VMM.
//! This was initially developed for qemu with linux in-tree drivers and opensource
//! driver for windows also exist now.
//! <https://fossies.org/linux/qemu/docs/specs/pvpanic.txt>
//!
//! This implementation emulates pci interface for pvpanic virtual device.

// TODO(218575411): Support pvpanic on windows crosvm.
#![cfg_attr(windows, allow(dead_code))]

use std::fmt;

use anyhow::Context;
use base::error;
use base::RawDescriptor;
use base::SendTube;
use base::VmEventType;
use resources::Alloc;
use resources::AllocOptions;
use resources::SystemAllocator;
use serde::Deserialize;
use serde::Serialize;

use crate::pci::pci_configuration::PciBarConfiguration;
use crate::pci::pci_configuration::PciBarPrefetchable;
use crate::pci::pci_configuration::PciBarRegionType;
use crate::pci::pci_configuration::PciClassCode;
use crate::pci::pci_configuration::PciConfiguration;
use crate::pci::pci_configuration::PciHeaderType;
use crate::pci::pci_configuration::PciOtherSubclass;
use crate::pci::pci_device;
use crate::pci::pci_device::BarRange;
use crate::pci::pci_device::PciDevice;
use crate::pci::pci_device::Result;
use crate::pci::PciAddress;
use crate::pci::PciDeviceError;
use crate::pci::PCI_VENDOR_ID_REDHAT;
use crate::Suspendable;

const PCI_DEVICE_ID_REDHAT_PVPANIC: u16 = 0x0011;
const PCI_PVPANIC_REVISION_ID: u8 = 1;

const PVPANIC_REG_NUM: u8 = 0;
const PVPANIC_REG_SIZE: u64 = 0x10;

// Guest panicked
pub const PVPANIC_PANICKED: u8 = 1 << 0;
// Guest kexeced crash kernel
pub const PVPANIC_CRASH_LOADED: u8 = 1 << 1;

const PVPANIC_CAPABILITIES: u8 = PVPANIC_PANICKED | PVPANIC_CRASH_LOADED;

#[repr(u8)]
#[derive(PartialEq, Eq)]
pub enum PvPanicCode {
    Panicked = PVPANIC_PANICKED,
    CrashLoaded = PVPANIC_CRASH_LOADED,
    Unknown = 0xFF,
}

impl PvPanicCode {
    pub fn from_u8(val: u8) -> PvPanicCode {
        match val {
            PVPANIC_PANICKED => PvPanicCode::Panicked,
            PVPANIC_CRASH_LOADED => PvPanicCode::CrashLoaded,
            _ => PvPanicCode::Unknown,
        }
    }
}

impl fmt::Display for PvPanicCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PvPanicCode::Panicked => write!(f, "Guest panicked"),
            PvPanicCode::CrashLoaded => write!(f, "Guest panicked and crash kernel loaded"),
            PvPanicCode::Unknown => write!(f, "Guest panicked with unknown code"),
        }
    }
}

#[derive(Serialize)]
pub struct PvPanicPciDevice {
    #[serde(skip_serializing)]
    pci_address: Option<PciAddress>,
    config_regs: PciConfiguration,
    #[serde(skip_serializing)]
    evt_wrtube: SendTube,
}

#[derive(Deserialize)]
struct PvPanicPciDeviceSerializable {
    config_regs: serde_json::Value,
}

impl PvPanicPciDevice {
    pub fn new(evt_wrtube: SendTube) -> PvPanicPciDevice {
        let config_regs = PciConfiguration::new(
            PCI_VENDOR_ID_REDHAT,
            PCI_DEVICE_ID_REDHAT_PVPANIC,
            PciClassCode::Other,
            &PciOtherSubclass::Other,
            None,
            PciHeaderType::Device,
            0xFF,
            0xFF,
            PCI_PVPANIC_REVISION_ID,
        );

        Self {
            pci_address: None,
            config_regs,
            evt_wrtube,
        }
    }
}

impl PciDevice for PvPanicPciDevice {
    fn debug_label(&self) -> String {
        "PvPanic".to_owned()
    }

    fn allocate_address(&mut self, resources: &mut SystemAllocator) -> Result<PciAddress> {
        if self.pci_address.is_none() {
            self.pci_address = match resources.allocate_pci(0, self.debug_label()) {
                Some(Alloc::PciBar {
                    bus,
                    dev,
                    func,
                    bar: _,
                }) => Some(PciAddress { bus, dev, func }),
                _ => None,
            }
        }
        self.pci_address.ok_or(PciDeviceError::PciAllocationFailed)
    }

    fn allocate_io_bars(&mut self, resources: &mut SystemAllocator) -> Result<Vec<BarRange>> {
        let address = self
            .pci_address
            .expect("allocate_address must be called prior to allocate_io_bars");
        let mut ranges: Vec<BarRange> = Vec::new();
        let pvpanic_reg_addr = resources
            .allocate_mmio(
                PVPANIC_REG_SIZE,
                Alloc::PciBar {
                    bus: address.bus,
                    dev: address.dev,
                    func: address.func,
                    bar: PVPANIC_REG_NUM,
                },
                "pvpanic_reg".to_string(),
                AllocOptions::new()
                    .max_address(u32::MAX.into())
                    .align(PVPANIC_REG_SIZE),
            )
            .map_err(|e| pci_device::Error::IoAllocationFailed(PVPANIC_REG_SIZE, e))?;
        let pvpanic_config = PciBarConfiguration::new(
            PVPANIC_REG_NUM.into(),
            PVPANIC_REG_SIZE,
            PciBarRegionType::Memory32BitRegion,
            PciBarPrefetchable::NotPrefetchable,
        )
        .set_address(pvpanic_reg_addr);
        self.config_regs
            .add_pci_bar(pvpanic_config)
            .map_err(|e| pci_device::Error::IoRegistrationFailed(pvpanic_reg_addr, e))?;
        ranges.push(BarRange {
            addr: pvpanic_reg_addr,
            size: PVPANIC_REG_SIZE,
            prefetchable: false,
        });

        Ok(ranges)
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

    fn read_bar(&mut self, addr: u64, data: &mut [u8]) {
        let mmio_addr = self.config_regs.get_bar_addr(PVPANIC_REG_NUM as usize);
        data[0] = if addr == mmio_addr && data.len() == 1 {
            PVPANIC_CAPABILITIES
        } else {
            0
        };
    }

    fn write_bar(&mut self, addr: u64, data: &[u8]) {
        let mmio_addr = self.config_regs.get_bar_addr(PVPANIC_REG_NUM as usize);
        if addr != mmio_addr || data.len() != 1 {
            return;
        }

        if let Err(e) = self
            .evt_wrtube
            .send::<VmEventType>(&VmEventType::Panic(data[0]))
        {
            error!("Failed to write to the event tube: {}", e);
        }
    }
}

impl Suspendable for PvPanicPciDevice {
    fn snapshot(&self) -> anyhow::Result<serde_json::Value> {
        serde_json::to_value(self).context("failed to serialize PvPanicPciDevice")
    }

    fn restore(&mut self, data: serde_json::Value) -> anyhow::Result<()> {
        let deser: PvPanicPciDeviceSerializable =
            serde_json::from_value(data).context("failed to deserialize PvPanicPciDevice")?;
        self.config_regs.restore(deser.config_regs)?;
        Ok(())
    }

    fn sleep(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn wake(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use base::Tube;
    use resources::AddressRange;
    use resources::SystemAllocator;
    use resources::SystemAllocatorConfig;

    use super::*;

    #[test]
    fn pvpanic_read_write() {
        let mut allocator = SystemAllocator::new(
            SystemAllocatorConfig {
                io: Some(AddressRange {
                    start: 0x1000,
                    end: 0xffff,
                }),
                low_mmio: AddressRange {
                    start: 0x2000_0000,
                    end: 0x2fffffff,
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

        let (evt_wrtube, evt_rdtube) = Tube::directional_pair().unwrap();
        let mut device = PvPanicPciDevice::new(evt_wrtube);

        assert!(device.allocate_address(&mut allocator).is_ok());
        assert!(device.allocate_io_bars(&mut allocator).is_ok());

        let mut data: [u8; 1] = [0; 1];

        // Read from an invalid addr
        device.read_bar(0, &mut data);
        assert_eq!(data[0], 0);

        // Read from the valid addr
        let mmio_addr = device.config_regs.get_bar_addr(PVPANIC_REG_NUM as usize);
        device.read_bar(mmio_addr, &mut data);
        assert_eq!(data[0], PVPANIC_CAPABILITIES);

        // Write to the valid addr.
        data[0] = PVPANIC_CRASH_LOADED;
        device.write_bar(mmio_addr, &data);

        // Verify the event
        let val = evt_rdtube.recv::<VmEventType>().unwrap();
        assert_eq!(val, VmEventType::Panic(PVPANIC_CRASH_LOADED));
    }
}

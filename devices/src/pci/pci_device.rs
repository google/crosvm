// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use acpi_tables::sdt::SDT;
use base::{Event, RawDescriptor};
use hypervisor::Datamatch;
use remain::sorted;
use resources::{Error as SystemAllocatorFaliure, SystemAllocator};
use thiserror::Error;

use crate::bus::{BusDeviceObj, ConfigWriteResult};
use crate::pci::pci_configuration::{
    self, PciBarConfiguration, COMMAND_REG, COMMAND_REG_IO_SPACE_MASK,
    COMMAND_REG_MEMORY_SPACE_MASK,
};
use crate::pci::{PciAddress, PciInterruptPin};
#[cfg(feature = "audio")]
use crate::virtio::snd::vios_backend::Error as VioSError;
use crate::{BusAccessInfo, BusDevice};

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    /// Setup of the device capabilities failed.
    #[error("failed to add capability {0}")]
    CapabilitiesSetup(pci_configuration::Error),
    /// Create cras client failed.
    #[cfg(all(feature = "audio", feature = "audio_cras"))]
    #[error("failed to create CRAS Client: {0}")]
    CreateCrasClientFailed(libcras::Error),
    /// Create VioS client failed.
    #[cfg(feature = "audio")]
    #[error("failed to create VioS Client: {0}")]
    CreateViosClientFailed(VioSError),
    /// Allocating space for an IO BAR failed.
    #[error("failed to allocate space for an IO BAR, size={0}: {1}")]
    IoAllocationFailed(u64, SystemAllocatorFaliure),
    /// Registering an IO BAR failed.
    #[error("failed to register an IO BAR, addr={0} err={1}")]
    IoRegistrationFailed(u64, pci_configuration::Error),
    /// MSIX Allocator encounters out-of-space
    #[error("Out-of-space detected in MSIX Allocator")]
    MsixAllocatorOutOfSpace,
    /// MSIX Allocator encounters overflow
    #[error("base={base} + size={size} overflows in MSIX Allocator")]
    MsixAllocatorOverflow { base: u64, size: u64 },
    /// MSIX Allocator encounters size of zero
    #[error("Size of zero detected in MSIX Allocator")]
    MsixAllocatorSizeZero,
    /// PCI Address is not allocated.
    #[error("PCI address is not allocated")]
    PciAddressMissing,
    /// PCI Address allocation failure.
    #[error("failed to allocate PCI address")]
    PciAllocationFailed,
}

pub type Result<T> = std::result::Result<T, Error>;

pub trait PciDevice: Send {
    /// Returns a label suitable for debug output.
    fn debug_label(&self) -> String;
    /// Allocate and return an unique bus, device and function number for this device.
    fn allocate_address(&mut self, resources: &mut SystemAllocator) -> Result<PciAddress>;
    /// A vector of device-specific file descriptors that must be kept open
    /// after jailing. Must be called before the process is jailed.
    fn keep_rds(&self) -> Vec<RawDescriptor>;
    /// Assign a legacy PCI IRQ to this device.
    /// The device may write to `irq_evt` to trigger an interrupt.
    /// When `irq_resample_evt` is signaled, the device should re-assert `irq_evt` if necessary.
    /// Optional irq_num can be used for default INTx allocation, device can overwrite it.
    /// If legacy INTx is used, function shall return requested IRQ number and PCI INTx pin.
    fn assign_irq(
        &mut self,
        _irq_evt: &Event,
        _irq_resample_evt: &Event,
        _irq_num: Option<u32>,
    ) -> Option<(u32, PciInterruptPin)> {
        None
    }
    /// Allocates the needed IO BAR space using the `allocate` function which takes a size and
    /// returns an address. Returns a Vec of (address, length) tuples.
    fn allocate_io_bars(&mut self, _resources: &mut SystemAllocator) -> Result<Vec<(u64, u64)>> {
        Ok(Vec::new())
    }

    /// Allocates the needed device BAR space. Returns a Vec of (address, length) tuples.
    /// Unlike MMIO BARs (see allocate_io_bars), device BARs are not expected to incur VM exits
    /// - these BARs represent normal memory.
    fn allocate_device_bars(
        &mut self,
        _resources: &mut SystemAllocator,
    ) -> Result<Vec<(u64, u64)>> {
        Ok(Vec::new())
    }

    /// Returns the configuration of a base address register, if present.
    fn get_bar_configuration(&self, bar_num: usize) -> Option<PciBarConfiguration>;

    /// Register any capabilties specified by the device.
    fn register_device_capabilities(&mut self) -> Result<()> {
        Ok(())
    }

    /// Gets a list of ioevents that should be registered with the running VM. The list is
    /// returned as a Vec of (event, addr, datamatch) tuples.
    fn ioevents(&self) -> Vec<(&Event, u64, Datamatch)> {
        Vec::new()
    }

    /// Reads from a PCI configuration register.
    /// * `reg_idx` - PCI register index (in units of 4 bytes).
    fn read_config_register(&self, reg_idx: usize) -> u32;

    /// Writes to a PCI configuration register.
    /// * `reg_idx` - PCI register index (in units of 4 bytes).
    /// * `offset`  - byte offset within 4-byte register.
    /// * `data`    - The data to write.
    fn write_config_register(&mut self, reg_idx: usize, offset: u64, data: &[u8]);

    /// Reads from a BAR region mapped in to the device.
    /// * `addr` - The guest address inside the BAR.
    /// * `data` - Filled with the data from `addr`.
    fn read_bar(&mut self, addr: u64, data: &mut [u8]);
    /// Writes to a BAR region mapped in to the device.
    /// * `addr` - The guest address inside the BAR.
    /// * `data` - The data to write.
    fn write_bar(&mut self, addr: u64, data: &[u8]);
    /// Invoked when the device is sandboxed.
    fn on_device_sandboxed(&mut self) {}

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn generate_acpi(&mut self, sdts: Vec<SDT>) -> Option<Vec<SDT>> {
        Some(sdts)
    }
}

impl<T: PciDevice> BusDevice for T {
    fn debug_label(&self) -> String {
        PciDevice::debug_label(self)
    }

    fn read(&mut self, info: BusAccessInfo, data: &mut [u8]) {
        self.read_bar(info.address, data)
    }

    fn write(&mut self, info: BusAccessInfo, data: &[u8]) {
        self.write_bar(info.address, data)
    }

    fn config_register_write(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> ConfigWriteResult {
        let mut result = ConfigWriteResult {
            ..Default::default()
        };
        if offset as usize + data.len() > 4 {
            return result;
        }

        if reg_idx == COMMAND_REG {
            let old_command_reg = self.read_config_register(COMMAND_REG);
            self.write_config_register(reg_idx, offset, data);
            let new_command_reg = self.read_config_register(COMMAND_REG);

            // Inform the caller of state changes.
            if (old_command_reg ^ new_command_reg) & COMMAND_REG_MEMORY_SPACE_MASK != 0 {
                result.mem_bus_new_state =
                    Some((new_command_reg & COMMAND_REG_MEMORY_SPACE_MASK) != 0);
            }
            if (old_command_reg ^ new_command_reg) & COMMAND_REG_IO_SPACE_MASK != 0 {
                result.io_bus_new_state = Some((new_command_reg & COMMAND_REG_IO_SPACE_MASK) != 0);
            }
        } else {
            self.write_config_register(reg_idx, offset, data);
        }

        result
    }

    fn config_register_read(&self, reg_idx: usize) -> u32 {
        self.read_config_register(reg_idx)
    }

    fn on_sandboxed(&mut self) {
        self.on_device_sandboxed();
    }
}

impl<T: PciDevice + ?Sized> PciDevice for Box<T> {
    /// Returns a label suitable for debug output.
    fn debug_label(&self) -> String {
        (**self).debug_label()
    }
    fn allocate_address(&mut self, resources: &mut SystemAllocator) -> Result<PciAddress> {
        (**self).allocate_address(resources)
    }
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        (**self).keep_rds()
    }
    fn assign_irq(
        &mut self,
        irq_evt: &Event,
        irq_resample_evt: &Event,
        irq_num: Option<u32>,
    ) -> Option<(u32, PciInterruptPin)> {
        (**self).assign_irq(irq_evt, irq_resample_evt, irq_num)
    }
    fn allocate_io_bars(&mut self, resources: &mut SystemAllocator) -> Result<Vec<(u64, u64)>> {
        (**self).allocate_io_bars(resources)
    }
    fn allocate_device_bars(&mut self, resources: &mut SystemAllocator) -> Result<Vec<(u64, u64)>> {
        (**self).allocate_device_bars(resources)
    }
    fn get_bar_configuration(&self, bar_num: usize) -> Option<PciBarConfiguration> {
        (**self).get_bar_configuration(bar_num)
    }
    fn register_device_capabilities(&mut self) -> Result<()> {
        (**self).register_device_capabilities()
    }
    fn ioevents(&self) -> Vec<(&Event, u64, Datamatch)> {
        (**self).ioevents()
    }
    fn read_config_register(&self, reg_idx: usize) -> u32 {
        (**self).read_config_register(reg_idx)
    }
    fn write_config_register(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        (**self).write_config_register(reg_idx, offset, data)
    }
    fn read_bar(&mut self, addr: u64, data: &mut [u8]) {
        (**self).read_bar(addr, data)
    }
    fn write_bar(&mut self, addr: u64, data: &[u8]) {
        (**self).write_bar(addr, data)
    }
    /// Invoked when the device is sandboxed.
    fn on_device_sandboxed(&mut self) {
        (**self).on_device_sandboxed()
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn generate_acpi(&mut self, sdts: Vec<SDT>) -> Option<Vec<SDT>> {
        (**self).generate_acpi(sdts)
    }
}

impl<T: 'static + PciDevice> BusDeviceObj for T {
    fn as_pci_device(&self) -> Option<&dyn PciDevice> {
        Some(self)
    }
    fn as_pci_device_mut(&mut self) -> Option<&mut dyn PciDevice> {
        Some(self)
    }
    fn into_pci_device(self: Box<Self>) -> Option<Box<dyn PciDevice>> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pci_configuration::{PciClassCode, PciConfiguration, PciHeaderType, PciMultimediaSubclass};

    struct TestDev {
        pub config_regs: PciConfiguration,
    }

    impl PciDevice for TestDev {
        fn debug_label(&self) -> String {
            "test".to_owned()
        }

        fn keep_rds(&self) -> Vec<RawDescriptor> {
            Vec::new()
        }

        fn read_config_register(&self, reg_idx: usize) -> u32 {
            self.config_regs.read_reg(reg_idx)
        }

        fn write_config_register(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
            (&mut self.config_regs).write_reg(reg_idx, offset, data)
        }

        fn read_bar(&mut self, _addr: u64, _data: &mut [u8]) {}

        fn write_bar(&mut self, _addr: u64, _data: &[u8]) {}

        fn allocate_address(&mut self, resources: &mut SystemAllocator) -> Result<PciAddress> {
            Err(Error::PciAllocationFailed)
        }

        fn get_bar_configuration(&self, bar_num: usize) -> Option<PciBarConfiguration> {
            None
        }
    }

    #[test]
    fn config_write_result() {
        let mut test_dev = TestDev {
            config_regs: PciConfiguration::new(
                0x1234,
                0xABCD,
                PciClassCode::MultimediaController,
                &PciMultimediaSubclass::AudioDevice,
                None,
                PciHeaderType::Device,
                false,
                0x5678,
                0xEF01,
                0,
            ),
        };

        // Initialize command register to an all-zeroes value.
        test_dev.config_register_write(COMMAND_REG, 0, &0u32.to_le_bytes());

        // Enable IO space access (bit 0 of command register).
        assert_eq!(
            test_dev.config_register_write(COMMAND_REG, 0, &1u32.to_le_bytes()),
            ConfigWriteResult {
                mem_bus_new_state: None,
                io_bus_new_state: Some(true),
            }
        );

        // Enable memory space access (bit 1 of command register).
        assert_eq!(
            test_dev.config_register_write(COMMAND_REG, 0, &3u32.to_le_bytes()),
            ConfigWriteResult {
                mem_bus_new_state: Some(true),
                io_bus_new_state: None,
            }
        );

        // Rewrite the same IO + mem value again (result should be no change).
        assert_eq!(
            test_dev.config_register_write(COMMAND_REG, 0, &3u32.to_le_bytes()),
            ConfigWriteResult {
                mem_bus_new_state: None,
                io_bus_new_state: None,
            }
        );

        // Disable IO space access, leaving mem enabled.
        assert_eq!(
            test_dev.config_register_write(COMMAND_REG, 0, &2u32.to_le_bytes()),
            ConfigWriteResult {
                mem_bus_new_state: None,
                io_bus_new_state: Some(false),
            }
        );

        // Re-enable IO space and disable mem simultaneously.
        assert_eq!(
            test_dev.config_register_write(COMMAND_REG, 0, &1u32.to_le_bytes()),
            ConfigWriteResult {
                mem_bus_new_state: Some(false),
                io_bus_new_state: Some(true),
            }
        );
    }
}

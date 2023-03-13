// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use acpi_tables::sdt::SDT;
use anyhow::bail;
use base::error;
use base::Event;
use base::MemoryMapping;
use base::RawDescriptor;
use base::Tube;
use hypervisor::Datamatch;
use remain::sorted;
use resources::Error as SystemAllocatorFaliure;
use resources::SystemAllocator;
use sync::Mutex;
use thiserror::Error;
use vm_control::IoEventUpdateRequest;
use vm_control::VmMemoryResponse;

use super::PciId;
use crate::bus::BusDeviceObj;
use crate::bus::BusRange;
use crate::bus::BusType;
use crate::bus::ConfigWriteResult;
use crate::pci::pci_configuration;
use crate::pci::pci_configuration::PciBarConfiguration;
use crate::pci::pci_configuration::BAR0_REG;
use crate::pci::pci_configuration::COMMAND_REG;
use crate::pci::pci_configuration::COMMAND_REG_IO_SPACE_MASK;
use crate::pci::pci_configuration::COMMAND_REG_MEMORY_SPACE_MASK;
use crate::pci::pci_configuration::NUM_BAR_REGS;
use crate::pci::pci_configuration::PCI_ID_REG;
use crate::pci::pci_configuration::ROM_BAR_REG;
use crate::pci::PciAddress;
use crate::pci::PciAddressError;
use crate::pci::PciInterruptPin;
use crate::virtio::ipc_memory_mapper::IpcMemoryMapper;
#[cfg(all(unix, feature = "audio"))]
use crate::virtio::snd::vios_backend::Error as VioSError;
use crate::BusAccessInfo;
use crate::BusDevice;
use crate::DeviceId;
use crate::IrqLevelEvent;
use crate::Suspendable;

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    /// Added pci device's parent bus does not belong to this bus
    #[error("pci device {0}'s parent bus does not belong to bus {1}")]
    AddedDeviceBusNotExist(PciAddress, u8),
    /// Invalid alignment encountered.
    #[error("Alignment must be a power of 2")]
    BadAlignment,
    /// The new bus has already been added to this bus
    #[error("Added bus {0} already existed on bus {1}")]
    BusAlreadyExist(u8, u8),
    /// Target bus not exists on this bus
    #[error("pci bus {0} does not exist on bus {1}")]
    BusNotExist(u8, u8),
    /// Setup of the device capabilities failed.
    #[error("failed to add capability {0}")]
    CapabilitiesSetup(pci_configuration::Error),
    /// Create cras client failed.
    #[cfg(all(unix, feature = "audio", feature = "audio_cras"))]
    #[error("failed to create CRAS Client: {0}")]
    CreateCrasClientFailed(libcras::Error),
    /// Create VioS client failed.
    #[cfg(all(unix, feature = "audio"))]
    #[error("failed to create VioS Client: {0}")]
    CreateViosClientFailed(VioSError),
    /// Device is already on this bus
    #[error("pci device {0} has already been added to bus {1}")]
    DeviceAlreadyExist(PciAddress, u8),
    /// Device not exist on this bus
    #[error("pci device {0} does not located on bus {1}")]
    DeviceNotExist(PciAddress, u8),
    /// Allocating space for an IO BAR failed.
    #[error("failed to allocate space for an IO BAR, size={0}: {1}")]
    IoAllocationFailed(u64, SystemAllocatorFaliure),
    /// ioevent registration failed.
    #[error("IoEvent registration failed: {0}")]
    IoEventRegisterFailed(IoEventError),
    /// supports_iommu is false.
    #[error("Iommu is not supported")]
    IommuNotSupported,
    /// Registering an IO BAR failed.
    #[error("failed to register an IO BAR, addr={0} err={1}")]
    IoRegistrationFailed(u64, pci_configuration::Error),
    /// Out-of-space encountered
    #[error("Out-of-space detected")]
    OutOfSpace,
    /// Overflow encountered
    #[error("base={0} + size={1} overflows")]
    Overflow(u64, u64),
    /// The new added bus does not located on this bus
    #[error("Added bus {0} does not located on bus {1}")]
    ParentBusNotExist(u8, u8),
    /// PCI Address is not allocated.
    #[error("PCI address is not allocated")]
    PciAddressMissing,
    /// PCI Address parsing failure.
    #[error("PCI address '{0}' could not be parsed: {1}")]
    PciAddressParseFailure(String, PciAddressError),
    /// PCI Address allocation failure.
    #[error("failed to allocate PCI address")]
    PciAllocationFailed,
    /// PCI Bus window allocation failure.
    #[error("failed to allocate window for PCI bus: {0}")]
    PciBusWindowAllocationFailure(String),
    /// Size of zero encountered
    #[error("Size of zero detected")]
    SizeZero,
}

/// Errors when io event registration fails:
#[derive(Clone, Debug, Error)]
pub enum IoEventError {
    /// Event clone failed.
    #[error("Event clone failed: {0}")]
    CloneFail(base::Error),
    /// Failed due to system error.
    #[error("System error: {0}")]
    SystemError(base::Error),
    /// Tube for ioevent register failed.
    #[error("IoEvent register Tube failed")]
    TubeFail,
    /// ioevent_register_request not implemented for PciDevice emitting it.
    #[error("ioevent register not implemented")]
    Unsupported,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Pci Bar Range information
#[derive(Clone, Debug)]
pub struct BarRange {
    /// pci bar start address
    pub addr: u64,
    /// pci bar size
    pub size: u64,
    /// pci bar is prefetchable or not, it used to set parent's bridge window
    pub prefetchable: bool,
}

/// Pci Bus information
#[derive(Debug)]
pub struct PciBus {
    // bus number
    bus_num: u8,
    // parent bus number
    parent_bus_num: u8,
    // devices located on this bus
    child_devices: HashSet<PciAddress>,
    // Hash map that stores all direct child buses of this bus.
    // It maps from child bus number to its pci bus structure.
    child_buses: HashMap<u8, Arc<Mutex<PciBus>>>,
    // Is hotplug bus
    hotplug_bus: bool,
}

impl PciBus {
    // Creates a new pci bus
    pub fn new(bus_num: u8, parent_bus_num: u8, hotplug_bus: bool) -> Self {
        PciBus {
            bus_num,
            parent_bus_num,
            child_devices: HashSet::new(),
            child_buses: HashMap::new(),
            hotplug_bus,
        }
    }

    pub fn get_bus_num(&self) -> u8 {
        self.bus_num
    }

    // Find all PCI buses from this PCI bus to a given PCI bus
    pub fn path_to(&self, bus_num: u8) -> Vec<u8> {
        if self.bus_num == bus_num {
            return vec![self.bus_num];
        }

        for (_, child_bus) in self.child_buses.iter() {
            let mut path = child_bus.lock().path_to(bus_num);
            if !path.is_empty() {
                path.insert(0, self.bus_num);
                return path;
            }
        }
        Vec::new()
    }

    // Add a new child device to this pci bus tree.
    pub fn add_child_device(&mut self, add_device: PciAddress) -> Result<()> {
        if self.bus_num == add_device.bus {
            if !self.child_devices.insert(add_device) {
                return Err(Error::DeviceAlreadyExist(add_device, self.bus_num));
            }
            return Ok(());
        }

        for child_bus in self.child_buses.values() {
            match child_bus.lock().add_child_device(add_device) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if let Error::DeviceAlreadyExist(_, _) = e {
                        return Err(e);
                    }
                }
            }
        }
        Err(Error::AddedDeviceBusNotExist(add_device, self.bus_num))
    }

    // Remove one child device from this pci bus tree
    pub fn remove_child_device(&mut self, device: PciAddress) -> Result<()> {
        if self.child_devices.remove(&device) {
            return Ok(());
        }
        for child_bus in self.child_buses.values() {
            if child_bus.lock().remove_child_device(device).is_ok() {
                return Ok(());
            }
        }
        Err(Error::DeviceNotExist(device, self.bus_num))
    }

    // Add a new child bus to this pci bus tree.
    pub fn add_child_bus(&mut self, add_bus: Arc<Mutex<PciBus>>) -> Result<()> {
        let add_bus_num = add_bus.lock().bus_num;
        let add_bus_parent = add_bus.lock().parent_bus_num;
        if self.bus_num == add_bus_parent {
            if self.child_buses.contains_key(&add_bus_num) {
                return Err(Error::BusAlreadyExist(self.bus_num, add_bus_num));
            }
            self.child_buses.insert(add_bus_num, add_bus);
            return Ok(());
        }

        for child_bus in self.child_buses.values() {
            match child_bus.lock().add_child_bus(add_bus.clone()) {
                Ok(_) => return Ok(()),
                Err(e) => {
                    if let Error::BusAlreadyExist(_, _) = e {
                        return Err(e);
                    }
                }
            }
        }
        Err(Error::ParentBusNotExist(add_bus_num, self.bus_num))
    }

    // Remove one child bus from this pci bus tree.
    pub fn remove_child_bus(&mut self, bus_no: u8) -> Result<()> {
        if self.child_buses.remove(&bus_no).is_some() {
            return Ok(());
        }
        for (_, child_bus) in self.child_buses.iter() {
            if child_bus.lock().remove_child_bus(bus_no).is_ok() {
                return Ok(());
            }
        }
        Err(Error::BusNotExist(bus_no, self.bus_num))
    }

    // Find all downstream devices under the given bus
    pub fn find_downstream_devices(&self, bus_no: u8) -> Vec<PciAddress> {
        if self.bus_num == bus_no {
            return self.get_downstream_devices();
        }
        for (_, child_bus) in self.child_buses.iter() {
            let res = child_bus.lock().find_downstream_devices(bus_no);
            if !res.is_empty() {
                return res;
            }
        }

        Vec::new()
    }

    // Get all devices in this pci bus tree by level-order traversal (BFS)
    pub fn get_downstream_devices(&self) -> Vec<PciAddress> {
        let mut devices = Vec::new();
        devices.extend(self.child_devices.clone());
        for child_bus in self.child_buses.values() {
            devices.extend(child_bus.lock().get_downstream_devices());
        }
        devices
    }

    // Check if given device is located in the device tree
    pub fn contains(&self, device: PciAddress) -> bool {
        if self.child_devices.contains(&device) {
            return true;
        }

        for (_, child_bus) in self.child_buses.iter() {
            if child_bus.lock().contains(device) {
                return true;
            }
        }

        false
    }

    // Returns the hotplug bus that this device is on.
    pub fn get_hotplug_bus(&self, device: PciAddress) -> Option<u8> {
        if self.hotplug_bus && self.contains(device) {
            return Some(self.bus_num);
        }
        for (_, child_bus) in self.child_buses.iter() {
            let hotplug_bus = child_bus.lock().get_hotplug_bus(device);
            if hotplug_bus.is_some() {
                return hotplug_bus;
            }
        }
        None
    }
}

pub enum PreferredIrq {
    None,
    Any,
    Fixed { pin: PciInterruptPin, gsi: u32 },
}

pub trait PciDevice: Send + Suspendable {
    /// Returns a label suitable for debug output.
    fn debug_label(&self) -> String;

    /// Preferred PCI address for this device, if any.
    fn preferred_address(&self) -> Option<PciAddress> {
        None
    }

    /// Allocate and return an unique bus, device and function number for this device.
    /// May be called multiple times; on subsequent calls, the device should return the same
    /// address it returned from the first call.
    fn allocate_address(&mut self, resources: &mut SystemAllocator) -> Result<PciAddress>;

    /// A vector of device-specific file descriptors that must be kept open
    /// after jailing. Must be called before the process is jailed.
    fn keep_rds(&self) -> Vec<RawDescriptor>;

    /// Preferred IRQ for this device.
    /// The device may request a specific pin and IRQ number by returning a `Fixed` value.
    /// If a device does not support INTx# interrupts at all, it should return `None`.
    /// Otherwise, an appropriate IRQ will be allocated automatically.
    /// The device's `assign_irq` function will be called with its assigned IRQ either way.
    fn preferred_irq(&self) -> PreferredIrq {
        PreferredIrq::Any
    }

    /// Assign a legacy PCI IRQ to this device.
    /// The device may write to `irq_evt` to trigger an interrupt.
    /// When `irq_resample_evt` is signaled, the device should re-assert `irq_evt` if necessary.
    fn assign_irq(&mut self, _irq_evt: IrqLevelEvent, _pin: PciInterruptPin, _irq_num: u32) {}

    /// Allocates the needed IO BAR space using the `allocate` function which takes a size and
    /// returns an address. Returns a Vec of BarRange{addr, size, prefetchable}.
    fn allocate_io_bars(&mut self, _resources: &mut SystemAllocator) -> Result<Vec<BarRange>> {
        Ok(Vec::new())
    }

    /// Allocates the needed device BAR space. Returns a Vec of BarRange{addr, size, prefetchable}.
    /// Unlike MMIO BARs (see allocate_io_bars), device BARs are not expected to incur VM exits
    /// - these BARs represent normal memory.
    fn allocate_device_bars(&mut self, _resources: &mut SystemAllocator) -> Result<Vec<BarRange>> {
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

    /// Gets a reference to the Tube for sending VmMemoryRequest. Any devices that uses ioevents
    /// shall provide Tube.
    fn get_vm_memory_request_tube(&self) -> Option<&Tube> {
        None
    }

    /// Reads from a PCI configuration register.
    /// * `reg_idx` - PCI register index (in units of 4 bytes).
    fn read_config_register(&self, reg_idx: usize) -> u32;

    /// Writes to a PCI configuration register.
    /// * `reg_idx` - PCI register index (in units of 4 bytes).
    /// * `offset`  - byte offset within 4-byte register.
    /// * `data`    - The data to write.
    fn write_config_register(&mut self, reg_idx: usize, offset: u64, data: &[u8]);

    /// Reads from a virtual config register.
    /// * `reg_idx` - virtual config register index (in units of 4 bytes).
    fn read_virtual_config_register(&self, _reg_idx: usize) -> u32 {
        0
    }

    /// Writes to a virtual config register.
    /// * `reg_idx` - virtual config register index (in units of 4 bytes).
    /// * `value`   - the value to be written.
    fn write_virtual_config_register(&mut self, _reg_idx: usize, _value: u32) {}

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

    /// Construct customized acpi method, and return the AML code and
    /// shared memory
    fn generate_acpi_methods(&mut self) -> (Vec<u8>, Option<(u32, MemoryMapping)>) {
        (Vec::new(), None)
    }

    /// Invoked when the device is destroyed
    fn destroy_device(&mut self) {}

    /// Get the removed children devices under pci bridge
    fn get_removed_children_devices(&self) -> Vec<PciAddress> {
        Vec::new()
    }

    /// Get the pci bus generated by this pci device
    fn get_new_pci_bus(&self) -> Option<Arc<Mutex<PciBus>>> {
        None
    }

    /// if device is a pci brdige, configure pci bridge window
    fn configure_bridge_window(
        &mut self,
        _resources: &mut SystemAllocator,
        _bar_ranges: &[BarRange],
    ) -> Result<Vec<BarRange>> {
        Ok(Vec::new())
    }

    /// if device is a pci bridge, configure subordinate bus number
    fn set_subordinate_bus(&mut self, _bus_no: u8) {}

    /// Indicates whether the device supports IOMMU
    fn supports_iommu(&self) -> bool {
        false
    }

    /// Sets the IOMMU for the device if `supports_iommu()`
    fn set_iommu(&mut self, _iommu: IpcMemoryMapper) -> anyhow::Result<()> {
        bail!("Iommu not supported.");
    }
}

impl<T: PciDevice> BusDevice for T {
    fn debug_label(&self) -> String {
        PciDevice::debug_label(self)
    }

    fn device_id(&self) -> DeviceId {
        // Use the PCI ID for PCI devices, which contains the PCI vendor ID and the PCI device ID
        let pci_id: PciId = PciDevice::read_config_register(self, PCI_ID_REG).into();
        pci_id.into()
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
            let old_ranges = self.get_ranges();
            self.write_config_register(reg_idx, offset, data);
            let new_command_reg = self.read_config_register(COMMAND_REG);
            let new_ranges = self.get_ranges();

            // Inform the caller of state changes.
            if (old_command_reg ^ new_command_reg) & COMMAND_REG_MEMORY_SPACE_MASK != 0 {
                // Enable memory, add new_mmio into mmio_bus
                if new_command_reg & COMMAND_REG_MEMORY_SPACE_MASK != 0 {
                    for (range, bus_type) in new_ranges.iter() {
                        if *bus_type == BusType::Mmio && range.base != 0 {
                            result.mmio_add.push(*range);
                        }
                    }
                } else {
                    // Disable memory, remove old_mmio from mmio_bus
                    for (range, bus_type) in old_ranges.iter() {
                        if *bus_type == BusType::Mmio && range.base != 0 {
                            result.mmio_remove.push(*range);
                        }
                    }
                }
            }
            if (old_command_reg ^ new_command_reg) & COMMAND_REG_IO_SPACE_MASK != 0 {
                // Enable IO, add new_io into io_bus
                if new_command_reg & COMMAND_REG_IO_SPACE_MASK != 0 {
                    for (range, bus_type) in new_ranges.iter() {
                        if *bus_type == BusType::Io && range.base != 0 {
                            result.io_add.push(*range);
                        }
                    }
                } else {
                    // Disable IO, remove old_io from io_bus
                    for (range, bus_type) in old_ranges.iter() {
                        if *bus_type == BusType::Io && range.base != 0 {
                            result.io_remove.push(*range);
                        }
                    }
                }
            }
        } else if (BAR0_REG..=BAR0_REG + 5).contains(&reg_idx) || reg_idx == ROM_BAR_REG {
            let old_ranges = self.get_ranges();
            self.write_config_register(reg_idx, offset, data);
            let new_ranges = self.get_ranges();

            for ((old_range, old_type), (new_range, new_type)) in
                old_ranges.iter().zip(new_ranges.iter())
            {
                if *old_type != *new_type {
                    error!(
                        "{}: bar {:x} type changed after a bar write",
                        self.debug_label(),
                        reg_idx
                    );
                    continue;
                }
                if old_range.base != new_range.base {
                    if *new_type == BusType::Mmio {
                        if old_range.base != 0 {
                            result.mmio_remove.push(*old_range);
                        }
                        if new_range.base != 0 {
                            result.mmio_add.push(*new_range);
                        }
                    } else {
                        if old_range.base != 0 {
                            result.io_remove.push(*old_range);
                        }
                        if new_range.base != 0 {
                            result.io_add.push(*new_range);
                        }
                    }
                }
            }
            // Handles ioevent changes:
            if !(result.io_add.is_empty()
                || result.io_remove.is_empty()
                || result.mmio_add.is_empty()
                || result.mmio_remove.is_empty())
            {
                let (ioevent_unregister_requests, ioevent_register_requests) =
                    match get_ioevent_requests(self.ioevents(), old_ranges, new_ranges) {
                        Ok(a) => a,
                        Err(e) => {
                            error!("Failed to get ioevent requests: {:?}", e);
                            return result;
                        }
                    };
                if let Some(tube) = self.get_vm_memory_request_tube() {
                    for request in ioevent_unregister_requests {
                        if let Err(e) = send_ioevent_update_request(tube, request) {
                            match &e {
                                IoEventError::SystemError(_) => {
                                    // Do nothing, as unregister may fail due to placeholder value
                                }
                                _ => {
                                    error!(
                                        "IoEvent unregister failed for {}: {:?}",
                                        self.debug_label(),
                                        &e
                                    );
                                }
                            }
                        }
                    }
                    for request in ioevent_register_requests {
                        if let Err(e) = send_ioevent_update_request(tube, request) {
                            error!(
                                "IoEvent register failed for {}: {:?}",
                                self.debug_label(),
                                &e
                            );
                        }
                    }
                } else {
                    error!(
                        "get_vm_memory_request_tube not implemented for {}, device may malfunction",
                        self.debug_label()
                    );
                }
            }
        } else {
            self.write_config_register(reg_idx, offset, data);
            let children_pci_addr = self.get_removed_children_devices();
            if !children_pci_addr.is_empty() {
                result.removed_pci_devices = children_pci_addr;
            }
        }

        result
    }

    fn config_register_read(&self, reg_idx: usize) -> u32 {
        self.read_config_register(reg_idx)
    }

    fn virtual_config_register_write(&mut self, reg_idx: usize, value: u32) {
        self.write_virtual_config_register(reg_idx, value);
    }

    fn virtual_config_register_read(&self, reg_idx: usize) -> u32 {
        self.read_virtual_config_register(reg_idx)
    }

    fn on_sandboxed(&mut self) {
        self.on_device_sandboxed();
    }

    fn get_ranges(&self) -> Vec<(BusRange, BusType)> {
        let mut ranges = Vec::new();
        for bar_num in 0..NUM_BAR_REGS {
            if let Some(bar) = self.get_bar_configuration(bar_num) {
                let bus_type = if bar.is_memory() {
                    BusType::Mmio
                } else {
                    BusType::Io
                };
                ranges.push((
                    BusRange {
                        base: bar.address(),
                        len: bar.size(),
                    },
                    bus_type,
                ));
            }
        }
        ranges
    }

    // Invoked when the device is destroyed
    fn destroy_device(&mut self) {
        self.destroy_device()
    }

    fn is_bridge(&self) -> Option<u8> {
        self.get_new_pci_bus().map(|bus| bus.lock().get_bus_num())
    }
}

impl<T: PciDevice + ?Sized> PciDevice for Box<T> {
    /// Returns a label suitable for debug output.
    fn debug_label(&self) -> String {
        (**self).debug_label()
    }
    fn preferred_address(&self) -> Option<PciAddress> {
        (**self).preferred_address()
    }
    fn allocate_address(&mut self, resources: &mut SystemAllocator) -> Result<PciAddress> {
        (**self).allocate_address(resources)
    }
    fn keep_rds(&self) -> Vec<RawDescriptor> {
        (**self).keep_rds()
    }
    fn preferred_irq(&self) -> PreferredIrq {
        (**self).preferred_irq()
    }
    fn assign_irq(&mut self, irq_evt: IrqLevelEvent, pin: PciInterruptPin, irq_num: u32) {
        (**self).assign_irq(irq_evt, pin, irq_num)
    }
    fn allocate_io_bars(&mut self, resources: &mut SystemAllocator) -> Result<Vec<BarRange>> {
        (**self).allocate_io_bars(resources)
    }
    fn allocate_device_bars(&mut self, resources: &mut SystemAllocator) -> Result<Vec<BarRange>> {
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
    fn read_virtual_config_register(&self, reg_idx: usize) -> u32 {
        (**self).read_virtual_config_register(reg_idx)
    }
    fn write_virtual_config_register(&mut self, reg_idx: usize, value: u32) {
        (**self).write_virtual_config_register(reg_idx, value)
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

    fn generate_acpi_methods(&mut self) -> (Vec<u8>, Option<(u32, MemoryMapping)>) {
        (**self).generate_acpi_methods()
    }

    fn destroy_device(&mut self) {
        (**self).destroy_device();
    }
    fn get_new_pci_bus(&self) -> Option<Arc<Mutex<PciBus>>> {
        (**self).get_new_pci_bus()
    }
    fn get_removed_children_devices(&self) -> Vec<PciAddress> {
        (**self).get_removed_children_devices()
    }

    fn configure_bridge_window(
        &mut self,
        resources: &mut SystemAllocator,
        bar_ranges: &[BarRange],
    ) -> Result<Vec<BarRange>> {
        (**self).configure_bridge_window(resources, bar_ranges)
    }
}

impl<T: PciDevice + ?Sized> Suspendable for Box<T> {
    fn snapshot(&self) -> anyhow::Result<serde_json::Value> {
        (**self).snapshot()
    }

    fn restore(&mut self, data: serde_json::Value) -> anyhow::Result<()> {
        (**self).restore(data)
    }

    fn sleep(&mut self) -> anyhow::Result<()> {
        (**self).sleep()
    }

    fn wake(&mut self) -> anyhow::Result<()> {
        (**self).wake()
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

/// Gets the ioevent requests based on new ioevents and changes to the BAR.
///
/// Assumes the number of ioevents are unchanged after bar remapping, and corresponds to the same
/// BAR regions.
/// Returns pair (ioevent_unregister_requests, ioevent_register_requests) to be handled by device.
fn get_ioevent_requests(
    mut ioevents: Vec<(&Event, u64, Datamatch)>,
    old_range: Vec<(BusRange, BusType)>,
    new_range: Vec<(BusRange, BusType)>,
) -> Result<(Vec<IoEventUpdateRequest>, Vec<IoEventUpdateRequest>)> {
    // Finds all ioevents with addr within new_range. Updates ioevents whose range are within the
    // changed windows. Bus ranges are disjoint since they are memory addresses. sort both ioevents
    // and range to get asymptotic optimal solution.
    ioevents.sort_by_key(|ioevent| ioevent.1);
    // Old and new ranges are paired to be sorted together to keep the correspondence.
    let mut range_pair: Vec<((BusRange, BusType), (BusRange, BusType))> =
        new_range.into_iter().zip(old_range.into_iter()).collect();
    range_pair.sort_by_key(|(new, _old)| new.0.base);
    let mut range_pair_iter = range_pair.iter();
    let mut cur_range_pair = range_pair_iter.next();
    let mut ioevent_iter = ioevents.into_iter();
    let mut cur_ioevent = ioevent_iter.next();
    let mut ioevent_unregister_requests = Vec::new();
    let mut ioevent_register_requests = Vec::new();
    while let Some((event, addr, datamatch)) = cur_ioevent {
        if let Some(((new_bus_range, _), (old_bus_range, _))) = cur_range_pair {
            if new_bus_range.contains(addr) {
                let offset = addr - new_bus_range.base;
                ioevent_unregister_requests.push(IoEventUpdateRequest {
                    event: event
                        .try_clone()
                        .map_err(|e| Error::IoEventRegisterFailed(IoEventError::CloneFail(e)))?,
                    addr: offset + old_bus_range.base,
                    datamatch,
                    register: false,
                });
                ioevent_register_requests.push(IoEventUpdateRequest {
                    event: event
                        .try_clone()
                        .map_err(|e| Error::IoEventRegisterFailed(IoEventError::CloneFail(e)))?,
                    addr,
                    datamatch,
                    register: true,
                });
                cur_ioevent = ioevent_iter.next();
                continue;
            }
            // Advance range if range upper bound is too small.
            else if new_bus_range.base + new_bus_range.len <= addr {
                cur_range_pair = range_pair_iter.next();
                cur_ioevent = Some((event, addr, datamatch));
                continue;
            }
            // Advance ioevent if ioevent is lower than range lower bound.
            else {
                cur_ioevent = ioevent_iter.next();
                continue;
            }
        }
        // Stop if range is depleted.
        break;
    }
    Ok((ioevent_unregister_requests, ioevent_register_requests))
}

/// Sends ioevents through the tube, and returns result.
fn send_ioevent_update_request(
    tube: &Tube,
    request: IoEventUpdateRequest,
) -> std::result::Result<(), IoEventError> {
    tube.send(&request).map_err(|_| IoEventError::TubeFail)?;
    if let VmMemoryResponse::Err(e) = tube
        .recv::<VmMemoryResponse>()
        .map_err(|_| IoEventError::TubeFail)?
    {
        return Err(IoEventError::SystemError(e));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use pci_configuration::PciBarPrefetchable;
    use pci_configuration::PciBarRegionType;
    use pci_configuration::PciClassCode;
    use pci_configuration::PciConfiguration;
    use pci_configuration::PciHeaderType;
    use pci_configuration::PciMultimediaSubclass;

    use super::*;

    const BAR0_SIZE: u64 = 0x1000;
    const BAR2_SIZE: u64 = 0x20;
    const BAR0_ADDR: u64 = 0xc0000000;
    const BAR2_ADDR: u64 = 0x800;

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
            self.config_regs.write_reg(reg_idx, offset, data)
        }

        fn read_bar(&mut self, _addr: u64, _data: &mut [u8]) {}

        fn write_bar(&mut self, _addr: u64, _data: &[u8]) {}

        fn allocate_address(&mut self, _resources: &mut SystemAllocator) -> Result<PciAddress> {
            Err(Error::PciAllocationFailed)
        }

        fn get_bar_configuration(&self, bar_num: usize) -> Option<PciBarConfiguration> {
            self.config_regs.get_bar_configuration(bar_num)
        }
    }

    impl Suspendable for TestDev {}

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
                0x5678,
                0xEF01,
                0,
            ),
        };

        let _ = test_dev.config_regs.add_pci_bar(
            PciBarConfiguration::new(
                0,
                BAR0_SIZE,
                PciBarRegionType::Memory64BitRegion,
                PciBarPrefetchable::Prefetchable,
            )
            .set_address(BAR0_ADDR),
        );
        let _ = test_dev.config_regs.add_pci_bar(
            PciBarConfiguration::new(
                2,
                BAR2_SIZE,
                PciBarRegionType::IoRegion,
                PciBarPrefetchable::NotPrefetchable,
            )
            .set_address(BAR2_ADDR),
        );
        let bar0_range = BusRange {
            base: BAR0_ADDR,
            len: BAR0_SIZE,
        };
        let bar2_range = BusRange {
            base: BAR2_ADDR,
            len: BAR2_SIZE,
        };

        // Initialize command register to an all-zeroes value.
        test_dev.config_register_write(COMMAND_REG, 0, &0u32.to_le_bytes());

        // Enable IO space access (bit 0 of command register).
        assert_eq!(
            test_dev.config_register_write(COMMAND_REG, 0, &1u32.to_le_bytes()),
            ConfigWriteResult {
                mmio_remove: Vec::new(),
                mmio_add: Vec::new(),
                io_remove: Vec::new(),
                io_add: vec![bar2_range],
                removed_pci_devices: Vec::new(),
            }
        );

        // Enable memory space access (bit 1 of command register).
        assert_eq!(
            test_dev.config_register_write(COMMAND_REG, 0, &3u32.to_le_bytes()),
            ConfigWriteResult {
                mmio_remove: Vec::new(),
                mmio_add: vec![bar0_range],
                io_remove: Vec::new(),
                io_add: Vec::new(),
                removed_pci_devices: Vec::new(),
            }
        );

        // Rewrite the same IO + mem value again (result should be no change).
        assert_eq!(
            test_dev.config_register_write(COMMAND_REG, 0, &3u32.to_le_bytes()),
            ConfigWriteResult {
                mmio_remove: Vec::new(),
                mmio_add: Vec::new(),
                io_remove: Vec::new(),
                io_add: Vec::new(),
                removed_pci_devices: Vec::new(),
            }
        );

        // Disable IO space access, leaving mem enabled.
        assert_eq!(
            test_dev.config_register_write(COMMAND_REG, 0, &2u32.to_le_bytes()),
            ConfigWriteResult {
                mmio_remove: Vec::new(),
                mmio_add: Vec::new(),
                io_remove: vec![bar2_range],
                io_add: Vec::new(),
                removed_pci_devices: Vec::new(),
            }
        );

        // Disable mem space access.
        assert_eq!(
            test_dev.config_register_write(COMMAND_REG, 0, &0u32.to_le_bytes()),
            ConfigWriteResult {
                mmio_remove: vec![bar0_range],
                mmio_add: Vec::new(),
                io_remove: Vec::new(),
                io_add: Vec::new(),
                removed_pci_devices: Vec::new(),
            }
        );

        assert_eq!(test_dev.get_ranges(), Vec::new());

        // Re-enable mem and IO space.
        assert_eq!(
            test_dev.config_register_write(COMMAND_REG, 0, &3u32.to_le_bytes()),
            ConfigWriteResult {
                mmio_remove: Vec::new(),
                mmio_add: vec![bar0_range],
                io_remove: Vec::new(),
                io_add: vec![bar2_range],
                removed_pci_devices: Vec::new(),
            }
        );

        // Change Bar0's address
        assert_eq!(
            test_dev.config_register_write(BAR0_REG, 0, &0xD0000000u32.to_le_bytes()),
            ConfigWriteResult {
                mmio_remove: vec!(bar0_range),
                mmio_add: vec![BusRange {
                    base: 0xD0000000,
                    len: BAR0_SIZE
                }],
                io_remove: Vec::new(),
                io_add: Vec::new(),
                removed_pci_devices: Vec::new(),
            }
        );
    }

    #[test]
    fn test_get_ioevent_request() {
        // Of the ioevents, only 108, 112, 116 are within the changed windows.
        // Corresponding old addresses are 208, 212, and 16.
        let events = vec![
            Event::new().unwrap(),
            Event::new().unwrap(),
            Event::new().unwrap(),
            Event::new().unwrap(),
            Event::new().unwrap(),
        ];
        let ioevents = vec![
            (&events[0], 100, Datamatch::AnyLength),
            (&events[1], 108, Datamatch::AnyLength),
            (&events[2], 112, Datamatch::AnyLength),
            (&events[3], 116, Datamatch::AnyLength),
            (&events[4], 120, Datamatch::AnyLength),
        ];
        let old_range = vec![
            (BusRange { base: 208, len: 8 }, BusType::Mmio),
            (BusRange { base: 16, len: 4 }, BusType::Mmio),
        ];
        let new_range = vec![
            (BusRange { base: 108, len: 8 }, BusType::Mmio),
            (BusRange { base: 116, len: 4 }, BusType::Mmio),
        ];
        let (mut unregister_requests, mut register_requests) =
            get_ioevent_requests(ioevents, old_range, new_range).unwrap();
        unregister_requests.sort_by_key(|request| request.addr);
        assert_eq!(unregister_requests.len(), 3);
        assert_eq!(unregister_requests[0].addr, 16);
        assert_eq!(unregister_requests[1].addr, 208);
        assert_eq!(unregister_requests[2].addr, 212);
        register_requests.sort_by_key(|request| request.addr);
        assert_eq!(register_requests.len(), 3);
        assert_eq!(register_requests[0].addr, 108);
        assert_eq!(register_requests[1].addr, 112);
        assert_eq!(register_requests[2].addr, 116);
    }
}

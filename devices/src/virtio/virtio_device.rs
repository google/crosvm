// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use acpi_tables::sdt::SDT;
use base::{Event, RawDescriptor};
use vm_memory::GuestMemory;

use super::*;
use crate::pci::{MsixStatus, PciAddress, PciBarConfiguration, PciBarIndex, PciCapability};

/// Trait for virtio devices to be driven by a virtio transport.
///
/// The lifecycle of a virtio device is to be moved to a virtio transport, which will then query the
/// device. Once the guest driver has configured the device, `VirtioDevice::activate` will be called
/// and all the events, memory, and queues for device operation will be moved into the device.
/// Optionally, a virtio device can implement device reset in which it returns said resources and
/// resets its internal.
pub trait VirtioDevice: Send {
    /// Returns a label suitable for debug output.
    fn debug_label(&self) -> String {
        match type_to_str(self.device_type()) {
            Some(s) => format!("virtio-{}", s),
            None => format!("virtio (type {})", self.device_type()),
        }
    }

    /// A vector of device-specific file descriptors that must be kept open
    /// after jailing. Must be called before the process is jailed.
    fn keep_rds(&self) -> Vec<RawDescriptor>;

    /// The virtio device type.
    fn device_type(&self) -> u32;

    /// The maximum size of each queue that this device supports.
    fn queue_max_sizes(&self) -> &[u16];

    /// The number of interrupts used by this device.
    fn num_interrupts(&self) -> usize {
        self.queue_max_sizes().len()
    }

    /// The set of feature bits that this device supports in addition to the base features.
    /// If this returns VIRTIO_F_ACCESS_PLATFORM, virtio-iommu will be enabled for this device.
    fn features(&self) -> u64 {
        0
    }

    /// Acknowledges that this set of features should be enabled.
    fn ack_features(&mut self, value: u64) {
        let _ = value;
    }

    /// Reads this device configuration space at `offset`.
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let _ = offset;
        let _ = data;
    }

    /// Writes to this device configuration space at `offset`.
    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let _ = offset;
        let _ = data;
    }

    /// Activates this device for real usage.
    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        queues: Vec<Queue>,
        queue_evts: Vec<Event>,
    );

    /// Optionally deactivates this device. If the reset method is
    /// not able to reset the virtio device, or the virtio device model doesn't
    /// implement the reset method, a false value is returned to indicate
    /// the reset is not successful. Otherwise a true value should be returned.
    fn reset(&mut self) -> bool {
        false
    }

    /// Returns any additional BAR configuration required by the device.
    fn get_device_bars(&mut self, _address: PciAddress) -> Vec<PciBarConfiguration> {
        Vec::new()
    }

    /// Returns any additional capabiltiies required by the device.
    fn get_device_caps(&self) -> Vec<Box<dyn PciCapability>> {
        Vec::new()
    }

    /// Invoked when the device is sandboxed.
    fn on_device_sandboxed(&mut self) {}

    fn control_notify(&self, _behavior: MsixStatus) {}

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn generate_acpi(
        &mut self,
        _pci_address: &Option<PciAddress>,
        sdts: Vec<SDT>,
    ) -> Option<Vec<SDT>> {
        Some(sdts)
    }

    /// Reads from a BAR region mapped in to the device.
    /// * `addr` - The guest address inside the BAR.
    /// * `data` - Filled with the data from `addr`.
    fn read_bar(&mut self, _bar_index: PciBarIndex, _offset: u64, _data: &mut [u8]) {}

    /// Writes to a BAR region mapped in to the device.
    /// * `addr` - The guest address inside the BAR.
    /// * `data` - The data to write.
    fn write_bar(&mut self, _bar_index: PciBarIndex, _offset: u64, _data: &[u8]) {}

    /// Returns the PCI address where the device will be allocated.
    /// Returns `None` if any address is good for the device.
    fn pci_address(&self) -> Option<PciAddress> {
        None
    }
}

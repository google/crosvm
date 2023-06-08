// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::sync::Arc;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use acpi_tables::sdt::SDT;
use anyhow::Result;
use base::Error as BaseError;
use base::Event;
use base::Protection;
use base::RawDescriptor;
use remain::sorted;
use sync::Mutex;
use thiserror::Error;
use vm_control::VmMemorySource;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

use super::*;
use crate::pci::MsixStatus;
use crate::pci::PciAddress;
use crate::pci::PciBarConfiguration;
use crate::pci::PciBarIndex;
use crate::pci::PciCapability;
use crate::virtio::ipc_memory_mapper::IpcMemoryMapper;
use crate::Suspendable;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioTransportType {
    Pci,
    Mmio,
}

#[derive(Clone)]
pub struct SharedMemoryRegion {
    /// The id of the shared memory region. A device may have multiple regions, but each
    /// must have a unique id. The meaning of a particular region is device-specific.
    pub id: u8,
    pub length: u64,
}

/// Trait for mapping memory into the device's shared memory region.
pub trait SharedMemoryMapper: Send {
    /// Maps the given |source| into the shared memory region at |offset|.
    fn add_mapping(&mut self, source: VmMemorySource, offset: u64, prot: Protection) -> Result<()>;

    /// Removes the mapping beginning at |offset|.
    fn remove_mapping(&mut self, offset: u64) -> Result<()>;

    fn as_raw_descriptor(&self) -> Option<RawDescriptor> {
        None
    }
}

/// Trait for virtio devices to be driven by a virtio transport.
///
/// The lifecycle of a virtio device is to be moved to a virtio transport, which will then query the
/// device. Once the guest driver has configured the device, `VirtioDevice::activate` will be called
/// and all the events, memory, and queues for device operation will be moved into the device.
/// Optionally, a virtio device can implement device reset in which it returns said resources and
/// resets its internal.
pub trait VirtioDevice: Send + Suspendable {
    /// Returns a label suitable for debug output.
    fn debug_label(&self) -> String {
        format!("virtio-{}", self.device_type())
    }

    /// A vector of device-specific file descriptors that must be kept open
    /// after jailing. Must be called before the process is jailed.
    fn keep_rds(&self) -> Vec<RawDescriptor>;

    /// The virtio device type.
    fn device_type(&self) -> DeviceType;

    /// The maximum size of each queue that this device supports.
    fn queue_max_sizes(&self) -> &[u16];

    /// The number of interrupts used by this device.
    fn num_interrupts(&self) -> usize {
        self.queue_max_sizes().len()
    }

    /// Whether this device supports a virtio-iommu.
    fn supports_iommu(&self) -> bool {
        false
    }

    /// The set of feature bits that this device supports in addition to the base features.
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

    /// If the device is translated by an IOMMU, called before
    /// |activate| with the IOMMU's mapper.
    fn set_iommu(&mut self, iommu: &Arc<Mutex<IpcMemoryMapper>>) {
        let _ = iommu;
    }

    /// Activates this device for real usage.
    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        queues: Vec<(Queue, Event)>,
    ) -> Result<()>;

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

    /// Returns the Virtio transport type: PCI (default for crosvm) or MMIO.
    fn transport_type(&self) -> VirtioTransportType {
        VirtioTransportType::Pci
    }

    /// Returns the device's shared memory region if present.
    fn get_shared_memory_region(&self) -> Option<SharedMemoryRegion> {
        None
    }

    /// If true, VFIO passthrough devices can access descriptors mapped into
    /// this region by mapping the corresponding addresses from this device's
    /// PCI bar into their IO address space with virtio-iommu.
    ///
    /// NOTE: Not all vm_control::VmMemorySource types are supported.
    fn expose_shmem_descriptors_with_viommu(&self) -> bool {
        false
    }

    /// Provides the trait object used to map files into the device's shared
    /// memory region.
    ///
    /// If `get_shared_memory_region` returns `Some`, then this will be called
    /// before `activate`.
    fn set_shared_memory_mapper(&mut self, _mapper: Box<dyn SharedMemoryMapper>) {}

    /// Provides the base address of the shared memory region, if one is present. Will
    /// be called before `activate`.
    ///
    /// NOTE: Mappings in shared memory regions should be accessed via offset, rather
    /// than via raw guest physical address. This function is only provided so
    /// devices can remain backwards compatible with older drivers.
    fn set_shared_memory_region_base(&mut self, _addr: GuestAddress) {}

    /// Stop the device and return queues and GuestMemory to the underlying bus that the virtio
    /// device resides on (Pci/Mmio) to preserve their state.
    fn stop(&mut self) -> Result<Option<VirtioDeviceSaved>, Error> {
        Err(Error::NotImplemented(self.debug_label()))
    }

    /// Pause all processing.
    ///
    /// Gives up the queues so that a higher layer can potentially snapshot them. The
    /// implementations should also drop the `Interrupt` and queues `Event`s that were given along
    /// with the queues originally.
    ///
    /// Unlike `Suspendable::sleep`, this is not idempotent. Attempting to sleep while already
    /// asleep is an error.
    fn virtio_sleep(&mut self) -> anyhow::Result<Option<Vec<Queue>>> {
        anyhow::bail!("virtio_sleep not implemented for {}", self.debug_label());
    }

    /// Resume all processing.
    ///
    /// If the device's queues are active, then the queues and associated data will is included.
    ///
    /// Unlike `Suspendable::wake`, this is not idempotent. Attempting to wake while already awake
    /// is an error.
    fn virtio_wake(
        &mut self,
        _queues_state: Option<(GuestMemory, Interrupt, Vec<(Queue, Event)>)>,
    ) -> anyhow::Result<()> {
        anyhow::bail!("virtio_wake not implemented for {}", self.debug_label());
    }

    /// Snapshot current state. Device must be asleep.
    fn virtio_snapshot(&self) -> anyhow::Result<serde_json::Value> {
        anyhow::bail!("virtio_snapshot not implemented for {}", self.debug_label());
    }

    /// Restore device state from a snapshot.
    fn virtio_restore(&mut self, _data: serde_json::Value) -> anyhow::Result<()> {
        anyhow::bail!("virtio_restore not implemented for {}", self.debug_label());
    }
}

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("thread error: {0}")]
    InThreadFailure(anyhow::Error),
    #[error("failed to kill {0} worker thread")]
    KillEventFailure(BaseError),
    #[error("Stop is not implemented for: {0}")]
    NotImplemented(String),
    #[error("thread ending failed: {0}")]
    ThreadJoinFailure(String),
}

pub struct VirtioDeviceSaved {
    pub queues: Vec<Queue>,
}

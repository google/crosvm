// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::sync::Arc;

#[cfg(target_arch = "x86_64")]
use acpi_tables::sdt::SDT;
use anyhow::Result;
use base::Event;
use base::Protection;
use base::RawDescriptor;
use hypervisor::MemCacheType;
use sync::Mutex;
use vm_control::VmMemorySource;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

use super::*;
use crate::pci::MsixConfig;
use crate::pci::MsixStatus;
use crate::pci::PciAddress;
use crate::pci::PciBarConfiguration;
use crate::pci::PciBarIndex;
use crate::pci::PciCapability;
use crate::virtio::queue::QueueConfig;

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
    fn add_mapping(
        &mut self,
        source: VmMemorySource,
        offset: u64,
        prot: Protection,
        cache: MemCacheType,
    ) -> Result<()>;

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
pub trait VirtioDevice: Send {
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

    /// Activates this device for real usage.
    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt: Interrupt,
        queues: BTreeMap<usize, Queue>,
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

    #[cfg(target_arch = "x86_64")]
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

    /// Pause all processing.
    ///
    /// Gives up the queues so that a higher layer can potentially snapshot them. The
    /// implementations should also drop the `Interrupt` and queues `Event`s that were given along
    /// with the queues originally.
    ///
    /// Unlike `Suspendable::sleep`, this is not idempotent. Attempting to sleep while already
    /// asleep is an error.
    fn virtio_sleep(&mut self) -> anyhow::Result<Option<BTreeMap<usize, Queue>>> {
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
        _queues_state: Option<(GuestMemory, Interrupt, BTreeMap<usize, Queue>)>,
    ) -> anyhow::Result<()> {
        anyhow::bail!("virtio_wake not implemented for {}", self.debug_label());
    }

    /// Snapshot current state. Device must be asleep.
    fn virtio_snapshot(&mut self) -> anyhow::Result<serde_json::Value> {
        anyhow::bail!("virtio_snapshot not implemented for {}", self.debug_label());
    }

    /// Restore device state from a snapshot.
    /// TODO(b/280607404): Vhost user will need fds passed to the device process.
    fn virtio_restore(&mut self, _data: serde_json::Value) -> anyhow::Result<()> {
        anyhow::bail!("virtio_restore not implemented for {}", self.debug_label());
    }

    /// Returns true if the device uses the vhost user protocol.
    fn is_vhost_user(&self) -> bool {
        false
    }

    /// Vhost user device specific restore to be called instead of `virtio_restore`. This will
    /// rewire irqfds, queue_evts, start up the worker if needed, and send a RESTORE request to
    /// the device process.
    fn vhost_user_restore(
        &mut self,
        _data: serde_json::Value,
        _queue_configs: &[QueueConfig],
        _queue_evts: Option<Vec<Event>>,
        _interrupt: Option<Interrupt>,
        _mem: GuestMemory,
        _msix_config: &Arc<Mutex<MsixConfig>>,
        _device_activated: bool,
    ) -> anyhow::Result<()> {
        anyhow::bail!(
            "vhost_user_restore not implemented for {}",
            self.debug_label()
        );
    }

    // Returns a tuple consisting of the non-arch specific part of the OpenFirmware path,
    // represented as bytes, and the boot index of a device. The non-arch specific part of path for
    // a virtio-blk device, for example, would consist of everything after the first '/' below:
    // pci@i0cf8/scsi@6[,3]/disk@0,0
    //    ^           ^  ^       ^ ^
    //    |           |  |       fixed
    //    |           | (PCI function related to disk (optional))
    // (x86 specf  (PCI slot holding disk)
    //  root at sys
    //  bus port)
    fn bootorder_fw_cfg(&self, _pci_address: u8) -> Option<(Vec<u8>, usize)> {
        None
    }
}

// General tests that should pass on all suspendables.
// Do implement device-specific tests to validate the functionality of the device.
// Those tests are not a replacement for regular tests. Only an extension specific to the trait's
// basic functionality.
/// `name` is the name of the test grouping. Can be anything unique within the same crate.
/// `dev` is a block that returns a created virtio device.
/// ``num_queues` is the number of queues to be created.
/// `modfun` is the function name of the function that would modify the device. The function call
/// should modify the device so that a snapshot taken after the function call would be different
/// from a snapshot taken before the function call.
#[macro_export]
macro_rules! suspendable_virtio_tests {
    ($name:ident, $dev: expr, $num_queues:literal, $modfun:expr) => {
        mod $name {
            use $crate::virtio::QueueConfig;

            use super::*;

            fn memory() -> GuestMemory {
                GuestMemory::new(&[(GuestAddress(0u64), 4 * 1024 * 1024)])
                    .expect("Creating guest memory failed.")
            }

            fn interrupt() -> Interrupt {
                Interrupt::new_for_test()
            }

            fn create_queues(
                num_queues: usize,
                queue_size: u16,
                mem: &GuestMemory,
            ) -> BTreeMap<usize, Queue> {
                let mut queues = BTreeMap::new();
                for i in 0..num_queues {
                    // activate with queues of an arbitrary size.
                    let mut queue = QueueConfig::new(queue_size, 0);
                    queue.set_ready(true);
                    let queue = queue
                        .activate(mem, Event::new().unwrap())
                        .expect("QueueConfig::activate");
                    queues.insert(i, queue);
                }
                queues
            }

            #[test]
            fn test_sleep_snapshot() {
                let (_ctx, device) = &mut $dev();
                let mem = memory();
                let interrupt = interrupt();
                let queues = create_queues(
                    $num_queues,
                    device
                        .queue_max_sizes()
                        .first()
                        .cloned()
                        .expect("missing queue size"),
                    &mem,
                );
                device
                    .activate(mem.clone(), interrupt.clone(), queues)
                    .expect("failed to activate");
                device
                    .virtio_sleep()
                    .expect("failed to sleep")
                    .expect("missing queues while sleeping");
                device.virtio_snapshot().expect("failed to snapshot");
            }

            #[test]
            fn test_sleep_snapshot_wake() {
                let (_ctx, device) = &mut $dev();
                let mem = memory();
                let interrupt = interrupt();
                let queues = create_queues(
                    $num_queues,
                    device
                        .queue_max_sizes()
                        .first()
                        .cloned()
                        .expect("missing queue size"),
                    &mem,
                );
                device
                    .activate(mem.clone(), interrupt.clone(), queues)
                    .expect("failed to activate");
                let sleep_result = device
                    .virtio_sleep()
                    .expect("failed to sleep")
                    .expect("missing queues while sleeping");
                device.virtio_snapshot().expect("failed to snapshot");
                device
                    .virtio_wake(Some((mem.clone(), interrupt.clone(), sleep_result)))
                    .expect("failed to wake");
            }

            #[test]
            fn test_suspend_mod_restore() {
                let (context, device) = &mut $dev();
                let mem = memory();
                let interrupt = interrupt();
                let queues = create_queues(
                    $num_queues,
                    device
                        .queue_max_sizes()
                        .first()
                        .cloned()
                        .expect("missing queue size"),
                    &mem,
                );
                device
                    .activate(mem.clone(), interrupt.clone(), queues)
                    .expect("failed to activate");
                let sleep_result = device
                    .virtio_sleep()
                    .expect("failed to sleep")
                    .expect("missing queues while sleeping");
                // Modify device before snapshotting.
                $modfun(context, device);
                let snap = device
                    .virtio_snapshot()
                    .expect("failed to take initial snapshot");
                device
                    .virtio_wake(Some((mem.clone(), interrupt.clone(), sleep_result)))
                    .expect("failed to wake");
                let (_, device) = &mut $dev();
                device
                    .virtio_restore(snap.clone())
                    .expect("failed to restore");
                let snap2 = device
                    .virtio_snapshot()
                    .expect("failed to take snapshot after mod");
                assert_eq!(snap, snap2);
            }
        }
    };
}

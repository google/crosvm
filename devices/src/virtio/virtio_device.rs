// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;

#[cfg(target_arch = "x86_64")]
use acpi_tables::sdt::SDT;
use anyhow::anyhow;
use anyhow::Result;
use base::Protection;
use base::RawDescriptor;
use hypervisor::MemCacheType;
use resources::AddressRange;
use snapshot::AnySnapshot;
use vm_control::VmMemorySource;
use vm_memory::GuestMemory;

use super::*;
use crate::pci::MsixStatus;
use crate::pci::PciAddress;
use crate::pci::PciBarConfiguration;
use crate::pci::PciCapability;

/// Type of Virtio device memory mapping to use.
pub enum SharedMemoryPrepareType {
    /// On first attempted mapping, the entire SharedMemoryRegion is configured with declared
    /// MemCacheType.
    SingleMappingOnFirst(MemCacheType),
    /// No mapping preparation is performed. each mapping is handled individually
    DynamicPerMapping,
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
///
/// Virtio device state machine
/// ```none
///                           restore (inactive)
///       ----------------------------------------------------
///       |                                                  |
///       |                                                  V
///       |                       ------------         --------------
/// ------------- restore(active) |  asleep  |         |   asleep   |   // States in this row
/// |asleep(new)|---------------> | (active) |         | (inactive) |   // can be snapshotted
/// -------------                 ------------         --------------
///    ^       |                     ^    |              ^      |
///    |       |                     |    |              |      |
///  sleep    wake                sleep  wake         sleep   wake
///    |       |                     |    |              |      |
///    |       V                     |    V              |      V
///  ------------     activate     ----------  reset   ------------
///  |    new   | ---------------> | active | ------>  | inactive |
///  ------------                  ---------- <------  ------------
///                                           activate
/// ```
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
    /// implement the reset method, an `Err` value is returned to indicate
    /// the reset is not successful. Otherwise `Ok(())` should be returned.
    fn reset(&mut self) -> Result<()> {
        Err(anyhow!("reset not implemented for {}", self.debug_label()))
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
        pci_address: PciAddress,
        sdts: &mut Vec<SDT>,
    ) -> anyhow::Result<()> {
        let _ = pci_address;
        let _ = sdts;
        Ok(())
    }

    /// Returns the PCI address where the device will be allocated.
    /// Returns `None` if any address is good for the device.
    fn pci_address(&self) -> Option<PciAddress> {
        None
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
    /// NOTE: Not yet compatible with PrepareSharedMemoryRegion (aka fixed mapping).
    fn expose_shmem_descriptors_with_viommu(&self) -> bool {
        false
    }

    /// Provides the trait object used to map files into the device's shared
    /// memory region.
    ///
    /// If `get_shared_memory_region` returns `Some`, then this will be called
    /// before `activate`.
    fn set_shared_memory_mapper(&mut self, _mapper: Box<dyn SharedMemoryMapper>) {}

    /// Provides the guest address range of the shared memory region, if one is present. Will
    /// be called before `activate`.
    fn set_shared_memory_region(&mut self, shmem_region: AddressRange) {
        let _ = shmem_region;
    }

    /// Queries the implementation whether a single prepared hypervisor memory mapping with explicit
    /// caching type should be setup lazily on first mapping request, or whether to dynamically
    /// setup a hypervisor mapping with every request's caching type.
    fn get_shared_memory_prepare_type(&mut self) -> SharedMemoryPrepareType {
        // default to lazy-prepare of a single memslot with explicit caching type
        SharedMemoryPrepareType::SingleMappingOnFirst(MemCacheType::CacheCoherent)
    }

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
    fn virtio_snapshot(&mut self) -> anyhow::Result<AnySnapshot> {
        anyhow::bail!("virtio_snapshot not implemented for {}", self.debug_label());
    }

    /// Restore device state from a snapshot.
    /// TODO(b/280607404): Vhost user will need fds passed to the device process.
    fn virtio_restore(&mut self, _data: AnySnapshot) -> anyhow::Result<()> {
        anyhow::bail!("virtio_restore not implemented for {}", self.debug_label());
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
                use vm_memory::GuestAddress;
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
                interrupt: Interrupt,
            ) -> BTreeMap<usize, Queue> {
                let mut queues = BTreeMap::new();
                for i in 0..num_queues {
                    // activate with queues of an arbitrary size.
                    let mut queue = QueueConfig::new(queue_size, 0);
                    queue.set_ready(true);
                    let queue = queue
                        .activate(mem, base::Event::new().unwrap(), interrupt.clone())
                        .expect("QueueConfig::activate");
                    queues.insert(i, queue);
                }
                queues
            }

            #[test]
            fn test_unactivated_sleep_snapshot_wake() {
                let (_ctx, mut device) = $dev();
                let sleep_result = device.virtio_sleep().expect("failed to sleep");
                assert!(sleep_result.is_none());
                device.virtio_snapshot().expect("failed to snapshot");
                device.virtio_wake(None).expect("failed to wake");
            }

            #[test]
            fn test_sleep_snapshot_wake() {
                let (_ctx, mut device) = $dev();
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
                    interrupt.clone(),
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
                let (mut context, mut device) = $dev();
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
                    interrupt.clone(),
                );
                device
                    .activate(mem.clone(), interrupt.clone(), queues)
                    .expect("failed to activate");
                let sleep_result = device
                    .virtio_sleep()
                    .expect("failed to sleep")
                    .expect("missing queues while sleeping");
                // Modify device before snapshotting.
                $modfun(&mut context, &mut device);
                let snap = device
                    .virtio_snapshot()
                    .expect("failed to take initial snapshot");
                device
                    .virtio_wake(Some((mem.clone(), interrupt.clone(), sleep_result)))
                    .expect("failed to wake");

                // Create a new device to restore the previously taken snapshot
                let (_ctx2, mut device) = $dev();
                // Sleep the device before restore
                assert!(device.virtio_sleep().expect("failed to sleep").is_none());
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

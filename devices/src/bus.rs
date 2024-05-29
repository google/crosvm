// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Handles routing to devices in an address space.

use std::cmp::Ord;
use std::cmp::Ordering;
use std::cmp::PartialEq;
use std::cmp::PartialOrd;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;
use std::result;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::Context;
use base::debug;
use base::error;
use base::Event;
use base::SharedMemory;
use remain::sorted;
use serde::Deserialize;
use serde::Serialize;
use sync::Mutex;
use thiserror::Error;

#[cfg(feature = "stats")]
use crate::bus_stats::BusOperation;
#[cfg(feature = "stats")]
use crate::BusStatistics;
use crate::DeviceId;
use crate::PciAddress;
use crate::PciDevice;
use crate::Suspendable;
#[cfg(any(target_os = "android", target_os = "linux"))]
use crate::VfioPlatformDevice;
use crate::VirtioMmioDevice;

/// Information about how a device was accessed.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct BusAccessInfo {
    /// Offset from base address that the device was accessed at.
    pub offset: u64,
    /// Absolute address of the device's access in its address space.
    pub address: u64,
    /// ID of the entity requesting a device access, usually the VCPU id.
    pub id: usize,
}

// Implement `Display` for `MinMax`.
impl std::fmt::Display for BusAccessInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Result of a write to a device's PCI configuration space.
/// This value represents the state change(s) that occurred due to the write.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConfigWriteResult {
    /// The BusRange in the vector will be removed from mmio_bus
    pub mmio_remove: Vec<BusRange>,

    /// The BusRange in the vector will be added into mmio_bus
    pub mmio_add: Vec<BusRange>,

    /// The BusRange in the vector will be removed from io_bus
    pub io_remove: Vec<BusRange>,

    /// The BusRange in the vector will be added into io_bus
    pub io_add: Vec<BusRange>,

    /// Device specified at PciAddress will be removed after this config write
    /// - `Vec<PciAddress>>`: specified device will be removed after this config write
    pub removed_pci_devices: Vec<PciAddress>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub enum BusType {
    Mmio,
    Io,
}

/// Trait for devices that respond to reads or writes in an arbitrary address space.
///
/// The device does not care where it exists in address space as each method is only given an offset
/// into its allocated portion of address space.
#[allow(unused_variables)]
pub trait BusDevice: Send + Suspendable {
    /// Returns a label suitable for debug output.
    fn debug_label(&self) -> String;
    /// Returns a unique id per device type suitable for metrics gathering.
    fn device_id(&self) -> DeviceId;
    /// Reads at `offset` from this device
    fn read(&mut self, offset: BusAccessInfo, data: &mut [u8]) {}
    /// Writes at `offset` into this device
    fn write(&mut self, offset: BusAccessInfo, data: &[u8]) {}
    /// Sets a register in the configuration space. Only used by PCI.
    /// * `reg_idx` - The index of the config register to modify.
    /// * `offset` - Offset in to the register.
    fn config_register_write(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> ConfigWriteResult {
        ConfigWriteResult {
            ..Default::default()
        }
    }
    /// Gets a register from the configuration space. Only used by PCI.
    /// * `reg_idx` - The index of the config register to read.
    fn config_register_read(&self, reg_idx: usize) -> u32 {
        0
    }
    /// Provides a memory region to back MMIO access to the configuration
    /// space. If the device can keep the memory region up to date, then it
    /// should return true, after which no more calls to config_register_read
    /// will be made. Otherwise the device should return false.
    ///
    /// The device must set the header type register (0x0E) before returning
    /// from this function, and must make no further modifications to it
    /// after returning. This is to allow the caller to manage the multi-
    /// function device bit without worrying about race conditions.
    ///
    /// * `shmem` - The shared memory to use for the configuration space.
    /// * `base` - The base address of the memory region in shmem.
    /// * `len` - The length of the memory region.
    fn init_pci_config_mapping(&mut self, shmem: &SharedMemory, base: usize, len: usize) -> bool {
        false
    }
    /// Sets a register in the virtual config space. Only used by PCI.
    /// * `reg_idx` - The index of the config register to modify.
    /// * `value` - The value to be written.
    fn virtual_config_register_write(&mut self, reg_idx: usize, value: u32) {}
    /// Gets a register from the virtual config space. Only used by PCI.
    /// * `reg_idx` - The index of the config register to read.
    fn virtual_config_register_read(&self, reg_idx: usize) -> u32 {
        0
    }
    /// Invoked when the device is sandboxed.
    fn on_sandboxed(&mut self) {}

    /// Gets a list of all ranges registered by this BusDevice.
    fn get_ranges(&self) -> Vec<(BusRange, BusType)> {
        Vec::new()
    }

    /// Invoked when the device is destroyed
    fn destroy_device(&mut self) {}

    /// Returns the secondary bus number if this bus device is pci bridge
    fn is_bridge(&self) -> Option<u8> {
        None
    }
}

pub trait BusDeviceSync: BusDevice + Sync {
    fn read(&self, offset: BusAccessInfo, data: &mut [u8]);
    fn write(&self, offset: BusAccessInfo, data: &[u8]);
    fn snapshot_sync(&self) -> anyhow::Result<serde_json::Value> {
        Err(anyhow!(
            "snapshot_sync not implemented for {}",
            std::any::type_name::<Self>()
        ))
    }
    /// Load a saved snapshot of an image.
    fn restore_sync(&self, _data: serde_json::Value) -> anyhow::Result<()> {
        Err(anyhow!(
            "restore_sync not implemented for {}",
            std::any::type_name::<Self>()
        ))
    }
    /// Stop all threads related to the device.
    /// Sleep should be idempotent.
    fn sleep_sync(&self) -> anyhow::Result<()> {
        Err(anyhow!(
            "sleep_sync not implemented for {}",
            std::any::type_name::<Self>()
        ))
    }
    /// Create/Resume all threads related to the device.
    /// Wake should be idempotent.
    fn wake_sync(&self) -> anyhow::Result<()> {
        Err(anyhow!(
            "wake_sync not implemented for {}",
            std::any::type_name::<Self>()
        ))
    }
}

pub trait BusResumeDevice: Send {
    /// notify the devices which are invoked
    /// before the VM resumes form suspend.
    fn resume_imminent(&mut self) {}
}

/// The key to identify hotplug device from host view.
/// like host sysfs path for vfio pci device, host disk file
/// path for virtio block device
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum HotPlugKey {
    HostUpstreamPort { host_addr: PciAddress },
    HostDownstreamPort { host_addr: PciAddress },
    HostVfio { host_addr: PciAddress },
    GuestDevice { guest_addr: PciAddress },
}

/// Trait for devices that notify hotplug event into guest
pub trait HotPlugBus: Send {
    /// Request hot plug event. Returns error if the request is not sent. Upon success, optionally
    /// returns an event, which is triggerred once when the guest OS completes the request (by
    /// sending PCI_EXP_SLTCTL_CCIE). Returns None if no such mechanism is provided.
    /// * 'addr' - the guest pci address for hotplug in device
    fn hot_plug(&mut self, addr: PciAddress) -> anyhow::Result<Option<Event>>;
    /// Request hot unplug event. Returns error if the request is not sent. Upon success, optionally
    /// returns an event, which is triggerred once when the guest OS completes the request (by
    /// sending PCI_EXP_SLTCTL_CCIE). Returns None if no such mechanism is provided.
    /// * 'addr' - the guest pci address for hotplug out device
    fn hot_unplug(&mut self, addr: PciAddress) -> anyhow::Result<Option<Event>>;
    /// Get a notification event when the HotPlugBus is ready for hot plug commands. If the port is
    /// already ready, then the notification event is triggerred immediately.
    fn get_ready_notification(&mut self) -> anyhow::Result<Event>;
    /// Check whether the hotplug bus is available to add the new device
    ///
    /// - 'None': hotplug bus isn't match with host pci device
    /// - 'Some(bus_num)': hotplug bus is match and put the device at bus_num
    fn is_match(&self, host_addr: PciAddress) -> Option<u8>;
    /// Gets the upstream PCI Address of the hotplug bus
    fn get_address(&self) -> Option<PciAddress>;
    /// Gets the secondary bus number of this bus
    fn get_secondary_bus_number(&self) -> Option<u8>;
    /// Add hotplug device into this bus
    /// * 'hotplug_key' - the key to identify hotplug device from host view
    /// * 'guest_addr' - the guest pci address for hotplug device
    fn add_hotplug_device(&mut self, hotplug_key: HotPlugKey, guest_addr: PciAddress);
    /// get guest pci address from the specified hotplug_key
    fn get_hotplug_device(&self, hotplug_key: HotPlugKey) -> Option<PciAddress>;
    /// Check whether this hotplug bus is empty
    fn is_empty(&self) -> bool;
    /// Get hotplug key of this hotplug bus
    fn get_hotplug_key(&self) -> Option<HotPlugKey>;
}

/// Trait for generic device abstraction, that is, all devices that reside on BusDevice and want
/// to be converted back to its original type. Each new foo device must provide
/// as_foo_device() + as_foo_device_mut() + into_foo_device(), default impl methods return None.
pub trait BusDeviceObj {
    fn as_pci_device(&self) -> Option<&dyn PciDevice> {
        None
    }
    fn as_pci_device_mut(&mut self) -> Option<&mut dyn PciDevice> {
        None
    }
    fn into_pci_device(self: Box<Self>) -> Option<Box<dyn PciDevice>> {
        None
    }
    #[cfg(any(target_os = "android", target_os = "linux"))]
    fn as_platform_device(&self) -> Option<&VfioPlatformDevice> {
        None
    }
    #[cfg(any(target_os = "android", target_os = "linux"))]
    fn as_platform_device_mut(&mut self) -> Option<&mut VfioPlatformDevice> {
        None
    }
    #[cfg(any(target_os = "android", target_os = "linux"))]
    fn into_platform_device(self: Box<Self>) -> Option<Box<VfioPlatformDevice>> {
        None
    }
    fn as_virtio_mmio_device(&self) -> Option<&VirtioMmioDevice> {
        None
    }
    fn as_virtio_mmio_device_mut(&mut self) -> Option<&mut VirtioMmioDevice> {
        None
    }
    fn into_virtio_mmio_device(self: Box<Self>) -> Option<Box<VirtioMmioDevice>> {
        None
    }
}

#[sorted]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Bus Range not found")]
    Empty,
    /// The insertion failed because the new device overlapped with an old device.
    #[error("new device {base},{len} overlaps with an old device {other_base},{other_len}")]
    Overlap {
        base: u64,
        len: u64,
        other_base: u64,
        other_len: u64,
    },
}

pub type Result<T> = result::Result<T, Error>;

/// Holds a base and length representing the address space occupied by a `BusDevice`.
///
/// * base - The address at which the range start.
/// * len - The length of the range in bytes.
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct BusRange {
    pub base: u64,
    pub len: u64,
}

impl BusRange {
    /// Returns true if `addr` is within the range.
    pub fn contains(&self, addr: u64) -> bool {
        self.base <= addr && addr < self.base.saturating_add(self.len)
    }

    /// Returns true if there is overlap with the given range.
    pub fn overlaps(&self, base: u64, len: u64) -> bool {
        self.base < base.saturating_add(len) && base < self.base.saturating_add(self.len)
    }
}

impl Eq for BusRange {}

impl PartialEq for BusRange {
    fn eq(&self, other: &BusRange) -> bool {
        self.base == other.base
    }
}

impl Ord for BusRange {
    fn cmp(&self, other: &BusRange) -> Ordering {
        self.base.cmp(&other.base)
    }
}

impl PartialOrd for BusRange {
    fn partial_cmp(&self, other: &BusRange) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Debug for BusRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}..+{:#x}", self.base, self.len)
    }
}

#[derive(Clone)]
struct BusEntry {
    #[cfg(feature = "stats")]
    index: usize,
    device: BusDeviceEntry,
}

#[derive(Clone)]
enum BusDeviceEntry {
    OuterSync(Arc<Mutex<dyn BusDevice>>),
    InnerSync(Arc<dyn BusDeviceSync>),
}

/// A device container for routing reads and writes over some address space.
///
/// This doesn't have any restrictions on what kind of device or address space this applies to. The
/// only restriction is that no two devices can overlap in this address space.
#[derive(Clone)]
pub struct Bus {
    devices: Arc<Mutex<BTreeMap<BusRange, BusEntry>>>,
    access_id: usize,
    #[cfg(feature = "stats")]
    pub stats: Arc<Mutex<BusStatistics>>,
    bus_type: BusType,
}

impl Bus {
    /// Constructs an a bus with an empty address space.
    pub fn new(bus_type: BusType) -> Bus {
        Bus {
            devices: Arc::new(Mutex::new(BTreeMap::new())),
            access_id: 0,
            #[cfg(feature = "stats")]
            stats: Arc::new(Mutex::new(BusStatistics::new())),
            bus_type,
        }
    }

    /// Gets the bus type
    pub fn get_bus_type(&self) -> BusType {
        self.bus_type
    }

    /// Sets the id that will be used for BusAccessInfo.
    pub fn set_access_id(&mut self, id: usize) {
        self.access_id = id;
    }

    fn first_before(&self, addr: u64) -> Option<(BusRange, BusEntry)> {
        let devices = self.devices.lock();
        let (range, entry) = devices
            .range(..=BusRange { base: addr, len: 1 })
            .next_back()?;
        Some((*range, entry.clone()))
    }

    fn get_device(&self, addr: u64) -> Option<(u64, u64, BusEntry)> {
        if let Some((range, entry)) = self.first_before(addr) {
            let offset = addr - range.base;
            if offset < range.len {
                return Some((offset, addr, entry));
            }
        }
        None
    }

    /// There is no unique ID for device instances. For now we use the Arc pointers to dedup them.
    ///
    /// See virtio-gpu for an example of a single device instance with multiple bus entries.
    ///
    /// TODO: Add a unique ID to BusDevice and use that instead of pointers.
    fn unique_devices(&self) -> Vec<BusDeviceEntry> {
        let mut seen_ptrs = BTreeSet::new();
        self.devices
            .lock()
            .iter()
            .map(|(_, bus_entry)| bus_entry.device.clone())
            .filter(|dev| match dev {
                BusDeviceEntry::OuterSync(dev) => seen_ptrs.insert(Arc::as_ptr(dev) as *const u8),
                BusDeviceEntry::InnerSync(dev) => seen_ptrs.insert(Arc::as_ptr(dev) as *const u8),
            })
            .collect()
    }

    /// Same as `unique_devices`, but also calculates the "snapshot key" for each device.
    ///
    /// The keys are used to associate a particular device with data in a serialized snapshot. The
    /// keys need to be stable across multiple runs of the same crosvm binary.
    ///
    /// It is most convienent to calculate all the snapshot keys at once, because the keys are
    /// dependant on the order of devices on the bus.
    fn unique_devices_with_snapshot_key(&self) -> Vec<(String, BusDeviceEntry)> {
        let mut next_ids = BTreeMap::<String, usize>::new();
        let mut choose_key = |debug_label: String| -> String {
            let label = debug_label.replace(char::is_whitespace, "-");
            let id = next_ids.entry(label.clone()).or_default();
            let key = format!("{}-{}", label, id);
            *id += 1;
            key
        };

        let mut result = Vec::new();
        for device_entry in self.unique_devices() {
            let key = match &device_entry {
                BusDeviceEntry::OuterSync(d) => choose_key(d.lock().debug_label()),
                BusDeviceEntry::InnerSync(d) => choose_key(d.debug_label()),
            };
            result.push((key, device_entry));
        }
        result
    }

    pub fn sleep_devices(&self) -> anyhow::Result<()> {
        for device_entry in self.unique_devices() {
            match device_entry {
                BusDeviceEntry::OuterSync(dev) => {
                    let mut dev = (*dev).lock();
                    debug!("Sleep on device: {}", dev.debug_label());
                    dev.sleep()
                        .with_context(|| format!("failed to sleep {}", dev.debug_label()))?;
                }
                BusDeviceEntry::InnerSync(dev) => {
                    debug!("Sleep on device: {}", dev.debug_label());
                    dev.sleep_sync()
                        .with_context(|| format!("failed to sleep {}", dev.debug_label()))?;
                }
            }
        }
        Ok(())
    }

    pub fn wake_devices(&self) -> anyhow::Result<()> {
        for device_entry in self.unique_devices() {
            match device_entry {
                BusDeviceEntry::OuterSync(dev) => {
                    let mut dev = dev.lock();
                    debug!("Wake on device: {}", dev.debug_label());
                    dev.wake()
                        .with_context(|| format!("failed to wake {}", dev.debug_label()))?;
                }
                BusDeviceEntry::InnerSync(dev) => {
                    debug!("Wake on device: {}", dev.debug_label());
                    dev.wake_sync()
                        .with_context(|| format!("failed to wake {}", dev.debug_label()))?;
                }
            }
        }
        Ok(())
    }

    pub fn snapshot_devices(
        &self,
        snapshot_writer: &vm_control::SnapshotWriter,
    ) -> anyhow::Result<()> {
        for (snapshot_key, device_entry) in self.unique_devices_with_snapshot_key() {
            match device_entry {
                BusDeviceEntry::OuterSync(dev) => {
                    let mut dev = dev.lock();
                    debug!("Snapshot on device: {}", dev.debug_label());
                    snapshot_writer.write_fragment(
                        &snapshot_key,
                        &(*dev)
                            .snapshot()
                            .with_context(|| format!("failed to snapshot {}", dev.debug_label()))?,
                    )?;
                }
                BusDeviceEntry::InnerSync(dev) => {
                    debug!("Snapshot on device: {}", dev.debug_label());
                    snapshot_writer.write_fragment(
                        &snapshot_key,
                        &dev.snapshot_sync()
                            .with_context(|| format!("failed to snapshot {}", dev.debug_label()))?,
                    )?;
                }
            }
        }
        Ok(())
    }

    pub fn restore_devices(
        &self,
        snapshot_reader: &vm_control::SnapshotReader,
    ) -> anyhow::Result<()> {
        let mut unused_keys: BTreeSet<String> =
            snapshot_reader.list_fragments()?.into_iter().collect();
        for (snapshot_key, device_entry) in self.unique_devices_with_snapshot_key() {
            unused_keys.remove(&snapshot_key);
            match device_entry {
                BusDeviceEntry::OuterSync(dev) => {
                    let mut dev = dev.lock();
                    debug!("Restore on device: {}", dev.debug_label());
                    dev.restore(snapshot_reader.read_fragment(&snapshot_key)?)
                        .with_context(|| {
                            format!("restore failed for device {}", dev.debug_label())
                        })?;
                }
                BusDeviceEntry::InnerSync(dev) => {
                    debug!("Restore on device: {}", dev.debug_label());
                    dev.restore_sync(snapshot_reader.read_fragment(&snapshot_key)?)
                        .with_context(|| {
                            format!("restore failed for device {}", dev.debug_label())
                        })?;
                }
            }
        }

        if !unused_keys.is_empty() {
            error!(
                "unused restore data in bus, devices might be missing: {:?}",
                unused_keys
            );
        }

        Ok(())
    }

    /// Puts the given device at the given address space.
    pub fn insert(&self, device: Arc<Mutex<dyn BusDevice>>, base: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Err(Error::Overlap {
                base,
                len,
                other_base: 0,
                other_len: 0,
            });
        }

        // Reject all cases where the new device's range overlaps with an existing device.
        let mut devices = self.devices.lock();
        devices.iter().try_for_each(|(range, _dev)| {
            if range.overlaps(base, len) {
                Err(Error::Overlap {
                    base,
                    len,
                    other_base: range.base,
                    other_len: range.len,
                })
            } else {
                Ok(())
            }
        })?;

        #[cfg(feature = "stats")]
        let name = device.lock().debug_label();
        #[cfg(feature = "stats")]
        let device_id = device.lock().device_id();
        if devices
            .insert(
                BusRange { base, len },
                BusEntry {
                    #[cfg(feature = "stats")]
                    index: self
                        .stats
                        .lock()
                        .next_device_index(name, device_id.into(), base, len),
                    device: BusDeviceEntry::OuterSync(device),
                },
            )
            .is_some()
        {
            return Err(Error::Overlap {
                base,
                len,
                other_base: base,
                other_len: len,
            });
        }

        Ok(())
    }

    /// Puts the given device that implements BusDeviceSync at the given address space. Devices
    /// that implement BusDeviceSync manage thread safety internally, and thus can be written to
    /// by multiple threads simultaneously.
    pub fn insert_sync(&self, device: Arc<dyn BusDeviceSync>, base: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Err(Error::Overlap {
                base,
                len,
                other_base: 0,
                other_len: 0,
            });
        }

        // Reject all cases where the new device's range overlaps with an existing device.
        let mut devices = self.devices.lock();
        devices.iter().try_for_each(|(range, _dev)| {
            if range.overlaps(base, len) {
                Err(Error::Overlap {
                    base,
                    len,
                    other_base: range.base,
                    other_len: range.len,
                })
            } else {
                Ok(())
            }
        })?;

        if devices
            .insert(
                BusRange { base, len },
                BusEntry {
                    #[cfg(feature = "stats")]
                    index: self.stats.lock().next_device_index(
                        device.debug_label(),
                        device.device_id().into(),
                        base,
                        len,
                    ),
                    device: BusDeviceEntry::InnerSync(device),
                },
            )
            .is_some()
        {
            return Err(Error::Overlap {
                base,
                len,
                other_base: base,
                other_len: len,
            });
        }

        Ok(())
    }

    /// Remove the given device at the given address space.
    pub fn remove(&self, base: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Err(Error::Overlap {
                base,
                len,
                other_base: 0,
                other_len: 0,
            });
        }

        let mut devices = self.devices.lock();
        if devices
            .iter()
            .any(|(range, _dev)| range.base == base && range.len == len)
        {
            let ret = devices.remove(&BusRange { base, len });
            if ret.is_some() {
                Ok(())
            } else {
                Err(Error::Empty)
            }
        } else {
            Err(Error::Empty)
        }
    }

    /// Reads data from the device that owns the range containing `addr` and puts it into `data`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn read(&self, addr: u64, data: &mut [u8]) -> bool {
        #[cfg(feature = "stats")]
        let start = self.stats.lock().start_stat();

        let device_index = if let Some((offset, address, entry)) = self.get_device(addr) {
            let io = BusAccessInfo {
                address,
                offset,
                id: self.access_id,
            };

            match &entry.device {
                BusDeviceEntry::OuterSync(dev) => dev.lock().read(io, data),
                BusDeviceEntry::InnerSync(dev) => dev.read(io, data),
            }
            #[cfg(feature = "stats")]
            let index = Some(entry.index);
            #[cfg(not(feature = "stats"))]
            let index = Some(());
            index
        } else {
            None
        };

        #[cfg(feature = "stats")]
        if let Some(device_index) = device_index {
            self.stats
                .lock()
                .end_stat(BusOperation::Write, start, device_index);
            return true;
        }

        device_index.is_some()
    }

    /// Writes `data` to the device that owns the range containing `addr`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn write(&self, addr: u64, data: &[u8]) -> bool {
        #[cfg(feature = "stats")]
        let start = self.stats.lock().start_stat();

        let device_index = if let Some((offset, address, entry)) = self.get_device(addr) {
            let io = BusAccessInfo {
                address,
                offset,
                id: self.access_id,
            };

            match &entry.device {
                BusDeviceEntry::OuterSync(dev) => dev.lock().write(io, data),
                BusDeviceEntry::InnerSync(dev) => dev.write(io, data),
            }

            #[cfg(feature = "stats")]
            let index = Some(entry.index);
            #[cfg(not(feature = "stats"))]
            let index = Some(());
            index
        } else {
            None
        };

        #[cfg(feature = "stats")]
        if let Some(device_index) = device_index {
            self.stats
                .lock()
                .end_stat(BusOperation::Write, start, device_index);
        }
        device_index.is_some()
    }
}

impl Default for Bus {
    fn default() -> Self {
        Self::new(BusType::Io)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result as AnyhowResult;

    use super::*;
    use crate::pci::CrosvmDeviceId;
    use crate::suspendable::Suspendable;
    use crate::suspendable_tests;

    #[derive(Copy, Clone, Serialize, Deserialize, Eq, PartialEq, Debug)]
    struct DummyDevice;

    impl BusDevice for DummyDevice {
        fn device_id(&self) -> DeviceId {
            CrosvmDeviceId::Cmos.into()
        }
        fn debug_label(&self) -> String {
            "dummy device".to_owned()
        }
    }

    impl Suspendable for DummyDevice {
        fn snapshot(&mut self) -> AnyhowResult<serde_json::Value> {
            serde_json::to_value(self).context("error serializing")
        }

        fn restore(&mut self, data: serde_json::Value) -> AnyhowResult<()> {
            *self = serde_json::from_value(data).context("error deserializing")?;
            Ok(())
        }

        fn sleep(&mut self) -> AnyhowResult<()> {
            Ok(())
        }

        fn wake(&mut self) -> AnyhowResult<()> {
            Ok(())
        }
    }

    #[derive(Copy, Clone, Serialize, Deserialize, Eq, PartialEq, Debug)]
    struct ConstantDevice {
        uses_full_addr: bool,
    }

    impl BusDevice for ConstantDevice {
        fn device_id(&self) -> DeviceId {
            CrosvmDeviceId::Cmos.into()
        }

        fn debug_label(&self) -> String {
            "constant device".to_owned()
        }

        fn read(&mut self, info: BusAccessInfo, data: &mut [u8]) {
            let addr = if self.uses_full_addr {
                info.address
            } else {
                info.offset
            };
            for (i, v) in data.iter_mut().enumerate() {
                *v = (addr as u8) + (i as u8);
            }
        }

        fn write(&mut self, info: BusAccessInfo, data: &[u8]) {
            let addr = if self.uses_full_addr {
                info.address
            } else {
                info.offset
            };
            for (i, v) in data.iter().enumerate() {
                assert_eq!(*v, (addr as u8) + (i as u8))
            }
        }
    }

    impl Suspendable for ConstantDevice {
        fn snapshot(&mut self) -> AnyhowResult<serde_json::Value> {
            serde_json::to_value(self).context("error serializing")
        }

        fn restore(&mut self, data: serde_json::Value) -> AnyhowResult<()> {
            *self = serde_json::from_value(data).context("error deserializing")?;
            Ok(())
        }

        fn sleep(&mut self) -> AnyhowResult<()> {
            Ok(())
        }

        fn wake(&mut self) -> AnyhowResult<()> {
            Ok(())
        }
    }

    fn modify_constant_device(constant: &mut ConstantDevice) {
        constant.uses_full_addr = !constant.uses_full_addr;
    }

    #[test]
    fn bus_insert() {
        let bus = Bus::new(BusType::Io);
        let dummy = Arc::new(Mutex::new(DummyDevice));
        assert!(bus.insert(dummy.clone(), 0x10, 0).is_err());
        assert!(bus.insert(dummy.clone(), 0x10, 0x10).is_ok());
        assert!(bus.insert(dummy.clone(), 0x0f, 0x10).is_err());
        assert!(bus.insert(dummy.clone(), 0x10, 0x10).is_err());
        assert!(bus.insert(dummy.clone(), 0x10, 0x15).is_err());
        assert!(bus.insert(dummy.clone(), 0x12, 0x15).is_err());
        assert!(bus.insert(dummy.clone(), 0x12, 0x01).is_err());
        assert!(bus.insert(dummy.clone(), 0x0, 0x20).is_err());
        assert!(bus.insert(dummy.clone(), 0x20, 0x05).is_ok());
        assert!(bus.insert(dummy.clone(), 0x25, 0x05).is_ok());
        assert!(bus.insert(dummy, 0x0, 0x10).is_ok());
    }

    #[test]
    fn bus_insert_full_addr() {
        let bus = Bus::new(BusType::Io);
        let dummy = Arc::new(Mutex::new(DummyDevice));
        assert!(bus.insert(dummy.clone(), 0x10, 0).is_err());
        assert!(bus.insert(dummy.clone(), 0x10, 0x10).is_ok());
        assert!(bus.insert(dummy.clone(), 0x0f, 0x10).is_err());
        assert!(bus.insert(dummy.clone(), 0x10, 0x10).is_err());
        assert!(bus.insert(dummy.clone(), 0x10, 0x15).is_err());
        assert!(bus.insert(dummy.clone(), 0x12, 0x15).is_err());
        assert!(bus.insert(dummy.clone(), 0x12, 0x01).is_err());
        assert!(bus.insert(dummy.clone(), 0x0, 0x20).is_err());
        assert!(bus.insert(dummy.clone(), 0x20, 0x05).is_ok());
        assert!(bus.insert(dummy.clone(), 0x25, 0x05).is_ok());
        assert!(bus.insert(dummy, 0x0, 0x10).is_ok());
    }

    #[test]
    fn bus_read_write() {
        let bus = Bus::new(BusType::Io);
        let dummy = Arc::new(Mutex::new(DummyDevice));
        assert!(bus.insert(dummy, 0x10, 0x10).is_ok());
        assert!(bus.read(0x10, &mut [0, 0, 0, 0]));
        assert!(bus.write(0x10, &[0, 0, 0, 0]));
        assert!(bus.read(0x11, &mut [0, 0, 0, 0]));
        assert!(bus.write(0x11, &[0, 0, 0, 0]));
        assert!(bus.read(0x16, &mut [0, 0, 0, 0]));
        assert!(bus.write(0x16, &[0, 0, 0, 0]));
        assert!(!bus.read(0x20, &mut [0, 0, 0, 0]));
        assert!(!bus.write(0x20, &[0, 0, 0, 0]));
        assert!(!bus.read(0x06, &mut [0, 0, 0, 0]));
        assert!(!bus.write(0x06, &[0, 0, 0, 0]));
    }

    #[test]
    fn bus_read_write_values() {
        let bus = Bus::new(BusType::Io);
        let dummy = Arc::new(Mutex::new(ConstantDevice {
            uses_full_addr: false,
        }));
        assert!(bus.insert(dummy, 0x10, 0x10).is_ok());

        let mut values = [0, 1, 2, 3];
        assert!(bus.read(0x10, &mut values));
        assert_eq!(values, [0, 1, 2, 3]);
        assert!(bus.write(0x10, &values));
        assert!(bus.read(0x15, &mut values));
        assert_eq!(values, [5, 6, 7, 8]);
        assert!(bus.write(0x15, &values));
    }

    #[test]
    fn bus_read_write_full_addr_values() {
        let bus = Bus::new(BusType::Io);
        let dummy = Arc::new(Mutex::new(ConstantDevice {
            uses_full_addr: true,
        }));
        assert!(bus.insert(dummy, 0x10, 0x10).is_ok());

        let mut values = [0u8; 4];
        assert!(bus.read(0x10, &mut values));
        assert_eq!(values, [0x10, 0x11, 0x12, 0x13]);
        assert!(bus.write(0x10, &values));
        assert!(bus.read(0x15, &mut values));
        assert_eq!(values, [0x15, 0x16, 0x17, 0x18]);
        assert!(bus.write(0x15, &values));
    }

    suspendable_tests!(
        constant_device_true,
        ConstantDevice {
            uses_full_addr: true,
        },
        modify_constant_device
    );

    suspendable_tests!(
        constant_device_false,
        ConstantDevice {
            uses_full_addr: false,
        },
        modify_constant_device
    );

    #[test]
    fn bus_range_contains() {
        let a = BusRange {
            base: 0x1000,
            len: 0x400,
        };
        assert!(a.contains(0x1000));
        assert!(a.contains(0x13ff));
        assert!(!a.contains(0xfff));
        assert!(!a.contains(0x1400));
        assert!(a.contains(0x1200));
    }

    #[test]
    fn bus_range_overlap() {
        let a = BusRange {
            base: 0x1000,
            len: 0x400,
        };
        assert!(a.overlaps(0x1000, 0x400));
        assert!(a.overlaps(0xf00, 0x400));
        assert!(a.overlaps(0x1000, 0x01));
        assert!(a.overlaps(0xfff, 0x02));
        assert!(a.overlaps(0x1100, 0x100));
        assert!(a.overlaps(0x13ff, 0x100));
        assert!(!a.overlaps(0x1400, 0x100));
        assert!(!a.overlaps(0xf00, 0x100));
    }
}

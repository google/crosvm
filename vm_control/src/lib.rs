// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Handles IPC for controlling the main VM process.
//!
//! The VM Control IPC protocol is synchronous, meaning that each `VmRequest` sent over a connection
//! will receive a `VmResponse` for that request next time data is received over that connection.
//!
//! The wire message format is a little-endian C-struct of fixed size, along with a file descriptor
//! if the request type expects one.

pub mod api;
#[cfg(feature = "gdb")]
pub mod gdb;
#[cfg(feature = "gpu")]
pub mod gpu;

use base::debug;
#[cfg(any(target_os = "android", target_os = "linux"))]
use base::linux::MemoryMappingBuilderUnix;
#[cfg(any(target_os = "android", target_os = "linux"))]
use base::sys::call_with_extended_max_files;
#[cfg(any(target_os = "android", target_os = "linux"))]
use base::MemoryMappingArena;
#[cfg(windows)]
use base::MemoryMappingBuilderWindows;
use hypervisor::BalloonEvent;
use hypervisor::MemCacheType;
use hypervisor::MemRegion;
use snapshot::AnySnapshot;

#[cfg(feature = "balloon")]
mod balloon_tube;
pub mod client;
pub mod sys;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::_rdtsc;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt;
use std::fmt::Display;
use std::fs::File;
use std::path::Path;
use std::path::PathBuf;
use std::result::Result as StdResult;
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Instant;

use anyhow::bail;
use anyhow::Context;
use base::error;
use base::info;
use base::warn;
use base::with_as_descriptor;
use base::AsRawDescriptor;
use base::Descriptor;
use base::Error as SysError;
use base::Event;
use base::ExternalMapping;
use base::IntoRawDescriptor;
use base::MappedRegion;
use base::MemoryMappingBuilder;
use base::MmapError;
use base::Protection;
use base::Result;
use base::SafeDescriptor;
use base::SharedMemory;
use base::Tube;
use hypervisor::Datamatch;
use hypervisor::IoEventAddress;
use hypervisor::IrqRoute;
use hypervisor::IrqSource;
pub use hypervisor::MemSlot;
use hypervisor::Vm;
use hypervisor::VmCap;
use libc::EINVAL;
use libc::EIO;
use libc::ENODEV;
use libc::ENOTSUP;
use libc::ERANGE;
#[cfg(feature = "registered_events")]
use protos::registered_events;
use remain::sorted;
use resources::Alloc;
use resources::SystemAllocator;
use rutabaga_gfx::DeviceId;
use rutabaga_gfx::RutabagaDescriptor;
use rutabaga_gfx::RutabagaFromRawDescriptor;
use rutabaga_gfx::RutabagaGralloc;
use rutabaga_gfx::RutabagaHandle;
use rutabaga_gfx::RutabagaMappedRegion;
use rutabaga_gfx::VulkanInfo;
use serde::de::Error;
use serde::Deserialize;
use serde::Serialize;
use snapshot::SnapshotReader;
use snapshot::SnapshotWriter;
use swap::SwapStatus;
use sync::Mutex;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use sys::FsMappingRequest;
#[cfg(windows)]
pub use sys::InitialAudioSessionState;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use sys::VmMemoryMappingRequest;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use sys::VmMemoryMappingResponse;
use thiserror::Error;
pub use vm_control_product::GpuSendToMain;
pub use vm_control_product::GpuSendToService;
pub use vm_control_product::ServiceSendToGpu;
use vm_memory::GuestAddress;

#[cfg(feature = "balloon")]
pub use crate::balloon_tube::BalloonControlCommand;
#[cfg(feature = "balloon")]
pub use crate::balloon_tube::BalloonTube;
#[cfg(feature = "gdb")]
pub use crate::gdb::VcpuDebug;
#[cfg(feature = "gdb")]
pub use crate::gdb::VcpuDebugStatus;
#[cfg(feature = "gdb")]
pub use crate::gdb::VcpuDebugStatusMessage;
#[cfg(feature = "gpu")]
use crate::gpu::GpuControlCommand;
#[cfg(feature = "gpu")]
use crate::gpu::GpuControlResult;

/// Control the state of a particular VM CPU.
#[derive(Clone, Debug)]
pub enum VcpuControl {
    #[cfg(feature = "gdb")]
    Debug(VcpuDebug),
    RunState(VmRunMode),
    MakeRT,
    // Request the current state of the vCPU. The result is sent back over the included channel.
    GetStates(mpsc::Sender<VmRunMode>),
    // Request the vcpu write a snapshot of itself to the writer, then send a `Result` back over
    // the channel after completion/failure.
    Snapshot(SnapshotWriter, mpsc::Sender<anyhow::Result<()>>),
    Restore(VcpuRestoreRequest),
    #[cfg(any(target_os = "android", target_os = "linux"))]
    Throttle(u32),
}

/// Request to restore a Vcpu from a given snapshot, and report the results
/// back via the provided channel.
#[derive(Clone, Debug)]
pub struct VcpuRestoreRequest {
    pub result_sender: mpsc::Sender<anyhow::Result<()>>,
    pub snapshot_reader: SnapshotReader,
    #[cfg(target_arch = "x86_64")]
    pub host_tsc_reference_moment: u64,
}

/// Mode of execution for the VM.
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub enum VmRunMode {
    /// The default run mode indicating the VCPUs are running.
    #[default]
    Running,
    /// Indicates that the VCPUs are suspending execution until the `Running` mode is set.
    Suspending,
    /// Indicates that the VM is exiting all processes.
    Exiting,
    /// Indicates that the VM is in a breakpoint waiting for the debugger to do continue.
    Breakpoint,
}

impl Display for VmRunMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::VmRunMode::*;

        match self {
            Running => write!(f, "running"),
            Suspending => write!(f, "suspending"),
            Exiting => write!(f, "exiting"),
            Breakpoint => write!(f, "breakpoint"),
        }
    }
}

// Trait for devices that get notification on specific GPE trigger
pub trait GpeNotify: Send {
    fn notify(&mut self) {}
}

// Trait for devices that get notification on specific PCI PME
pub trait PmeNotify: Send {
    fn notify(&mut self, _requester_id: u16) {}
}

pub trait PmResource {
    fn pwrbtn_evt(&mut self) {}
    fn slpbtn_evt(&mut self) {}
    fn rtc_evt(&mut self, _clear_evt: Event) {}
    fn gpe_evt(&mut self, _gpe: u32, _clear_evt: Option<Event>) {}
    fn pme_evt(&mut self, _requester_id: u16) {}
    fn register_gpe_notify_dev(&mut self, _gpe: u32, _notify_dev: Arc<Mutex<dyn GpeNotify>>) {}
    fn register_pme_notify_dev(&mut self, _bus: u8, _notify_dev: Arc<Mutex<dyn PmeNotify>>) {}
}

/// The maximum number of devices that can be listed in one `UsbControlCommand`.
///
/// This value was set to be equal to `xhci_regs::MAX_PORTS` for convenience, but it is not
/// necessary for correctness. Importing that value directly would be overkill because it would
/// require adding a big dependency for a single const.
pub const USB_CONTROL_MAX_PORTS: usize = 16;

#[derive(Serialize, Deserialize, Debug)]
pub enum DiskControlCommand {
    /// Resize a disk to `new_size` in bytes.
    Resize { new_size: u64 },
}

impl Display for DiskControlCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::DiskControlCommand::*;

        match self {
            Resize { new_size } => write!(f, "disk_resize {}", new_size),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum DiskControlResult {
    Ok,
    Err(SysError),
}

/// Net control commands for adding and removing tap devices.
#[cfg(feature = "pci-hotplug")]
#[derive(Serialize, Deserialize, Debug)]
pub enum NetControlCommand {
    AddTap(String),
    RemoveTap(u8),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum UsbControlCommand {
    AttachDevice {
        #[serde(with = "with_as_descriptor")]
        file: File,
    },
    AttachSecurityKey {
        #[serde(with = "with_as_descriptor")]
        file: File,
    },
    DetachDevice {
        port: u8,
    },
    ListDevice {
        ports: [u8; USB_CONTROL_MAX_PORTS],
    },
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Default)]
pub struct UsbControlAttachedDevice {
    pub port: u8,
    pub vendor_id: u16,
    pub product_id: u16,
}

impl UsbControlAttachedDevice {
    pub fn valid(self) -> bool {
        self.port != 0
    }
}

#[cfg(feature = "pci-hotplug")]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[must_use]
/// Result for hotplug and removal of PCI device.
pub enum PciControlResult {
    AddOk { bus: u8 },
    ErrString(String),
    RemoveOk,
}

#[cfg(feature = "pci-hotplug")]
impl Display for PciControlResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::PciControlResult::*;

        match self {
            AddOk { bus } => write!(f, "add_ok {}", bus),
            ErrString(e) => write!(f, "error: {}", e),
            RemoveOk => write!(f, "remove_ok"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum UsbControlResult {
    Ok { port: u8 },
    NoAvailablePort,
    NoSuchDevice,
    NoSuchPort,
    FailedToOpenDevice,
    Devices([UsbControlAttachedDevice; USB_CONTROL_MAX_PORTS]),
    FailedToInitHostDevice,
}

impl Display for UsbControlResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::UsbControlResult::*;

        match self {
            UsbControlResult::Ok { port } => write!(f, "ok {}", port),
            NoAvailablePort => write!(f, "no_available_port"),
            NoSuchDevice => write!(f, "no_such_device"),
            NoSuchPort => write!(f, "no_such_port"),
            FailedToOpenDevice => write!(f, "failed_to_open_device"),
            Devices(devices) => {
                write!(f, "devices")?;
                for d in devices.iter().filter(|d| d.valid()) {
                    write!(f, " {} {:04x} {:04x}", d.port, d.vendor_id, d.product_id)?;
                }
                std::result::Result::Ok(())
            }
            FailedToInitHostDevice => write!(f, "failed_to_init_host_device"),
        }
    }
}

/// Commands for snapshot feature
#[derive(Serialize, Deserialize, Debug)]
pub enum SnapshotCommand {
    Take {
        snapshot_path: PathBuf,
        compress_memory: bool,
        encrypt: bool,
    },
}

/// Commands for actions on devices and the devices control thread.
#[derive(Serialize, Deserialize, Debug)]
pub enum DeviceControlCommand {
    SleepDevices,
    WakeDevices,
    SnapshotDevices { snapshot_writer: SnapshotWriter },
    RestoreDevices { snapshot_reader: SnapshotReader },
    GetDevicesState,
    Exit,
}

/// Commands to control the IRQ handler thread.
#[derive(Serialize, Deserialize)]
pub enum IrqHandlerRequest {
    /// No response is sent for this command.
    AddIrqControlTubes(Vec<Tube>),
    /// Refreshes the set of event tokens (Events) from the Irqchip that the IRQ
    /// handler waits on to forward IRQs to their final destination (e.g. via
    /// Irqchip::service_irq_event).
    ///
    /// If the set of tokens exposed by the Irqchip changes while the VM is
    /// running (such as for snapshot restore), this command must be sent
    /// otherwise the VM will not receive IRQs as expected.
    RefreshIrqEventTokens,
    WakeAndNotifyIteration,
    /// No response is sent for this command.
    Exit,
}

const EXPECTED_MAX_IRQ_FLUSH_ITERATIONS: usize = 100;

/// Response for [IrqHandlerRequest].
#[derive(Serialize, Deserialize, Debug)]
pub enum IrqHandlerResponse {
    /// Sent when the IRQ event tokens have been refreshed.
    IrqEventTokenRefreshComplete,
    /// Specifies the number of tokens serviced in the requested iteration
    /// (less the token for the `WakeAndNotifyIteration` request).
    HandlerIterationComplete(usize),
}

/// Source of a `VmMemoryRequest::RegisterMemory` mapping.
#[derive(Serialize, Deserialize)]
pub enum VmMemorySource {
    /// Register shared memory represented by the given descriptor.
    /// On Windows, descriptor MUST be a mapping handle.
    SharedMemory(SharedMemory),
    /// Register a file mapping from the given descriptor.
    Descriptor {
        /// File descriptor to map.
        descriptor: SafeDescriptor,
        /// Offset within the file in bytes.
        offset: u64,
        /// Size of the mapping in bytes.
        size: u64,
    },
    /// Register memory mapped by Vulkano.
    Vulkan {
        descriptor: SafeDescriptor,
        handle_type: u32,
        memory_idx: u32,
        device_uuid: [u8; 16],
        driver_uuid: [u8; 16],
        size: u64,
    },
    /// Register the current rutabaga external mapping.
    ExternalMapping { ptr: u64, size: u64 },
}

// The following are wrappers to avoid base dependencies in the rutabaga crate
fn to_rutabaga_desciptor(s: SafeDescriptor) -> RutabagaDescriptor {
    // SAFETY:
    // Safe because we own the SafeDescriptor at this point.
    unsafe { RutabagaDescriptor::from_raw_descriptor(s.into_raw_descriptor()) }
}

struct RutabagaMemoryRegion {
    region: Box<dyn RutabagaMappedRegion>,
}

impl RutabagaMemoryRegion {
    pub fn new(region: Box<dyn RutabagaMappedRegion>) -> RutabagaMemoryRegion {
        RutabagaMemoryRegion { region }
    }
}

// SAFETY:
//
// Self guarantees `ptr`..`ptr+size` is an mmaped region owned by this object that
// can't be unmapped during the `MappedRegion`'s lifetime.
unsafe impl MappedRegion for RutabagaMemoryRegion {
    fn as_ptr(&self) -> *mut u8 {
        self.region.as_ptr()
    }

    fn size(&self) -> usize {
        self.region.size()
    }
}

impl Display for VmMemorySource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::VmMemorySource::*;

        match self {
            SharedMemory(..) => write!(f, "VmMemorySource::SharedMemory"),
            Descriptor { .. } => write!(f, "VmMemorySource::Descriptor"),
            Vulkan { .. } => write!(f, "VmMemorySource::Vulkan"),
            ExternalMapping { .. } => write!(f, "VmMemorySource::ExternalMapping"),
        }
    }
}

impl VmMemorySource {
    /// Map the resource and return its mapping and size in bytes.
    fn map(
        self,
        gralloc: &mut RutabagaGralloc,
        prot: Protection,
    ) -> anyhow::Result<(Box<dyn MappedRegion>, u64, Option<SafeDescriptor>)> {
        let (mem_region, size, descriptor) = match self {
            VmMemorySource::Descriptor {
                descriptor,
                offset,
                size,
            } => (
                map_descriptor(&descriptor, offset, size, prot)?,
                size,
                Some(descriptor),
            ),

            VmMemorySource::SharedMemory(shm) => {
                (map_descriptor(&shm, 0, shm.size(), prot)?, shm.size(), None)
            }
            VmMemorySource::Vulkan {
                descriptor,
                handle_type,
                memory_idx,
                device_uuid,
                driver_uuid,
                size,
            } => {
                let device_id = DeviceId {
                    device_uuid,
                    driver_uuid,
                };
                let mapped_region = gralloc
                    .import_and_map(
                        RutabagaHandle {
                            os_handle: to_rutabaga_desciptor(descriptor),
                            handle_type,
                        },
                        VulkanInfo {
                            memory_idx,
                            device_id,
                        },
                        size,
                    )
                    .with_context(|| {
                        format!(
                            "gralloc failed to import and map, handle type: {}, memory index {}, \
                             size: {}",
                            handle_type, memory_idx, size
                        )
                    })?;
                let mapped_region: Box<dyn MappedRegion> =
                    Box::new(RutabagaMemoryRegion::new(mapped_region));
                (mapped_region, size, None)
            }
            VmMemorySource::ExternalMapping { ptr, size } => {
                let mapped_region: Box<dyn MappedRegion> = Box::new(ExternalMapping {
                    ptr,
                    size: size as usize,
                });
                (mapped_region, size, None)
            }
        };
        Ok((mem_region, size, descriptor))
    }
}

/// Destination of a `VmMemoryRequest::RegisterMemory` mapping in guest address space.
#[derive(Serialize, Deserialize)]
pub enum VmMemoryDestination {
    /// Map at an offset within an existing PCI BAR allocation.
    ExistingAllocation { allocation: Alloc, offset: u64 },
    /// Map at the specified guest physical address.
    GuestPhysicalAddress(u64),
}

impl VmMemoryDestination {
    /// Allocate and return the guest address of a memory mapping destination.
    pub fn allocate(self, allocator: &mut SystemAllocator, size: u64) -> Result<GuestAddress> {
        let addr = match self {
            VmMemoryDestination::ExistingAllocation { allocation, offset } => allocator
                .mmio_allocator_any()
                .address_from_pci_offset(allocation, offset, size)
                .map_err(|_e| SysError::new(EINVAL))?,
            VmMemoryDestination::GuestPhysicalAddress(gpa) => gpa,
        };
        Ok(GuestAddress(addr))
    }
}

/// Request to register or unregister an ioevent.
#[derive(Serialize, Deserialize)]
pub struct IoEventUpdateRequest {
    pub event: Event,
    pub addr: u64,
    pub datamatch: Datamatch,
    pub register: bool,
}

/// Request to mmap a file to a shared memory.
/// This request is supposed to follow a `VmMemoryRequest::MmapAndRegisterMemory` request that
/// contains `SharedMemory` that `file` is mmaped to.
#[cfg(any(target_os = "android", target_os = "linux"))]
#[derive(Serialize, Deserialize)]
pub struct VmMemoryFileMapping {
    #[serde(with = "with_as_descriptor")]
    pub file: File,
    pub length: usize,
    pub mem_offset: usize,
    pub file_offset: u64,
}

#[derive(Serialize, Deserialize)]
pub enum VmMemoryRequest {
    /// Prepare a shared memory region to make later operations more efficient. This
    /// may be a no-op depending on underlying platform support.
    PrepareSharedMemoryRegion { alloc: Alloc, cache: MemCacheType },
    /// Register a memory to be mapped to the guest.
    RegisterMemory {
        /// Source of the memory to register (mapped file descriptor, shared memory region, etc.)
        source: VmMemorySource,
        /// Where to map the memory in the guest.
        dest: VmMemoryDestination,
        /// Whether to map the memory read only (true) or read-write (false).
        prot: Protection,
        /// Cache attribute for guest memory setting
        cache: MemCacheType,
    },
    #[cfg(any(target_os = "android", target_os = "linux"))]
    /// Call mmap to `shm` and register the memory region as a read-only guest memory.
    /// This request is followed by an array of `VmMemoryFileMapping` with length
    /// `num_file_mappings`
    MmapAndRegisterMemory {
        /// Source of the memory to register (mapped file descriptor, shared memory region, etc.)
        shm: SharedMemory,
        /// Where to map the memory in the guest.
        dest: VmMemoryDestination,
        /// Length of the array of `VmMemoryFileMapping` that follows.
        num_file_mappings: usize,
    },
    /// Call hypervisor to free the given memory range.
    DynamicallyFreeMemoryRanges { ranges: Vec<(GuestAddress, u64)> },
    /// Call hypervisor to reclaim a priorly freed memory range.
    DynamicallyReclaimMemoryRanges { ranges: Vec<(GuestAddress, u64)> },
    /// Balloon allocation/deallocation target reached.
    BalloonTargetReached { size: u64 },
    /// Unregister the given memory slot that was previously registered with `RegisterMemory`.
    UnregisterMemory(VmMemoryRegionId),
    /// Register an eventfd with raw guest memory address.
    IoEventRaw(IoEventUpdateRequest),
}

/// Struct for managing `VmMemoryRequest`s IOMMU related state.
pub struct VmMemoryRequestIommuClient {
    tube: Arc<Mutex<Tube>>,
    registered_memory: BTreeSet<VmMemoryRegionId>,
}

impl VmMemoryRequestIommuClient {
    /// Constructs `VmMemoryRequestIommuClient` from a tube for communication with the viommu.
    pub fn new(tube: Arc<Mutex<Tube>>) -> Self {
        Self {
            tube,
            registered_memory: BTreeSet::new(),
        }
    }
}

enum RegisteredMemory {
    FixedMapping {
        slot: MemSlot,
        offset: usize,
        size: usize,
    },
    DynamicMapping {
        slot: MemSlot,
    },
}

pub struct VmMappedMemoryRegion {
    guest_address: GuestAddress,
    slot: MemSlot,
}

#[derive(Default)]
pub struct VmMemoryRegionState {
    mapped_regions: HashMap<Alloc, VmMappedMemoryRegion>,
    registered_memory: BTreeMap<VmMemoryRegionId, RegisteredMemory>,
}

fn try_map_to_prepared_region(
    vm: &mut impl Vm,
    region_state: &mut VmMemoryRegionState,
    source: &VmMemorySource,
    dest: &VmMemoryDestination,
    prot: &Protection,
) -> Option<VmMemoryResponse> {
    let VmMemoryDestination::ExistingAllocation {
        allocation,
        offset: dest_offset,
    } = dest
    else {
        return None;
    };

    let VmMappedMemoryRegion {
        guest_address,
        slot,
    } = region_state.mapped_regions.get(allocation)?;

    let (descriptor, file_offset, size) = match source {
        VmMemorySource::Descriptor {
            descriptor,
            offset,
            size,
        } => (
            Descriptor(descriptor.as_raw_descriptor()),
            *offset,
            *size as usize,
        ),
        VmMemorySource::SharedMemory(shm) => {
            let size = shm.size() as usize;
            (Descriptor(shm.as_raw_descriptor()), 0, size)
        }
        _ => {
            let error = anyhow::anyhow!(
                "source {} is not compatible with fixed mapping into prepared memory region",
                source
            );
            return Some(VmMemoryResponse::Err(error.into()));
        }
    };
    if let Err(err) = vm
        .add_fd_mapping(
            *slot,
            *dest_offset as usize,
            size,
            &descriptor,
            file_offset,
            *prot,
        )
        .context("failed to add fd mapping when trying to map to prepared region")
    {
        return Some(VmMemoryResponse::Err(err.into()));
    }

    let guest_address = GuestAddress(guest_address.0 + dest_offset);
    let region_id = VmMemoryRegionId(guest_address);
    region_state.registered_memory.insert(
        region_id,
        RegisteredMemory::FixedMapping {
            slot: *slot,
            offset: *dest_offset as usize,
            size,
        },
    );

    Some(VmMemoryResponse::RegisterMemory {
        region_id,
        slot: *slot,
    })
}

impl VmMemoryRequest {
    /// Executes this request on the given Vm.
    ///
    /// # Arguments
    /// * `vm` - The `Vm` to perform the request on.
    /// * `allocator` - Used to allocate addresses.
    ///
    /// This does not return a result, instead encapsulating the success or failure in a
    /// `VmMemoryResponse` with the intended purpose of sending the response back over the socket
    /// that received this `VmMemoryResponse`.
    pub fn execute(
        self,
        #[cfg(any(target_os = "android", target_os = "linux"))] tube: &Tube,
        vm: &mut impl Vm,
        sys_allocator: &mut SystemAllocator,
        gralloc: &mut RutabagaGralloc,
        iommu_client: Option<&mut VmMemoryRequestIommuClient>,
        region_state: &mut VmMemoryRegionState,
    ) -> VmMemoryResponse {
        use self::VmMemoryRequest::*;
        match self {
            PrepareSharedMemoryRegion { alloc, cache } => {
                // Currently the iommu_client is only used by virtio-gpu when used alongside GPU
                // pci-passthrough.
                //
                // TODO(b/323368701): Make compatible with iommu_client by ensuring that
                // VirtioIOMMUVfioCommand::VfioDmabufMap is submitted for both dynamic mappings and
                // fixed mappings (i.e. whether or not try_map_to_prepared_region succeeds in
                // RegisterMemory case below).
                assert!(iommu_client.is_none());

                if !sys::should_prepare_memory_region() {
                    return VmMemoryResponse::Ok;
                }

                match sys::prepare_shared_memory_region(vm, sys_allocator, alloc, cache)
                    .context("failed to prepare shared memory region")
                {
                    Ok(region) => {
                        region_state.mapped_regions.insert(alloc, region);
                        VmMemoryResponse::Ok
                    }
                    Err(e) => VmMemoryResponse::Err(e.into()),
                }
            }
            RegisterMemory {
                source,
                dest,
                prot,
                cache,
            } => {
                if let Some(resp) =
                    try_map_to_prepared_region(vm, region_state, &source, &dest, &prot)
                {
                    return resp;
                }

                // Correct on Windows because callers of this IPC guarantee descriptor is a mapping
                // handle.
                let (mapped_region, size, descriptor) =
                    match source.map(gralloc, prot).context("gralloc mapping") {
                        Ok((region, size, descriptor)) => (region, size, descriptor),
                        Err(e) => return VmMemoryResponse::Err(e.into()),
                    };

                let guest_addr = match dest
                    .allocate(sys_allocator, size)
                    .context("VM memory destination allocation fails")
                {
                    Ok(addr) => addr,
                    Err(e) => return VmMemoryResponse::Err(e.into()),
                };

                let slot = match vm
                    .add_memory_region(
                        guest_addr,
                        mapped_region,
                        prot == Protection::read(),
                        false,
                        cache,
                    )
                    .context("failed to add memory region when registering memory")
                {
                    Ok(slot) => slot,
                    Err(e) => return VmMemoryResponse::Err(e.into()),
                };

                let region_id = VmMemoryRegionId(guest_addr);
                if let (Some(descriptor), Some(iommu_client)) = (descriptor, iommu_client) {
                    let request =
                        VirtioIOMMURequest::VfioCommand(VirtioIOMMUVfioCommand::VfioDmabufMap {
                            region_id,
                            gpa: guest_addr.0,
                            size,
                            dma_buf: descriptor,
                        });

                    match virtio_iommu_request(&iommu_client.tube.lock(), &request) {
                        Ok(VirtioIOMMUResponse::VfioResponse(VirtioIOMMUVfioResult::Ok)) => (),
                        resp => {
                            let error = anyhow::anyhow!(
                                "Unexpected virtio-iommu message response when registering memory: \
                                 {:?}", resp);
                            if let Err(e) = vm.remove_memory_region(slot) {
                                // There is nothing we can do here, so we just log a warning
                                // message.
                                warn!("failed to remove memory region: {:?}", e);
                            }
                            return VmMemoryResponse::Err(error.into());
                        }
                    };

                    iommu_client.registered_memory.insert(region_id);
                }

                region_state
                    .registered_memory
                    .insert(region_id, RegisteredMemory::DynamicMapping { slot });
                VmMemoryResponse::RegisterMemory { region_id, slot }
            }
            #[cfg(any(target_os = "android", target_os = "linux"))]
            MmapAndRegisterMemory {
                shm,
                dest,
                num_file_mappings,
            } => {
                // Define a callback to be executed with extended limit of file counts.
                // It recieves `num_file_mappings` FDs and call `add_fd_mapping` for each.
                let callback = || {
                    let mem = match MemoryMappingBuilder::new(shm.size() as usize)
                        .from_shared_memory(&shm)
                        .build()
                        .context("failed to build MemoryMapping from shared memory")
                    {
                        Ok(mem) => mem,
                        Err(e) => return Err(VmMemoryResponse::Err(e.into())),
                    };
                    let mut mmap_arena = MemoryMappingArena::from(mem);

                    // If `num_file_mappings` exceeds `SCM_MAX_FD`, `file_mappings` are sent in
                    // chunks of length `SCM_MAX_FD`.
                    let mut file_mappings = Vec::with_capacity(num_file_mappings);
                    let mut read = 0;
                    while read < num_file_mappings {
                        let len = std::cmp::min(num_file_mappings - read, base::unix::SCM_MAX_FD);
                        let mps: Vec<VmMemoryFileMapping> = match tube
                            .recv_with_max_fds(len)
                            .with_context(|| format!("get {num_file_mappings} FDs to be mapped"))
                        {
                            Ok(m) => m,
                            Err(e) => return Err(VmMemoryResponse::Err(e.into())),
                        };
                        file_mappings.extend(mps.into_iter());
                        read += len;
                    }

                    for VmMemoryFileMapping {
                        mem_offset,
                        length,
                        file,
                        file_offset,
                    } in file_mappings
                    {
                        if let Err(e) = mmap_arena
                            .add_fd_mapping(
                                mem_offset,
                                length,
                                &file,
                                file_offset,
                                Protection::read(),
                            )
                            .context(
                                "failed to add fd mapping when handling mmap and register memory",
                            )
                        {
                            return Err(VmMemoryResponse::Err(e.into()));
                        }
                    }
                    Ok(mmap_arena)
                };
                let mmap_arena = match call_with_extended_max_files(callback)
                    .context("failed to set max count of file descriptors")
                {
                    Ok(Ok(m)) => m,
                    Ok(Err(e)) => {
                        return e;
                    }
                    Err(e) => {
                        error!("{e:?}");
                        return VmMemoryResponse::Err(e.into());
                    }
                };

                let size = shm.size();
                let guest_addr = match dest.allocate(sys_allocator, size).context(
                    "VM memory destination allocation fails when handling mmap and register memory",
                ) {
                    Ok(addr) => addr,
                    Err(e) => return VmMemoryResponse::Err(e.into()),
                };

                let slot = match vm
                    .add_memory_region(
                        guest_addr,
                        Box::new(mmap_arena),
                        true,
                        false,
                        MemCacheType::CacheCoherent,
                    )
                    .context("failed to add memory region when handling mmap and register memory")
                {
                    Ok(slot) => slot,
                    Err(e) => return VmMemoryResponse::Err(e.into()),
                };

                let region_id = VmMemoryRegionId(guest_addr);

                region_state
                    .registered_memory
                    .insert(region_id, RegisteredMemory::DynamicMapping { slot });

                VmMemoryResponse::RegisterMemory { region_id, slot }
            }
            UnregisterMemory(id) => match region_state.registered_memory.remove(&id) {
                Some(RegisteredMemory::DynamicMapping { slot }) => match vm
                    .remove_memory_region(slot)
                    .context(
                        "failed to remove memory region when unregistering dynamic mapping memory",
                    ) {
                    Ok(_) => {
                        if let Some(iommu_client) = iommu_client {
                            if iommu_client.registered_memory.remove(&id) {
                                let request = VirtioIOMMURequest::VfioCommand(
                                    VirtioIOMMUVfioCommand::VfioDmabufUnmap(id),
                                );

                                match virtio_iommu_request(&iommu_client.tube.lock(), &request) {
                                    Ok(VirtioIOMMUResponse::VfioResponse(
                                        VirtioIOMMUVfioResult::Ok,
                                    )) => VmMemoryResponse::Ok,
                                    resp => {
                                        let error = anyhow::anyhow!(
                                            "Unexpected virtio-iommu message response when \
                                             unregistering memory: {:?}",
                                            resp
                                        );
                                        VmMemoryResponse::Err(error.into())
                                    }
                                }
                            } else {
                                VmMemoryResponse::Ok
                            }
                        } else {
                            VmMemoryResponse::Ok
                        }
                    }
                    Err(e) => VmMemoryResponse::Err(e.into()),
                },
                Some(RegisteredMemory::FixedMapping { slot, offset, size }) => {
                    match vm.remove_mapping(slot, offset, size).context(
                        "failed to remove memory mapping when unregistering fixed mapping memory",
                    ) {
                        Ok(()) => VmMemoryResponse::Ok,
                        Err(e) => VmMemoryResponse::Err(e.into()),
                    }
                }
                None => {
                    let error =
                        anyhow::anyhow!("can't find the memory region when unregistering memory");
                    VmMemoryResponse::Err(error.into())
                }
            },
            DynamicallyFreeMemoryRanges { ranges } => {
                let mut r = VmMemoryResponse::Ok;
                for (guest_address, size) in ranges {
                    match vm
                        .handle_balloon_event(BalloonEvent::Inflate(MemRegion {
                            guest_address,
                            size,
                        }))
                        .context(
                            "failed to handle the inflate balloon event when freeing memory ranges \
                             dynamically",
                        ) {
                        Ok(_) => {}
                        Err(e) => {
                            error!("{:?}", e);
                            r = VmMemoryResponse::Err(e.into());
                            break;
                        }
                    }
                }
                r
            }
            DynamicallyReclaimMemoryRanges { ranges } => {
                let mut r = VmMemoryResponse::Ok;
                for (guest_address, size) in ranges {
                    match vm
                        .handle_balloon_event(BalloonEvent::Deflate(MemRegion {
                            guest_address,
                            size,
                        }))
                        .context(
                            "failed to handle the deflate balloon event when reclaiming memory \
                             ranges dynamically",
                        ) {
                        Ok(_) => {}
                        Err(e) => {
                            error!("{:?}", e);
                            r = VmMemoryResponse::Err(e.into());
                            break;
                        }
                    }
                }
                r
            }
            BalloonTargetReached { size } => {
                match vm
                    .handle_balloon_event(BalloonEvent::BalloonTargetReached(size))
                    .context("failed to handle the target reached balloon event")
                {
                    Ok(_) => VmMemoryResponse::Ok,
                    Err(e) => VmMemoryResponse::Err(e.into()),
                }
            }
            IoEventRaw(request) => {
                let res = if request.register {
                    vm.register_ioevent(
                        &request.event,
                        IoEventAddress::Mmio(request.addr),
                        request.datamatch,
                    )
                    .context("failed to register IO event")
                } else {
                    vm.unregister_ioevent(
                        &request.event,
                        IoEventAddress::Mmio(request.addr),
                        request.datamatch,
                    )
                    .context("failed to unregister IO event")
                };
                match res {
                    Ok(_) => VmMemoryResponse::Ok,
                    Err(e) => VmMemoryResponse::Err(e.into()),
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialOrd, PartialEq, Eq, Ord, Clone, Copy)]
/// Identifer for registered memory regions. Globally unique.
// The current implementation uses guest physical address as the unique identifier.
pub struct VmMemoryRegionId(GuestAddress);

#[derive(Serialize, Deserialize, Debug)]
pub enum VmMemoryResponse {
    /// The request to register memory into guest address space was successful.
    RegisterMemory {
        region_id: VmMemoryRegionId,
        slot: u32,
    },
    Ok,
    Err(VmMemoryResponseError),
}

impl<T> From<Result<T>> for VmMemoryResponse {
    fn from(r: Result<T>) -> Self {
        match r {
            Ok(_) => VmMemoryResponse::Ok,
            Err(e) => VmMemoryResponse::Err(anyhow::Error::new(e).into()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Vm memory response error: {0}")]
pub struct VmMemoryResponseError(#[from] pub anyhow::Error);

impl TryFrom<FlatVmMemoryResponseError> for VmMemoryResponseError {
    type Error = anyhow::Error;
    fn try_from(value: FlatVmMemoryResponseError) -> StdResult<Self, Self::Error> {
        let inner = value
            .0
            .into_iter()
            .fold(
                None,
                |error: Option<anyhow::Error>, current_context| match error {
                    Some(error) => Some(error.context(current_context)),
                    None => Some(anyhow::Error::msg(current_context)),
                },
            )
            .context("should carry at least one error")?;
        Ok(Self(inner))
    }
}

impl Serialize for VmMemoryResponseError {
    fn serialize<S>(&self, serializer: S) -> StdResult<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let flat: FlatVmMemoryResponseError = self.into();
        flat.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for VmMemoryResponseError {
    fn deserialize<D>(deserializer: D) -> StdResult<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let flat = FlatVmMemoryResponseError::deserialize(deserializer)?;
        flat.try_into()
            .map_err(|e: anyhow::Error| D::Error::custom(e.to_string()))
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct FlatVmMemoryResponseError(Vec<String>);

impl From<&VmMemoryResponseError> for FlatVmMemoryResponseError {
    fn from(value: &VmMemoryResponseError) -> Self {
        let contexts = value
            .0
            .chain()
            .map(ToString::to_string)
            .rev()
            .collect::<Vec<_>>();
        Self(contexts)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum VmIrqRequest {
    /// Allocate one gsi, and associate gsi to irqfd with register_irqfd()
    AllocateOneMsi {
        irqfd: Event,
        device_id: u32,
        queue_id: usize,
        device_name: String,
    },
    /// Allocate a specific gsi to irqfd with register_irqfd(). This must only
    /// be used when it is known that the gsi is free. Only the snapshot
    /// subsystem can make this guarantee, and use of this request by any other
    /// caller is strongly discouraged.
    AllocateOneMsiAtGsi {
        irqfd: Event,
        gsi: u32,
        device_id: u32,
        queue_id: usize,
        device_name: String,
    },
    /// Add one msi route entry into the IRQ chip.
    AddMsiRoute {
        gsi: u32,
        msi_address: u64,
        msi_data: u32,
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        pci_address: resources::PciAddress,
    },
    // unregister_irqfs() and release gsi
    ReleaseOneIrq {
        gsi: u32,
        irqfd: Event,
    },
}

/// Data to set up an IRQ event or IRQ route on the IRQ chip.
/// VmIrqRequest::execute can't take an `IrqChip` argument, because of a dependency cycle between
/// devices and vm_control, so it takes a Fn that processes an `IrqSetup`.
pub enum IrqSetup<'a> {
    Event(u32, &'a Event, u32, usize, String),
    Route(IrqRoute),
    UnRegister(u32, &'a Event),
}

impl VmIrqRequest {
    /// Executes this request on the given Vm.
    ///
    /// # Arguments
    /// * `set_up_irq` - A function that applies an `IrqSetup` to an IRQ chip.
    ///
    /// This does not return a result, instead encapsulating the success or failure in a
    /// `VmIrqResponse` with the intended purpose of sending the response back over the socket
    /// that received this `VmIrqResponse`.
    pub fn execute<F>(&self, set_up_irq: F, sys_allocator: &mut SystemAllocator) -> VmIrqResponse
    where
        F: FnOnce(IrqSetup) -> Result<()>,
    {
        use self::VmIrqRequest::*;
        match *self {
            AllocateOneMsi {
                ref irqfd,
                device_id,
                queue_id,
                ref device_name,
            } => {
                if let Some(irq_num) = sys_allocator.allocate_irq() {
                    match set_up_irq(IrqSetup::Event(
                        irq_num,
                        irqfd,
                        device_id,
                        queue_id,
                        device_name.clone(),
                    )) {
                        Ok(_) => VmIrqResponse::AllocateOneMsi { gsi: irq_num },
                        Err(e) => VmIrqResponse::Err(e),
                    }
                } else {
                    VmIrqResponse::Err(SysError::new(EINVAL))
                }
            }
            AllocateOneMsiAtGsi {
                ref irqfd,
                gsi,
                device_id,
                queue_id,
                ref device_name,
            } => {
                match set_up_irq(IrqSetup::Event(
                    gsi,
                    irqfd,
                    device_id,
                    queue_id,
                    device_name.clone(),
                )) {
                    Ok(_) => VmIrqResponse::Ok,
                    Err(e) => VmIrqResponse::Err(e),
                }
            }
            AddMsiRoute {
                gsi,
                msi_address,
                msi_data,
                #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
                pci_address,
            } => {
                let route = IrqRoute {
                    gsi,
                    source: IrqSource::Msi {
                        address: msi_address,
                        data: msi_data,
                        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
                        pci_address,
                    },
                };
                match set_up_irq(IrqSetup::Route(route)) {
                    Ok(_) => VmIrqResponse::Ok,
                    Err(e) => VmIrqResponse::Err(e),
                }
            }
            ReleaseOneIrq { gsi, ref irqfd } => {
                let _ = set_up_irq(IrqSetup::UnRegister(gsi, irqfd));
                sys_allocator.release_irq(gsi);
                VmIrqResponse::Ok
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum VmIrqResponse {
    AllocateOneMsi { gsi: u32 },
    Ok,
    Err(SysError),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum DevicesState {
    Sleep,
    Wake,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum BatControlResult {
    Ok,
    NoBatDevice,
    NoSuchHealth,
    NoSuchProperty,
    NoSuchStatus,
    NoSuchBatType,
    StringParseIntErr,
    StringParseBoolErr,
}

impl Display for BatControlResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::BatControlResult::*;

        match self {
            Ok => write!(f, "Setting battery property successfully"),
            NoBatDevice => write!(f, "No battery device created"),
            NoSuchHealth => write!(f, "Invalid Battery health setting. Only support: unknown/good/overheat/dead/overvoltage/unexpectedfailure/cold/watchdogtimerexpire/safetytimerexpire/overcurrent"),
            NoSuchProperty => write!(f, "Battery doesn't have such property. Only support: status/health/present/capacity/aconline"),
            NoSuchStatus => write!(f, "Invalid Battery status setting. Only support: unknown/charging/discharging/notcharging/full"),
            NoSuchBatType => write!(f, "Invalid Battery type setting. Only support: goldfish"),
            StringParseIntErr => write!(f, "Battery property target ParseInt error"),
            StringParseBoolErr => write!(f, "Battery property target ParseBool error"),
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BatteryType {
    #[default]
    Goldfish,
}

impl FromStr for BatteryType {
    type Err = BatControlResult;

    fn from_str(s: &str) -> StdResult<Self, Self::Err> {
        match s {
            "goldfish" => Ok(BatteryType::Goldfish),
            _ => Err(BatControlResult::NoSuchBatType),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum BatProperty {
    Status,
    Health,
    Present,
    Capacity,
    ACOnline,
    SetFakeBatConfig,
    CancelFakeBatConfig,
}

impl FromStr for BatProperty {
    type Err = BatControlResult;

    fn from_str(s: &str) -> StdResult<Self, Self::Err> {
        match s {
            "status" => Ok(BatProperty::Status),
            "health" => Ok(BatProperty::Health),
            "present" => Ok(BatProperty::Present),
            "capacity" => Ok(BatProperty::Capacity),
            "aconline" => Ok(BatProperty::ACOnline),
            "set_fake_bat_config" => Ok(BatProperty::SetFakeBatConfig),
            "cancel_fake_bat_config" => Ok(BatProperty::CancelFakeBatConfig),
            _ => Err(BatControlResult::NoSuchProperty),
        }
    }
}

impl Display for BatProperty {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BatProperty::Status => write!(f, "status"),
            BatProperty::Health => write!(f, "health"),
            BatProperty::Present => write!(f, "present"),
            BatProperty::Capacity => write!(f, "capacity"),
            BatProperty::ACOnline => write!(f, "aconline"),
            BatProperty::SetFakeBatConfig => write!(f, "set_fake_bat_config"),
            BatProperty::CancelFakeBatConfig => write!(f, "cancel_fake_bat_config"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum BatStatus {
    Unknown,
    Charging,
    DisCharging,
    NotCharging,
    Full,
}

impl BatStatus {
    pub fn new(status: String) -> std::result::Result<Self, BatControlResult> {
        match status.as_str() {
            "unknown" => Ok(BatStatus::Unknown),
            "charging" => Ok(BatStatus::Charging),
            "discharging" => Ok(BatStatus::DisCharging),
            "notcharging" => Ok(BatStatus::NotCharging),
            "full" => Ok(BatStatus::Full),
            _ => Err(BatControlResult::NoSuchStatus),
        }
    }
}

impl FromStr for BatStatus {
    type Err = BatControlResult;

    fn from_str(s: &str) -> StdResult<Self, Self::Err> {
        match s {
            "unknown" => Ok(BatStatus::Unknown),
            "charging" => Ok(BatStatus::Charging),
            "discharging" => Ok(BatStatus::DisCharging),
            "notcharging" => Ok(BatStatus::NotCharging),
            "full" => Ok(BatStatus::Full),
            _ => Err(BatControlResult::NoSuchStatus),
        }
    }
}

impl From<BatStatus> for u32 {
    fn from(status: BatStatus) -> Self {
        status as u32
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum BatHealth {
    Unknown,
    Good,
    Overheat,
    Dead,
    OverVoltage,
    UnexpectedFailure,
    Cold,
    WatchdogTimerExpire,
    SafetyTimerExpire,
    OverCurrent,
}

impl FromStr for BatHealth {
    type Err = BatControlResult;

    fn from_str(s: &str) -> StdResult<Self, Self::Err> {
        match s {
            "unknown" => Ok(BatHealth::Unknown),
            "good" => Ok(BatHealth::Good),
            "overheat" => Ok(BatHealth::Overheat),
            "dead" => Ok(BatHealth::Dead),
            "overvoltage" => Ok(BatHealth::OverVoltage),
            "unexpectedfailure" => Ok(BatHealth::UnexpectedFailure),
            "cold" => Ok(BatHealth::Cold),
            "watchdogtimerexpire" => Ok(BatHealth::WatchdogTimerExpire),
            "safetytimerexpire" => Ok(BatHealth::SafetyTimerExpire),
            "overcurrent" => Ok(BatHealth::OverCurrent),
            _ => Err(BatControlResult::NoSuchHealth),
        }
    }
}

impl From<BatHealth> for u32 {
    fn from(status: BatHealth) -> Self {
        status as u32
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum BatControlCommand {
    SetStatus(BatStatus),
    SetHealth(BatHealth),
    SetPresent(u32),
    SetCapacity(u32),
    SetACOnline(u32),
    SetFakeBatConfig(u32),
    CancelFakeConfig,
}

impl BatControlCommand {
    pub fn new(property: String, target: String) -> std::result::Result<Self, BatControlResult> {
        let cmd = property.parse::<BatProperty>()?;
        match cmd {
            BatProperty::Status => Ok(BatControlCommand::SetStatus(target.parse::<BatStatus>()?)),
            BatProperty::Health => Ok(BatControlCommand::SetHealth(target.parse::<BatHealth>()?)),
            BatProperty::Present => Ok(BatControlCommand::SetPresent(
                target
                    .parse::<u32>()
                    .map_err(|_| BatControlResult::StringParseIntErr)?,
            )),
            BatProperty::Capacity => Ok(BatControlCommand::SetCapacity(
                target
                    .parse::<u32>()
                    .map_err(|_| BatControlResult::StringParseIntErr)?,
            )),
            BatProperty::ACOnline => Ok(BatControlCommand::SetACOnline(
                target
                    .parse::<u32>()
                    .map_err(|_| BatControlResult::StringParseIntErr)?,
            )),
            BatProperty::SetFakeBatConfig => Ok(BatControlCommand::SetFakeBatConfig(
                target
                    .parse::<u32>()
                    .map_err(|_| BatControlResult::StringParseIntErr)?,
            )),
            BatProperty::CancelFakeBatConfig => Ok(BatControlCommand::CancelFakeConfig),
        }
    }
}

/// Used for VM to control battery properties.
pub struct BatControl {
    pub type_: BatteryType,
    pub control_tube: Tube,
}

/// Used for VM to control for virtio-snd
#[derive(Serialize, Deserialize, Debug)]
pub enum SndControlCommand {
    MuteAll(bool),
}

// Used to mark hotplug pci device's device type
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum HotPlugDeviceType {
    UpstreamPort,
    DownstreamPort,
    EndPoint,
}

// Used for VM to hotplug pci devices
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HotPlugDeviceInfo {
    pub device_type: HotPlugDeviceType,
    pub path: PathBuf,
    pub hp_interrupt: bool,
}

/// Message for communicating a suspend or resume to the virtio-pvclock device.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PvClockCommand {
    Suspend,
    Resume,
}

/// Message used by virtio-pvclock to communicate command results.
#[derive(Serialize, Deserialize, Debug)]
pub enum PvClockCommandResponse {
    Ok,
    Resumed { total_suspended_ticks: u64 },
    DeviceInactive,
    Err(SysError),
}

/// Commands for vmm-swap feature
#[derive(Serialize, Deserialize, Debug)]
pub enum SwapCommand {
    Enable,
    Trim,
    SwapOut,
    Disable { slow_file_cleanup: bool },
    Status,
}

///
/// A request to the main process to perform some operation on the VM.
///
/// Unless otherwise noted, each request should expect a `VmResponse::Ok` to be received on success.
#[derive(Serialize, Deserialize, Debug)]
pub enum VmRequest {
    /// Break the VM's run loop and exit.
    Exit,
    /// Trigger a power button event in the guest.
    Powerbtn,
    /// Trigger a sleep button event in the guest.
    Sleepbtn,
    /// Trigger a RTC interrupt in the guest. When the irq associated with the RTC is
    /// resampled, it will be re-asserted as long as `clear_evt` is not signaled.
    Rtc { clear_evt: Event },
    /// Suspend the VM's VCPUs until resume.
    SuspendVcpus,
    /// Swap the memory content into files on a disk
    Swap(SwapCommand),
    /// Resume the VM's VCPUs that were previously suspended.
    ResumeVcpus,
    /// Inject a general-purpose event. If `clear_evt` is provided, when the irq associated
    /// with the GPE is resampled, it will be re-asserted as long as `clear_evt` is not
    /// signaled.
    Gpe { gpe: u32, clear_evt: Option<Event> },
    /// Inject a PCI PME
    PciPme(u16),
    /// Make the VM's RT VCPU real-time.
    MakeRT,
    /// Command for balloon driver.
    #[cfg(feature = "balloon")]
    BalloonCommand(BalloonControlCommand),
    /// Send a command to a disk chosen by `disk_index`.
    /// `disk_index` is a 0-based count of `--disk`, `--rwdisk`, and `-r` command-line options.
    DiskCommand {
        disk_index: usize,
        command: DiskControlCommand,
    },
    /// Command to use controller.
    UsbCommand(UsbControlCommand),
    /// Command to modify the gpu.
    #[cfg(feature = "gpu")]
    GpuCommand(GpuControlCommand),
    /// Command to set battery.
    BatCommand(BatteryType, BatControlCommand),
    /// Command to control snd devices
    #[cfg(feature = "audio")]
    SndCommand(SndControlCommand),
    /// Command to add/remove multiple vfio-pci devices
    HotPlugVfioCommand {
        device: HotPlugDeviceInfo,
        add: bool,
    },
    /// Command to add/remove network tap device as virtio-pci device
    #[cfg(feature = "pci-hotplug")]
    HotPlugNetCommand(NetControlCommand),
    /// Command to Snapshot devices
    Snapshot(SnapshotCommand),
    /// Register for event notification
    RegisterListener {
        socket_addr: String,
        event: RegisteredEvent,
    },
    /// Unregister for notifications for event
    UnregisterListener {
        socket_addr: String,
        event: RegisteredEvent,
    },
    /// Unregister for all event notification
    Unregister { socket_addr: String },
    /// Suspend VM VCPUs and Devices until resume.
    SuspendVm,
    /// Resume VM VCPUs and Devices.
    ResumeVm,
    /// Returns Vcpus PID/TID
    VcpuPidTid,
    /// Throttles the requested vCPU for microseconds
    Throttle(usize, u32),
    /// Returns unique descriptor of this VM.
    GetVmDescriptor,
}

/// NOTE: when making any changes to this enum please also update
/// RegisteredEventFfi in crosvm_control/src/lib.rs
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum RegisteredEvent {
    VirtioBalloonWsReport,
    VirtioBalloonResize,
    VirtioBalloonOOMDeflation,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum RegisteredEventWithData {
    VirtioBalloonWsReport {
        ws_buckets: Vec<balloon_control::WSBucket>,
        balloon_actual: u64,
    },
    VirtioBalloonResize,
    VirtioBalloonOOMDeflation,
}

impl RegisteredEventWithData {
    pub fn into_event(&self) -> RegisteredEvent {
        match self {
            Self::VirtioBalloonWsReport { .. } => RegisteredEvent::VirtioBalloonWsReport,
            Self::VirtioBalloonResize => RegisteredEvent::VirtioBalloonResize,
            Self::VirtioBalloonOOMDeflation => RegisteredEvent::VirtioBalloonOOMDeflation,
        }
    }

    #[cfg(feature = "registered_events")]
    pub fn into_proto(&self) -> registered_events::RegisteredEvent {
        match self {
            Self::VirtioBalloonWsReport {
                ws_buckets,
                balloon_actual,
            } => {
                let mut report = registered_events::VirtioBalloonWsReport {
                    balloon_actual: *balloon_actual,
                    ..registered_events::VirtioBalloonWsReport::new()
                };
                for ws in ws_buckets {
                    report.ws_buckets.push(registered_events::VirtioWsBucket {
                        age: ws.age,
                        file_bytes: ws.bytes[0],
                        anon_bytes: ws.bytes[1],
                        ..registered_events::VirtioWsBucket::new()
                    });
                }
                let mut event = registered_events::RegisteredEvent::new();
                event.set_ws_report(report);
                event
            }
            Self::VirtioBalloonResize => {
                let mut event = registered_events::RegisteredEvent::new();
                event.set_resize(registered_events::VirtioBalloonResize::new());
                event
            }
            Self::VirtioBalloonOOMDeflation => {
                let mut event = registered_events::RegisteredEvent::new();
                event.set_oom_deflation(registered_events::VirtioBalloonOOMDeflation::new());
                event
            }
        }
    }

    pub fn from_ws(ws: &balloon_control::BalloonWS, balloon_actual: u64) -> Self {
        RegisteredEventWithData::VirtioBalloonWsReport {
            ws_buckets: ws.ws.clone(),
            balloon_actual,
        }
    }
}

pub fn handle_disk_command(command: &DiskControlCommand, disk_host_tube: &Tube) -> VmResponse {
    // Forward the request to the block device process via its control socket.
    if let Err(e) = disk_host_tube.send(command) {
        error!("disk socket send failed: {}", e);
        return VmResponse::Err(SysError::new(EINVAL));
    }

    // Wait for the disk control command to be processed
    match disk_host_tube.recv() {
        Ok(DiskControlResult::Ok) => VmResponse::Ok,
        Ok(DiskControlResult::Err(e)) => VmResponse::Err(e),
        Err(e) => {
            error!("disk socket recv failed: {}", e);
            VmResponse::Err(SysError::new(EINVAL))
        }
    }
}

/// WARNING: descriptor must be a mapping handle on Windows.
fn map_descriptor(
    descriptor: &dyn AsRawDescriptor,
    offset: u64,
    size: u64,
    prot: Protection,
) -> Result<Box<dyn MappedRegion>> {
    let size: usize = size.try_into().map_err(|_e| SysError::new(ERANGE))?;
    match MemoryMappingBuilder::new(size)
        .from_descriptor(descriptor)
        .offset(offset)
        .protection(prot)
        .build()
    {
        Ok(mmap) => Ok(Box::new(mmap)),
        Err(MmapError::SystemCallFailed(e)) => Err(e),
        _ => Err(SysError::new(EINVAL)),
    }
}

// Get vCPU state. vCPUs are expected to all hold the same state.
// In this function, there may be a time where vCPUs are not holding the same state
// as they transition from one state to the other. This is expected, and the final result
// should be all vCPUs holding the same state.
fn get_vcpu_state(kick_vcpus: impl Fn(VcpuControl), vcpu_num: usize) -> anyhow::Result<VmRunMode> {
    let (send_chan, recv_chan) = mpsc::channel();
    kick_vcpus(VcpuControl::GetStates(send_chan));
    if vcpu_num == 0 {
        bail!("vcpu_num is zero");
    }
    let mut current_mode_vec: Vec<VmRunMode> = Vec::new();
    for _ in 0..vcpu_num {
        match recv_chan.recv() {
            Ok(state) => current_mode_vec.push(state),
            Err(e) => {
                bail!("Failed to get vCPU state: {}", e);
            }
        };
    }
    let first_state = current_mode_vec[0];
    if first_state == VmRunMode::Exiting {
        panic!("Attempt to snapshot while exiting.");
    }
    if current_mode_vec.iter().any(|x| *x != first_state) {
        // We do not panic here. It could be that vCPUs are transitioning from one mode to another.
        bail!("Unknown VM state: vCPUs hold different states.");
    }
    Ok(first_state)
}

/// A guard to guarantee that all the vCPUs are suspended during the scope.
///
/// When this guard is dropped, it rolls back the state of CPUs.
pub struct VcpuSuspendGuard<'a> {
    saved_run_mode: VmRunMode,
    kick_vcpus: &'a dyn Fn(VcpuControl),
}

impl<'a> VcpuSuspendGuard<'a> {
    /// Check the all vCPU state and suspend the vCPUs if they are running.
    ///
    /// This returns [VcpuSuspendGuard] to rollback the vcpu state.
    ///
    /// # Arguments
    ///
    /// * `kick_vcpus` - A funtion to send [VcpuControl] message to all the vCPUs and interrupt
    ///   them.
    /// * `vcpu_num` - The number of vCPUs.
    pub fn new(kick_vcpus: &'a impl Fn(VcpuControl), vcpu_num: usize) -> anyhow::Result<Self> {
        // get initial vcpu state
        let saved_run_mode = get_vcpu_state(kick_vcpus, vcpu_num)?;
        match saved_run_mode {
            VmRunMode::Running => {
                kick_vcpus(VcpuControl::RunState(VmRunMode::Suspending));
                // Blocking call, waiting for response to ensure vCPU state was updated.
                // In case of failure, where a vCPU still has the state running, start up vcpus and
                // abort operation.
                let current_mode = get_vcpu_state(kick_vcpus, vcpu_num)?;
                if current_mode != VmRunMode::Suspending {
                    kick_vcpus(VcpuControl::RunState(saved_run_mode));
                    bail!("vCPUs failed to all suspend. Kicking back all vCPUs to their previous state: {saved_run_mode}");
                }
            }
            VmRunMode::Suspending => {
                // do nothing. keep the state suspending.
            }
            other => {
                bail!("vcpus are not in running/suspending state, but {}", other);
            }
        };
        Ok(Self {
            saved_run_mode,
            kick_vcpus,
        })
    }
}

impl Drop for VcpuSuspendGuard<'_> {
    fn drop(&mut self) {
        if self.saved_run_mode != VmRunMode::Suspending {
            (self.kick_vcpus)(VcpuControl::RunState(self.saved_run_mode));
        }
    }
}

/// A guard to guarantee that all devices are sleeping during its scope.
///
/// When this guard is dropped, it wakes the devices.
pub struct DeviceSleepGuard<'a> {
    device_control_tube: &'a Tube,
    devices_state: DevicesState,
}

impl<'a> DeviceSleepGuard<'a> {
    fn new(device_control_tube: &'a Tube) -> anyhow::Result<Self> {
        device_control_tube
            .send(&DeviceControlCommand::GetDevicesState)
            .context("send command to devices control socket")?;
        let devices_state = match device_control_tube
            .recv()
            .context("receive from devices control socket")?
        {
            VmResponse::DevicesState(state) => state,
            resp => bail!("failed to get devices state. Unexpected behavior: {}", resp),
        };
        if let DevicesState::Wake = devices_state {
            device_control_tube
                .send(&DeviceControlCommand::SleepDevices)
                .context("send command to devices control socket")?;
            match device_control_tube
                .recv()
                .context("receive from devices control socket")?
            {
                VmResponse::Ok => (),
                resp => bail!("device sleep failed: {}", resp),
            }
        }
        Ok(Self {
            device_control_tube,
            devices_state,
        })
    }
}

impl Drop for DeviceSleepGuard<'_> {
    fn drop(&mut self) {
        if let DevicesState::Wake = self.devices_state {
            if let Err(e) = self
                .device_control_tube
                .send(&DeviceControlCommand::WakeDevices)
            {
                panic!("failed to request device wake after snapshot: {}", e);
            }
            match self.device_control_tube.recv() {
                Ok(VmResponse::Ok) => (),
                Ok(resp) => panic!("unexpected response to device wake request: {}", resp),
                Err(e) => panic!("failed to get reply for device wake request: {}", e),
            }
        }
    }
}

impl VmRequest {
    /// Executes this request on the given Vm and other mutable state.
    ///
    /// This does not return a result, instead encapsulating the success or failure in a
    /// `VmResponse` with the intended purpose of sending the response back over the  socket that
    /// received this `VmRequest`.
    ///
    /// `suspended_pvclock_state`: If the hypervisor has its own pvclock (not the same as
    /// virtio-pvclock) and the VM is suspended (not just the vCPUs, but the full VM), then
    /// `suspended_pvclock_state` will be used to store the ClockState saved just after the vCPUs
    /// were suspended. It is important that we save the value right after the vCPUs are suspended
    /// and restore it right before the vCPUs are resumed (instead of, more naturally, during the
    /// snapshot/restore steps) because the pvclock continues to tick even when the vCPUs are
    /// suspended.
    #[allow(unused_variables)]
    pub fn execute(
        &self,
        vm: &impl Vm,
        disk_host_tubes: &[Tube],
        snd_host_tubes: &[Tube],
        pm: &mut Option<Arc<Mutex<dyn PmResource + Send>>>,
        gpu_control_tube: Option<&Tube>,
        usb_control_tube: Option<&Tube>,
        bat_control: &mut Option<BatControl>,
        kick_vcpus: impl Fn(VcpuControl),
        #[cfg(any(target_os = "android", target_os = "linux"))] kick_vcpu: impl Fn(usize, VcpuControl),
        force_s2idle: bool,
        #[cfg(feature = "swap")] swap_controller: Option<&swap::SwapController>,
        device_control_tube: &Tube,
        vcpu_size: usize,
        irq_handler_control: &Tube,
        snapshot_irqchip: impl Fn() -> anyhow::Result<AnySnapshot>,
        suspended_pvclock_state: &mut Option<hypervisor::ClockState>,
    ) -> VmResponse {
        match self {
            VmRequest::Exit => {
                panic!("VmRequest::Exit should be handled by the platform run loop");
            }
            VmRequest::Powerbtn => {
                if let Some(pm) = pm {
                    pm.lock().pwrbtn_evt();
                    VmResponse::Ok
                } else {
                    error!("{:#?} not supported", *self);
                    VmResponse::Err(SysError::new(ENOTSUP))
                }
            }
            VmRequest::Sleepbtn => {
                if let Some(pm) = pm {
                    pm.lock().slpbtn_evt();
                    VmResponse::Ok
                } else {
                    error!("{:#?} not supported", *self);
                    VmResponse::Err(SysError::new(ENOTSUP))
                }
            }
            VmRequest::Rtc { clear_evt } => {
                if let Some(pm) = pm.as_ref() {
                    match clear_evt.try_clone() {
                        Ok(clear_evt) => {
                            // RTC event will asynchronously trigger wakeup.
                            pm.lock().rtc_evt(clear_evt);
                            VmResponse::Ok
                        }
                        Err(err) => {
                            error!("Error cloning clear_evt: {:?}", err);
                            VmResponse::Err(SysError::new(EIO))
                        }
                    }
                } else {
                    error!("{:#?} not supported", *self);
                    VmResponse::Err(SysError::new(ENOTSUP))
                }
            }
            VmRequest::SuspendVcpus => {
                if !force_s2idle {
                    kick_vcpus(VcpuControl::RunState(VmRunMode::Suspending));
                    let current_mode = match get_vcpu_state(kick_vcpus, vcpu_size) {
                        Ok(state) => state,
                        Err(e) => {
                            error!("failed to get vcpu state: {e}");
                            return VmResponse::Err(SysError::new(EIO));
                        }
                    };
                    if current_mode != VmRunMode::Suspending {
                        error!("vCPUs failed to all suspend.");
                        return VmResponse::Err(SysError::new(EIO));
                    }
                }
                VmResponse::Ok
            }
            VmRequest::ResumeVcpus => {
                if let Err(e) = device_control_tube.send(&DeviceControlCommand::GetDevicesState) {
                    error!("failed to send GetDevicesState: {}", e);
                    return VmResponse::Err(SysError::new(EIO));
                }
                let devices_state = match device_control_tube.recv() {
                    Ok(VmResponse::DevicesState(state)) => state,
                    Ok(resp) => {
                        error!("failed to get devices state. Unexpected behavior: {}", resp);
                        return VmResponse::Err(SysError::new(EINVAL));
                    }
                    Err(e) => {
                        error!("failed to get devices state. Unexpected behavior: {}", e);
                        return VmResponse::Err(SysError::new(EINVAL));
                    }
                };
                if let DevicesState::Sleep = devices_state {
                    error!("Trying to wake Vcpus while Devices are asleep. Did you mean to use `crosvm resume --full`?");
                    return VmResponse::Err(SysError::new(EINVAL));
                }

                if force_s2idle {
                    // During resume also emulate powerbtn event which will allow to wakeup fully
                    // suspended guest.
                    if let Some(pm) = pm {
                        pm.lock().pwrbtn_evt();
                    } else {
                        error!("triggering power btn during resume not supported");
                        return VmResponse::Err(SysError::new(ENOTSUP));
                    }
                }

                kick_vcpus(VcpuControl::RunState(VmRunMode::Running));
                VmResponse::Ok
            }
            VmRequest::Swap(SwapCommand::Enable) => {
                #[cfg(feature = "swap")]
                if let Some(swap_controller) = swap_controller {
                    // Suspend all vcpus and devices while vmm-swap is enabling (move the guest
                    // memory contents to the staging memory) to guarantee no processes other than
                    // the swap monitor process access the guest memory.
                    let _vcpu_guard = match VcpuSuspendGuard::new(&kick_vcpus, vcpu_size) {
                        Ok(guard) => guard,
                        Err(e) => {
                            error!("failed to suspend vcpus: {:?}", e);
                            return VmResponse::Err(SysError::new(EINVAL));
                        }
                    };
                    // TODO(b/253386409): Use `devices::Suspendable::sleep()` instead of sending
                    // `SIGSTOP` signal.
                    let _devices_guard = match swap_controller.suspend_devices() {
                        Ok(guard) => guard,
                        Err(e) => {
                            error!("failed to suspend devices: {:?}", e);
                            return VmResponse::Err(SysError::new(EINVAL));
                        }
                    };

                    return match swap_controller.enable() {
                        Ok(()) => VmResponse::Ok,
                        Err(e) => {
                            error!("swap enable failed: {}", e);
                            VmResponse::Err(SysError::new(EINVAL))
                        }
                    };
                }
                VmResponse::Err(SysError::new(ENOTSUP))
            }
            VmRequest::Swap(SwapCommand::Trim) => {
                #[cfg(feature = "swap")]
                if let Some(swap_controller) = swap_controller {
                    return match swap_controller.trim() {
                        Ok(()) => VmResponse::Ok,
                        Err(e) => {
                            error!("swap trim failed: {}", e);
                            VmResponse::Err(SysError::new(EINVAL))
                        }
                    };
                }
                VmResponse::Err(SysError::new(ENOTSUP))
            }
            VmRequest::Swap(SwapCommand::SwapOut) => {
                #[cfg(feature = "swap")]
                if let Some(swap_controller) = swap_controller {
                    return match swap_controller.swap_out() {
                        Ok(()) => VmResponse::Ok,
                        Err(e) => {
                            error!("swap out failed: {}", e);
                            VmResponse::Err(SysError::new(EINVAL))
                        }
                    };
                }
                VmResponse::Err(SysError::new(ENOTSUP))
            }
            VmRequest::Swap(SwapCommand::Disable {
                #[cfg(feature = "swap")]
                slow_file_cleanup,
                ..
            }) => {
                #[cfg(feature = "swap")]
                if let Some(swap_controller) = swap_controller {
                    return match swap_controller.disable(*slow_file_cleanup) {
                        Ok(()) => VmResponse::Ok,
                        Err(e) => {
                            error!("swap disable failed: {}", e);
                            VmResponse::Err(SysError::new(EINVAL))
                        }
                    };
                }
                VmResponse::Err(SysError::new(ENOTSUP))
            }
            VmRequest::Swap(SwapCommand::Status) => {
                #[cfg(feature = "swap")]
                if let Some(swap_controller) = swap_controller {
                    return match swap_controller.status() {
                        Ok(status) => VmResponse::SwapStatus(status),
                        Err(e) => {
                            error!("swap status failed: {}", e);
                            VmResponse::Err(SysError::new(EINVAL))
                        }
                    };
                }
                VmResponse::Err(SysError::new(ENOTSUP))
            }
            VmRequest::SuspendVm => {
                info!("Starting crosvm suspend");
                kick_vcpus(VcpuControl::RunState(VmRunMode::Suspending));
                let current_mode = match get_vcpu_state(kick_vcpus, vcpu_size) {
                    Ok(state) => state,
                    Err(e) => {
                        error!("failed to get vcpu state: {e}");
                        return VmResponse::Err(SysError::new(EIO));
                    }
                };
                if current_mode != VmRunMode::Suspending {
                    error!("vCPUs failed to all suspend.");
                    return VmResponse::Err(SysError::new(EIO));
                }
                // Snapshot the pvclock ASAP after stopping vCPUs.
                if vm.check_capability(VmCap::PvClock) {
                    if suspended_pvclock_state.is_none() {
                        *suspended_pvclock_state = Some(match vm.get_pvclock() {
                            Ok(x) => x,
                            Err(e) => {
                                error!("suspend_pvclock failed: {e:?}");
                                return VmResponse::Err(SysError::new(EIO));
                            }
                        });
                    }
                }
                if let Err(e) = device_control_tube
                    .send(&DeviceControlCommand::SleepDevices)
                    .context("send command to devices control socket")
                {
                    error!("{:?}", e);
                    return VmResponse::Err(SysError::new(EIO));
                };
                match device_control_tube
                    .recv()
                    .context("receive from devices control socket")
                {
                    Ok(VmResponse::Ok) => {
                        info!("Finished crosvm suspend successfully");
                        VmResponse::Ok
                    }
                    Ok(resp) => {
                        error!("device sleep failed: {}", resp);
                        VmResponse::Err(SysError::new(EIO))
                    }
                    Err(e) => {
                        error!("receive from devices control socket: {:?}", e);
                        VmResponse::Err(SysError::new(EIO))
                    }
                }
            }
            VmRequest::ResumeVm => {
                info!("Starting crosvm resume");
                if let Err(e) = device_control_tube
                    .send(&DeviceControlCommand::WakeDevices)
                    .context("send command to devices control socket")
                {
                    error!("{:?}", e);
                    return VmResponse::Err(SysError::new(EIO));
                };
                match device_control_tube
                    .recv()
                    .context("receive from devices control socket")
                {
                    Ok(VmResponse::Ok) => {
                        info!("Finished crosvm resume successfully");
                    }
                    Ok(resp) => {
                        error!("device wake failed: {}", resp);
                        return VmResponse::Err(SysError::new(EIO));
                    }
                    Err(e) => {
                        error!("receive from devices control socket: {:?}", e);
                        return VmResponse::Err(SysError::new(EIO));
                    }
                }
                // Resume the pvclock as late as possible before starting vCPUs.
                if vm.check_capability(VmCap::PvClock) {
                    // If None, then we aren't suspended, which is a valid case.
                    if let Some(x) = suspended_pvclock_state {
                        if let Err(e) = vm.set_pvclock(x) {
                            error!("resume_pvclock failed: {e:?}");
                            return VmResponse::Err(SysError::new(EIO));
                        }
                    }
                }
                kick_vcpus(VcpuControl::RunState(VmRunMode::Running));
                VmResponse::Ok
            }
            VmRequest::Gpe { gpe, clear_evt } => {
                if let Some(pm) = pm.as_ref() {
                    match clear_evt.as_ref().map(|e| e.try_clone()).transpose() {
                        Ok(clear_evt) => {
                            pm.lock().gpe_evt(*gpe, clear_evt);
                            VmResponse::Ok
                        }
                        Err(err) => {
                            error!("Error cloning clear_evt: {:?}", err);
                            VmResponse::Err(SysError::new(EIO))
                        }
                    }
                } else {
                    error!("{:#?} not supported", *self);
                    VmResponse::Err(SysError::new(ENOTSUP))
                }
            }
            VmRequest::PciPme(requester_id) => {
                if let Some(pm) = pm.as_ref() {
                    pm.lock().pme_evt(*requester_id);
                    VmResponse::Ok
                } else {
                    error!("{:#?} not supported", *self);
                    VmResponse::Err(SysError::new(ENOTSUP))
                }
            }
            VmRequest::MakeRT => {
                kick_vcpus(VcpuControl::MakeRT);
                VmResponse::Ok
            }
            #[cfg(feature = "balloon")]
            VmRequest::BalloonCommand(_) => unreachable!("Should be handled with BalloonTube"),
            VmRequest::DiskCommand {
                disk_index,
                ref command,
            } => match &disk_host_tubes.get(*disk_index) {
                Some(tube) => handle_disk_command(command, tube),
                None => VmResponse::Err(SysError::new(ENODEV)),
            },
            #[cfg(feature = "gpu")]
            VmRequest::GpuCommand(ref cmd) => match gpu_control_tube {
                Some(gpu_control) => {
                    let res = gpu_control.send(cmd);
                    if let Err(e) = res {
                        error!("fail to send command to gpu control socket: {}", e);
                        return VmResponse::Err(SysError::new(EIO));
                    }
                    match gpu_control.recv() {
                        Ok(response) => VmResponse::GpuResponse(response),
                        Err(e) => {
                            error!("fail to recv command from gpu control socket: {}", e);
                            VmResponse::Err(SysError::new(EIO))
                        }
                    }
                }
                None => {
                    error!("gpu control is not enabled in crosvm");
                    VmResponse::Err(SysError::new(EIO))
                }
            },
            VmRequest::UsbCommand(ref cmd) => {
                let usb_control_tube = match usb_control_tube {
                    Some(t) => t,
                    None => {
                        error!("attempted to execute USB request without control tube");
                        return VmResponse::Err(SysError::new(ENODEV));
                    }
                };
                let res = usb_control_tube.send(cmd);
                if let Err(e) = res {
                    error!("fail to send command to usb control socket: {}", e);
                    return VmResponse::Err(SysError::new(EIO));
                }
                match usb_control_tube.recv() {
                    Ok(response) => VmResponse::UsbResponse(response),
                    Err(e) => {
                        error!("fail to recv command from usb control socket: {}", e);
                        VmResponse::Err(SysError::new(EIO))
                    }
                }
            }
            VmRequest::BatCommand(type_, ref cmd) => {
                match bat_control {
                    Some(battery) => {
                        if battery.type_ != *type_ {
                            error!("ignored battery command due to battery type: expected {:?}, got {:?}", battery.type_, type_);
                            return VmResponse::Err(SysError::new(EINVAL));
                        }

                        let res = battery.control_tube.send(cmd);
                        if let Err(e) = res {
                            error!("fail to send command to bat control socket: {}", e);
                            return VmResponse::Err(SysError::new(EIO));
                        }

                        match battery.control_tube.recv() {
                            Ok(response) => VmResponse::BatResponse(response),
                            Err(e) => {
                                error!("fail to recv command from bat control socket: {}", e);
                                VmResponse::Err(SysError::new(EIO))
                            }
                        }
                    }
                    None => VmResponse::BatResponse(BatControlResult::NoBatDevice),
                }
            }
            #[cfg(feature = "audio")]
            VmRequest::SndCommand(ref cmd) => match cmd {
                SndControlCommand::MuteAll(muted) => {
                    for tube in snd_host_tubes {
                        let res = tube.send(&SndControlCommand::MuteAll(*muted));
                        if let Err(e) = res {
                            error!("fail to send command to snd control socket: {}", e);
                            return VmResponse::Err(SysError::new(EIO));
                        }

                        match tube.recv() {
                            Ok(VmResponse::Ok) => {
                                debug!("device is successfully muted");
                            }
                            Ok(resp) => {
                                error!("mute failed: {}", resp);
                                return VmResponse::ErrString("fail to mute the device".to_owned());
                            }
                            Err(e) => return VmResponse::Err(SysError::new(EIO)),
                        }
                    }
                    VmResponse::Ok
                }
            },
            VmRequest::HotPlugVfioCommand { device: _, add: _ } => VmResponse::Ok,
            #[cfg(feature = "pci-hotplug")]
            VmRequest::HotPlugNetCommand(ref _net_cmd) => {
                VmResponse::ErrString("hot plug not supported".to_owned())
            }
            VmRequest::Snapshot(SnapshotCommand::Take {
                ref snapshot_path,
                compress_memory,
                encrypt,
            }) => {
                info!("Starting crosvm snapshot");
                match do_snapshot(
                    snapshot_path.to_path_buf(),
                    kick_vcpus,
                    irq_handler_control,
                    device_control_tube,
                    vcpu_size,
                    snapshot_irqchip,
                    *compress_memory,
                    *encrypt,
                    suspended_pvclock_state,
                    vm,
                ) {
                    Ok(()) => {
                        info!("Finished crosvm snapshot successfully");
                        VmResponse::Ok
                    }
                    Err(e) => {
                        error!("failed to handle snapshot: {:?}", e);
                        VmResponse::Err(SysError::new(EIO))
                    }
                }
            }
            VmRequest::RegisterListener {
                socket_addr: _,
                event: _,
            } => VmResponse::Ok,
            VmRequest::UnregisterListener {
                socket_addr: _,
                event: _,
            } => VmResponse::Ok,
            VmRequest::Unregister { socket_addr: _ } => VmResponse::Ok,
            VmRequest::VcpuPidTid => unreachable!(),
            VmRequest::Throttle(_, _) => unreachable!(),
            VmRequest::GetVmDescriptor => {
                let vm_fd = match vm.try_clone_descriptor() {
                    Ok(vm_fd) => vm_fd,
                    Err(e) => {
                        error!("failed to get vm_fd: {:?}", e);
                        return VmResponse::Err(e);
                    }
                };
                VmResponse::VmDescriptor {
                    hypervisor: vm.hypervisor_kind(),
                    vm_fd,
                }
            }
        }
    }
}

/// Snapshot the VM to file at `snapshot_path`
fn do_snapshot(
    snapshot_path: PathBuf,
    kick_vcpus: impl Fn(VcpuControl),
    irq_handler_control: &Tube,
    device_control_tube: &Tube,
    vcpu_size: usize,
    snapshot_irqchip: impl Fn() -> anyhow::Result<AnySnapshot>,
    compress_memory: bool,
    encrypt: bool,
    suspended_pvclock_state: &mut Option<hypervisor::ClockState>,
    vm: &impl Vm,
) -> anyhow::Result<()> {
    let snapshot_start = Instant::now();

    let _vcpu_guard = VcpuSuspendGuard::new(&kick_vcpus, vcpu_size)?;
    let _device_guard = DeviceSleepGuard::new(device_control_tube)?;

    // We want to flush all pending IRQs to the interrupt controller. There are two cases:
    //
    // MSIs: these are directly delivered to the interrupt controller.
    // We must verify the handler thread cycles once to deliver these interrupts.
    //
    // Legacy interrupts: in the case of a split IRQ chip, these interrupts may
    // flow through the userspace IOAPIC. If the hypervisor does not support
    // irqfds (e.g. WHPX), a single iteration will only flush the IRQ to the
    // IOAPIC. The underlying MSI will be asserted at this point, but if the
    // IRQ handler doesn't run another iteration, it won't be delivered to the
    // interrupt controller. This is why we cycle the handler thread twice (doing so
    // ensures we process the underlying MSI).
    //
    // We can handle both of these cases by iterating until there are no tokens
    // serviced on the requested iteration. Note that in the legacy case, this
    // ensures at least two iterations.
    //
    // Note: within CrosVM, *all* interrupts are eventually converted into the
    // same mechanicism that MSIs use. This is why we say "underlying" MSI for
    // a legacy IRQ.
    {
        let mut flush_attempts = 0;
        loop {
            irq_handler_control
                .send(&IrqHandlerRequest::WakeAndNotifyIteration)
                .context("failed to send flush command to IRQ handler thread")?;
            let resp = irq_handler_control
                .recv()
                .context("failed to recv flush response from IRQ handler thread")?;
            match resp {
                IrqHandlerResponse::HandlerIterationComplete(tokens_serviced) => {
                    if tokens_serviced == 0 {
                        break;
                    }
                }
                _ => bail!("received unexpected reply from IRQ handler: {:?}", resp),
            }
            flush_attempts += 1;
            if flush_attempts > EXPECTED_MAX_IRQ_FLUSH_ITERATIONS {
                warn!(
                    "flushing IRQs for snapshot may be stalled after iteration {}, expected <= {}
                      iterations",
                    flush_attempts, EXPECTED_MAX_IRQ_FLUSH_ITERATIONS
                );
            }
        }
        info!("flushed IRQs in {} iterations", flush_attempts);
    }
    let snapshot_writer = SnapshotWriter::new(snapshot_path, encrypt)?;

    // Snapshot hypervisor's paravirtualized clock.
    snapshot_writer.write_fragment("pvclock", &AnySnapshot::to_any(suspended_pvclock_state)?)?;

    // Snapshot Vcpus
    info!("VCPUs snapshotting...");
    let (send_chan, recv_chan) = mpsc::channel();
    kick_vcpus(VcpuControl::Snapshot(
        snapshot_writer.add_namespace("vcpu")?,
        send_chan,
    ));
    // Validate all Vcpus snapshot successfully
    for _ in 0..vcpu_size {
        recv_chan
            .recv()
            .context("Failed to recv Vcpu snapshot response")?
            .context("Failed to snapshot Vcpu")?;
    }
    info!("VCPUs snapshotted.");

    // Snapshot irqchip
    info!("Snapshotting irqchip...");
    let irqchip_snap = snapshot_irqchip()?;
    snapshot_writer
        .write_fragment("irqchip", &irqchip_snap)
        .context("Failed to write irqchip state")?;
    info!("Snapshotted irqchip.");

    // Snapshot memory
    {
        let mem_snap_start = Instant::now();
        // Use 64MB chunks when writing the memory snapshot (if encryption is used).
        const MEMORY_SNAP_ENCRYPTED_CHUNK_SIZE_BYTES: usize = 1024 * 1024 * 64;
        // SAFETY:
        // VM & devices are stopped.
        let guest_memory_metadata = unsafe {
            vm.get_memory()
                .snapshot(
                    &mut snapshot_writer.raw_fragment_with_chunk_size(
                        "mem",
                        MEMORY_SNAP_ENCRYPTED_CHUNK_SIZE_BYTES,
                    )?,
                    compress_memory,
                )
                .context("failed to snapshot memory")?
        };
        snapshot_writer.write_fragment("mem_metadata", &guest_memory_metadata)?;

        let mem_snap_duration_ms = mem_snap_start.elapsed().as_millis();
        info!(
            "snapshot: memory snapshotted {}MB in {}ms",
            vm.get_memory().memory_size() / 1024 / 1024,
            mem_snap_duration_ms
        );
        metrics::log_metric_with_details(
            metrics::MetricEventType::SnapshotSaveMemoryLatency,
            mem_snap_duration_ms as i64,
            &metrics_events::RecordDetails {},
        );
    }
    // Snapshot devices
    info!("Devices snapshotting...");
    device_control_tube
        .send(&DeviceControlCommand::SnapshotDevices { snapshot_writer })
        .context("send command to devices control socket")?;
    let resp: VmResponse = device_control_tube
        .recv()
        .context("receive from devices control socket")?;
    if !matches!(resp, VmResponse::Ok) {
        bail!("unexpected SnapshotDevices response: {resp}");
    }
    info!("Devices snapshotted.");

    let snap_duration_ms = snapshot_start.elapsed().as_millis();
    info!(
        "snapshot: completed snapshot in {}ms; VM mem size: {}MB",
        snap_duration_ms,
        vm.get_memory().memory_size() / 1024 / 1024,
    );
    metrics::log_metric_with_details(
        metrics::MetricEventType::SnapshotSaveOverallLatency,
        snap_duration_ms as i64,
        &metrics_events::RecordDetails {},
    );
    Ok(())
}

/// Restore the VM to the snapshot at `restore_path`.
///
/// Same as `VmRequest::execute` with a `VmRequest::Restore`. Exposed as a separate function
/// because not all the `VmRequest::execute` arguments are available in the "cold restore" flow.
pub fn do_restore(
    restore_path: &Path,
    kick_vcpus: impl Fn(VcpuControl),
    kick_vcpu: impl Fn(VcpuControl, usize),
    irq_handler_control: &Tube,
    device_control_tube: &Tube,
    vcpu_size: usize,
    mut restore_irqchip: impl FnMut(AnySnapshot) -> anyhow::Result<()>,
    require_encrypted: bool,
    suspended_pvclock_state: &mut Option<hypervisor::ClockState>,
    vm: &impl Vm,
) -> anyhow::Result<()> {
    let restore_start = Instant::now();
    let _guard = VcpuSuspendGuard::new(&kick_vcpus, vcpu_size);
    let _devices_guard = DeviceSleepGuard::new(device_control_tube)?;

    let snapshot_reader = SnapshotReader::new(restore_path, require_encrypted)?;

    // Restore hypervisor's paravirtualized clock.
    *suspended_pvclock_state = snapshot_reader.read_fragment("pvclock")?;

    // Restore IrqChip
    let irq_snapshot: AnySnapshot = snapshot_reader.read_fragment("irqchip")?;
    restore_irqchip(irq_snapshot)?;

    // Restore Vcpu(s)
    let vcpu_snapshot_reader = snapshot_reader.namespace("vcpu")?;
    let vcpu_snapshot_count = vcpu_snapshot_reader.list_fragments()?.len();
    if vcpu_snapshot_count != vcpu_size {
        bail!(
            "bad cpu count in snapshot: expected={} got={}",
            vcpu_size,
            vcpu_snapshot_count,
        );
    }
    #[cfg(target_arch = "x86_64")]
    let host_tsc_reference_moment = {
        // SAFETY: rdtsc takes no arguments.
        unsafe { _rdtsc() }
    };
    let (send_chan, recv_chan) = mpsc::channel();
    for vcpu_id in 0..vcpu_size {
        kick_vcpu(
            VcpuControl::Restore(VcpuRestoreRequest {
                result_sender: send_chan.clone(),
                snapshot_reader: vcpu_snapshot_reader.clone(),
                #[cfg(target_arch = "x86_64")]
                host_tsc_reference_moment,
            }),
            vcpu_id,
        );
    }
    for _ in 0..vcpu_size {
        recv_chan
            .recv()
            .context("Failed to recv restore response")?
            .context("Failed to restore vcpu")?;
    }

    // Restore Memory
    {
        let mem_restore_start = Instant::now();
        let guest_memory_metadata = snapshot_reader.read_fragment("mem_metadata")?;
        // SAFETY:
        // VM & devices are stopped.
        unsafe {
            vm.get_memory().restore(
                guest_memory_metadata,
                &mut snapshot_reader.raw_fragment("mem")?,
            )?
        };
        let mem_restore_duration_ms = mem_restore_start.elapsed().as_millis();
        info!(
            "snapshot: memory restored {}MB in {}ms",
            vm.get_memory().memory_size() / 1024 / 1024,
            mem_restore_duration_ms
        );
        metrics::log_metric_with_details(
            metrics::MetricEventType::SnapshotRestoreMemoryLatency,
            mem_restore_duration_ms as i64,
            &metrics_events::RecordDetails {},
        );
    }
    // Restore devices
    device_control_tube
        .send(&DeviceControlCommand::RestoreDevices {
            snapshot_reader: snapshot_reader.clone(),
        })
        .context("send restore devices command to devices control socket")?;
    let resp: VmResponse = device_control_tube
        .recv()
        .context("receive from devices control socket")?;
    if !matches!(resp, VmResponse::Ok) {
        bail!("unexpected RestoreDevices response: {resp}");
    }

    // refresh the IRQ tokens.
    {
        irq_handler_control
            .send(&IrqHandlerRequest::RefreshIrqEventTokens)
            .context("failed to send refresh irq event token command to IRQ handler thread")?;
        let resp: IrqHandlerResponse = irq_handler_control
            .recv()
            .context("failed to recv refresh response from IRQ handler thread")?;
        if !matches!(resp, IrqHandlerResponse::IrqEventTokenRefreshComplete) {
            bail!(
                "received unexpected reply from IRQ handler thread: {:?}",
                resp
            );
        }
    }

    let restore_duration_ms = restore_start.elapsed().as_millis();
    info!(
        "snapshot: completed restore in {}ms; mem size: {}",
        restore_duration_ms,
        vm.get_memory().memory_size(),
    );

    metrics::log_metric_with_details(
        metrics::MetricEventType::SnapshotRestoreOverallLatency,
        restore_duration_ms as i64,
        &metrics_events::RecordDetails {},
    );
    Ok(())
}

pub type HypervisorKind = hypervisor::HypervisorKind;

/// Indication of success or failure of a `VmRequest`.
///
/// Success is usually indicated `VmResponse::Ok` unless there is data associated with the response.
#[derive(Serialize, Deserialize, Debug)]
#[must_use]
pub enum VmResponse {
    /// Indicates the request was executed successfully.
    Ok,
    /// Indicates the request encountered some error during execution.
    Err(SysError),
    /// Indicates the request encountered some error during execution.
    ErrString(String),
    /// The memory was registered into guest address space in memory slot number `slot`.
    RegisterMemory { slot: u32 },
    /// Results of balloon control commands.
    #[cfg(feature = "balloon")]
    BalloonStats {
        stats: balloon_control::BalloonStats,
        balloon_actual: u64,
    },
    /// Results of balloon WS-R command
    #[cfg(feature = "balloon")]
    BalloonWS {
        ws: balloon_control::BalloonWS,
        balloon_actual: u64,
    },
    /// Results of PCI hot plug
    #[cfg(feature = "pci-hotplug")]
    PciHotPlugResponse { bus: u8 },
    /// Results of usb control commands.
    UsbResponse(UsbControlResult),
    #[cfg(feature = "gpu")]
    /// Results of gpu control commands.
    GpuResponse(GpuControlResult),
    /// Results of battery control commands.
    BatResponse(BatControlResult),
    /// Results of swap status command.
    SwapStatus(SwapStatus),
    /// Gets the state of Devices (sleep/wake)
    DevicesState(DevicesState),
    /// Map of the Vcpu PID/TIDs
    VcpuPidTidResponse {
        pid_tid_map: BTreeMap<usize, (u32, u32)>,
    },
    VmDescriptor {
        hypervisor: HypervisorKind,
        vm_fd: SafeDescriptor,
    },
}

impl Display for VmResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::VmResponse::*;

        match self {
            Ok => write!(f, "ok"),
            Err(e) => write!(f, "error: {}", e),
            ErrString(e) => write!(f, "error: {}", e),
            RegisterMemory { slot } => write!(f, "memory registered in slot {}", slot),
            #[cfg(feature = "balloon")]
            VmResponse::BalloonStats {
                stats,
                balloon_actual,
            } => {
                write!(
                    f,
                    "stats: {}\nballoon_actual: {}",
                    serde_json::to_string_pretty(&stats)
                        .unwrap_or_else(|_| "invalid_response".to_string()),
                    balloon_actual
                )
            }
            #[cfg(feature = "balloon")]
            VmResponse::BalloonWS { ws, balloon_actual } => {
                write!(
                    f,
                    "ws: {}, balloon_actual: {}",
                    serde_json::to_string_pretty(&ws)
                        .unwrap_or_else(|_| "invalid_response".to_string()),
                    balloon_actual,
                )
            }
            UsbResponse(result) => write!(f, "usb control request get result {:?}", result),
            #[cfg(feature = "pci-hotplug")]
            PciHotPlugResponse { bus } => write!(f, "pci hotplug bus {:?}", bus),
            #[cfg(feature = "gpu")]
            GpuResponse(result) => write!(f, "gpu control request result {:?}", result),
            BatResponse(result) => write!(f, "{}", result),
            SwapStatus(status) => {
                write!(
                    f,
                    "{}",
                    serde_json::to_string(&status)
                        .unwrap_or_else(|_| "invalid_response".to_string()),
                )
            }
            DevicesState(status) => write!(f, "devices status: {:?}", status),
            VcpuPidTidResponse { pid_tid_map } => write!(f, "vcpu pid tid map: {:?}", pid_tid_map),
            VmDescriptor { hypervisor, vm_fd } => {
                write!(f, "hypervisor: {:?}, vm_fd: {:?}", hypervisor, vm_fd)
            }
        }
    }
}

/// Enum that allows remote control of a wait context (used between the Windows GpuDisplay & the
/// GPU worker).
#[derive(Serialize, Deserialize)]
pub enum ModifyWaitContext {
    Add(#[serde(with = "with_as_descriptor")] Descriptor),
}

#[sorted]
#[derive(Error, Debug)]
pub enum VirtioIOMMUVfioError {
    #[error("socket failed")]
    SocketFailed,
    #[error("unexpected response: {0}")]
    UnexpectedResponse(VirtioIOMMUResponse),
    #[error("unknown command: `{0}`")]
    UnknownCommand(String),
    #[error("{0}")]
    VfioControl(VirtioIOMMUVfioResult),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum VirtioIOMMUVfioCommand {
    // Add the vfio device attached to virtio-iommu.
    VfioDeviceAdd {
        endpoint_addr: u32,
        wrapper_id: u32,
        #[serde(with = "with_as_descriptor")]
        container: File,
    },
    // Delete the vfio device attached to virtio-iommu.
    VfioDeviceDel {
        endpoint_addr: u32,
    },
    // Map a dma-buf into vfio iommu table
    VfioDmabufMap {
        region_id: VmMemoryRegionId,
        gpa: u64,
        size: u64,
        dma_buf: SafeDescriptor,
    },
    // Unmap a dma-buf from vfio iommu table
    VfioDmabufUnmap(VmMemoryRegionId),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum VirtioIOMMUVfioResult {
    Ok,
    NotInPCIRanges,
    NoAvailableContainer,
    NoSuchDevice,
    NoSuchMappedDmabuf,
    InvalidParam,
}

impl Display for VirtioIOMMUVfioResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::VirtioIOMMUVfioResult::*;

        match self {
            Ok => write!(f, "successfully"),
            NotInPCIRanges => write!(f, "not in the pci ranges of virtio-iommu"),
            NoAvailableContainer => write!(f, "no available vfio container"),
            NoSuchDevice => write!(f, "no such a vfio device"),
            NoSuchMappedDmabuf => write!(f, "no such a mapped dmabuf"),
            InvalidParam => write!(f, "invalid parameters"),
        }
    }
}

/// A request to the virtio-iommu process to perform some operations.
///
/// Unless otherwise noted, each request should expect a `VirtioIOMMUResponse::Ok` to be received on
/// success.
#[derive(Serialize, Deserialize, Debug)]
pub enum VirtioIOMMURequest {
    /// Command for vfio related operations.
    VfioCommand(VirtioIOMMUVfioCommand),
}

/// Indication of success or failure of a `VirtioIOMMURequest`.
///
/// Success is usually indicated `VirtioIOMMUResponse::Ok` unless there is data associated with the
/// response.
#[derive(Serialize, Deserialize, Debug)]
pub enum VirtioIOMMUResponse {
    /// Indicates the request was executed successfully.
    Ok,
    /// Indicates the request encountered some error during execution.
    Err(SysError),
    /// Results for Vfio commands.
    VfioResponse(VirtioIOMMUVfioResult),
}

impl Display for VirtioIOMMUResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::VirtioIOMMUResponse::*;
        match self {
            Ok => write!(f, "ok"),
            Err(e) => write!(f, "error: {}", e),
            VfioResponse(result) => write!(
                f,
                "The vfio-related virtio-iommu request got result: {:?}",
                result
            ),
        }
    }
}

/// Send VirtioIOMMURequest without waiting for the response
pub fn virtio_iommu_request_async(
    iommu_control_tube: &Tube,
    req: &VirtioIOMMURequest,
) -> VirtioIOMMUResponse {
    match iommu_control_tube.send(&req) {
        Ok(_) => VirtioIOMMUResponse::Ok,
        Err(e) => {
            error!("virtio-iommu socket send failed: {:?}", e);
            VirtioIOMMUResponse::Err(SysError::last())
        }
    }
}

pub type VirtioIOMMURequestResult = std::result::Result<VirtioIOMMUResponse, ()>;

/// Send VirtioIOMMURequest and wait to get the response
pub fn virtio_iommu_request(
    iommu_control_tube: &Tube,
    req: &VirtioIOMMURequest,
) -> VirtioIOMMURequestResult {
    let response = match virtio_iommu_request_async(iommu_control_tube, req) {
        VirtioIOMMUResponse::Ok => match iommu_control_tube.recv() {
            Ok(response) => response,
            Err(e) => {
                error!("virtio-iommu socket recv failed: {:?}", e);
                VirtioIOMMUResponse::Err(SysError::last())
            }
        },
        resp => resp,
    };
    Ok(response)
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;

    use super::*;

    #[test]
    fn vm_memory_response_error_should_serialize_and_deserialize_correctly() {
        let source_error: VmMemoryResponseError = anyhow!("root cause")
            .context("context 1")
            .context("context 2")
            .into();
        let serialized_bytes =
            serde_json::to_vec(&source_error).expect("should serialize to json successfully");
        let target_error = serde_json::from_slice::<VmMemoryResponseError>(&serialized_bytes)
            .expect("should deserialize from json successfully");
        assert_eq!(
            format!("{:?}", source_error.0),
            format!("{:?}", target_error.0)
        );
    }

    #[test]
    fn vm_memory_response_error_deserialization_should_handle_malformat_correctly() {
        let flat_source = FlatVmMemoryResponseError(vec![]);
        let serialized_bytes =
            serde_json::to_vec(&flat_source).expect("should serialize to json successfully");
        serde_json::from_slice::<VmMemoryResponseError>(&serialized_bytes)
            .expect_err("deserialize with 0 error messages should fail");
    }
}

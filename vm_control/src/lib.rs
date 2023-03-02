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

#[cfg(all(any(target_arch = "x86_64", target_arch = "aarch64"), feature = "gdb"))]
pub mod gdb;
#[cfg(feature = "gpu")]
pub mod gpu;

#[cfg(unix)]
use base::MemoryMappingBuilderUnix;
#[cfg(windows)]
use base::MemoryMappingBuilderWindows;

pub mod client;
pub mod display;
pub mod sys;

use std::collections::BTreeSet;
use std::convert::TryInto;
use std::fmt;
use std::fmt::Display;
use std::fs::File;
use std::path::PathBuf;
use std::result::Result as StdResult;
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::Arc;

use anyhow::bail;
use anyhow::Context;
pub use balloon_control::BalloonStats;
#[cfg(feature = "balloon")]
use balloon_control::BalloonTubeCommand;
#[cfg(feature = "balloon")]
use balloon_control::BalloonTubeResult;
use base::error;
use base::info;
use base::warn;
use base::with_as_descriptor;
use base::AsRawDescriptor;
use base::Error as SysError;
use base::Event;
use base::ExternalMapping;
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
use libc::EINVAL;
use libc::EIO;
use libc::ENODEV;
use libc::ENOTSUP;
use libc::ERANGE;
use remain::sorted;
use resources::Alloc;
use resources::SystemAllocator;
use rutabaga_gfx::DeviceId;
use rutabaga_gfx::RutabagaGralloc;
use rutabaga_gfx::RutabagaHandle;
use rutabaga_gfx::VulkanInfo;
use serde::Deserialize;
use serde::Serialize;
use sync::Mutex;
#[cfg(unix)]
pub use sys::FsMappingRequest;
#[cfg(unix)]
pub use sys::VmMsyncRequest;
#[cfg(unix)]
pub use sys::VmMsyncResponse;
use thiserror::Error;
use vm_memory::GuestAddress;

use crate::display::AspectRatio;
use crate::display::DisplaySize;
use crate::display::GuestDisplayDensity;
use crate::display::MouseMode;
use crate::display::WindowEvent;
use crate::display::WindowMode;
use crate::display::WindowVisibility;
#[cfg(all(any(target_arch = "x86_64", target_arch = "aarch64"), feature = "gdb"))]
pub use crate::gdb::VcpuDebug;
#[cfg(all(any(target_arch = "x86_64", target_arch = "aarch64"), feature = "gdb"))]
pub use crate::gdb::VcpuDebugStatus;
#[cfg(all(any(target_arch = "x86_64", target_arch = "aarch64"), feature = "gdb"))]
pub use crate::gdb::VcpuDebugStatusMessage;
#[cfg(feature = "gpu")]
use crate::gpu::GpuControlCommand;
#[cfg(feature = "gpu")]
use crate::gpu::GpuControlResult;

/// Control the state of a particular VM CPU.
#[derive(Clone, Debug)]
pub enum VcpuControl {
    #[cfg(all(any(target_arch = "x86_64", target_arch = "aarch64"), feature = "gdb"))]
    Debug(VcpuDebug),
    RunState(VmRunMode),
    MakeRT,
    GetStates,
}

/// Mode of execution for the VM.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum VmRunMode {
    /// The default run mode indicating the VCPUs are running.
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

impl Default for VmRunMode {
    fn default() -> Self {
        VmRunMode::Running
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
    fn gpe_evt(&mut self, _gpe: u32) {}
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

// Balloon commands that are sent on the crosvm control socket.
#[derive(Serialize, Deserialize, Debug)]
pub enum BalloonControlCommand {
    /// Set the size of the VM's balloon.
    Adjust {
        num_bytes: u64,
    },
    Stats,
}

// BalloonControlResult holds results for BalloonControlCommand defined above.
#[derive(Serialize, Deserialize, Debug)]
pub enum BalloonControlResult {
    Stats {
        stats: BalloonStats,
        balloon_actual: u64,
    },
}

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

#[derive(Serialize, Deserialize, Debug)]
pub enum UsbControlCommand {
    AttachDevice {
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
    Take { snapshot_path: PathBuf },
}

/// Response for [SnapshotCommand]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SnapshotControlResult {
    /// The request is accepted successfully.
    Ok,
    /// The command fails.
    Failed(String),
    /// Request VM shut down in case of major failures.
    Shutdown,
}
/// Commands for restore feature
#[derive(Serialize, Deserialize, Debug)]
pub enum RestoreCommand {
    Apply { restore_path: PathBuf },
}

/// Response for [RestoreCommand]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum RestoreControlResult {
    /// The request is accepted successfully.
    Ok,
    /// The command fails.
    Failed(String),
}

/// Commands for actions on devices and the devices control thread.
#[derive(Serialize, Deserialize, Debug)]
pub enum DeviceControlCommand {
    SnapshotDevices { snapshot_path: PathBuf },
    RestoreDevices { restore_path: PathBuf },
    Exit,
}

/// Commands to control the IRQ handler thread.
#[derive(Serialize, Deserialize)]
pub enum IrqHandlerRequest {
    /// No response is sent for this command.
    AddIrqControlTubes(Vec<Tube>),
    WakeAndNotifyIteration,
    /// No response is sent for this command.
    Exit,
}

const EXPECTED_MAX_IRQ_FLUSH_ITERATIONS: usize = 100;

/// Response for [IrqHandlerRequest].
#[derive(Serialize, Deserialize, Debug)]
pub enum IrqHandlerResponse {
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
        device_id: DeviceId,
        size: u64,
    },
    /// Register the current rutabaga external mapping.
    ExternalMapping { ptr: u64, size: u64 },
}

impl VmMemorySource {
    /// Map the resource and return its mapping and size in bytes.
    pub fn map(
        self,
        gralloc: &mut RutabagaGralloc,
        prot: Protection,
    ) -> Result<(Box<dyn MappedRegion>, u64, Option<SafeDescriptor>)> {
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
                device_id,
                size,
            } => {
                let mapped_region = match gralloc.import_and_map(
                    RutabagaHandle {
                        os_handle: descriptor,
                        handle_type,
                    },
                    VulkanInfo {
                        memory_idx,
                        device_id,
                    },
                    size,
                ) {
                    Ok(mapped_region) => mapped_region,
                    Err(e) => {
                        error!("gralloc failed to import and map: {}", e);
                        return Err(SysError::new(EINVAL));
                    }
                };
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

#[derive(Serialize, Deserialize)]
pub enum VmMemoryRequest {
    RegisterMemory {
        /// Source of the memory to register (mapped file descriptor, shared memory region, etc.)
        source: VmMemorySource,
        /// Where to map the memory in the guest.
        dest: VmMemoryDestination,
        /// Whether to map the memory read only (true) or read-write (false).
        prot: Protection,
    },
    /// Call hypervisor to free the given memory range.
    DynamicallyFreeMemoryRange {
        guest_address: GuestAddress,
        size: u64,
    },
    /// Call hypervisor to reclaim a priorly freed memory range.
    DynamicallyReclaimMemoryRange {
        guest_address: GuestAddress,
        size: u64,
    },
    /// Unregister the given memory slot that was previously registered with `RegisterMemory`.
    UnregisterMemory(MemSlot),
    /// Register an ioeventfd
    IoEvent {
        evt: Event,
        allocation: Alloc,
        offset: u64,
        datamatch: Datamatch,
        register: bool,
    },
}

/// Struct for managing `VmMemoryRequest`s IOMMU related state.
pub struct VmMemoryRequestIommuClient<'a> {
    tube: &'a Tube,
    gpu_memory: BTreeSet<MemSlot>,
}

impl<'a> VmMemoryRequestIommuClient<'a> {
    /// Constructs `VmMemoryRequestIommuClient` from a tube for communication with the viommu.
    pub fn new(tube: &'a Tube) -> Self {
        Self {
            tube,
            gpu_memory: BTreeSet::new(),
        }
    }
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
        vm: &mut impl Vm,
        sys_allocator: &mut SystemAllocator,
        gralloc: &mut RutabagaGralloc,
        iommu_client: Option<&mut VmMemoryRequestIommuClient>,
    ) -> VmMemoryResponse {
        use self::VmMemoryRequest::*;
        match self {
            RegisterMemory { source, dest, prot } => {
                // Correct on Windows because callers of this IPC guarantee descriptor is a mapping
                // handle.
                let (mapped_region, size, descriptor) = match source.map(gralloc, prot) {
                    Ok((region, size, descriptor)) => (region, size, descriptor),
                    Err(e) => return VmMemoryResponse::Err(e),
                };

                let guest_addr = match dest.allocate(sys_allocator, size) {
                    Ok(addr) => addr,
                    Err(e) => return VmMemoryResponse::Err(e),
                };

                let slot = match vm.add_memory_region(
                    guest_addr,
                    mapped_region,
                    prot == Protection::read(),
                    false,
                ) {
                    Ok(slot) => slot,
                    Err(e) => return VmMemoryResponse::Err(e),
                };

                if let (Some(descriptor), Some(iommu_client)) = (descriptor, iommu_client) {
                    let request =
                        VirtioIOMMURequest::VfioCommand(VirtioIOMMUVfioCommand::VfioDmabufMap {
                            mem_slot: slot,
                            gfn: guest_addr.0 >> 12,
                            size,
                            dma_buf: descriptor,
                        });

                    match virtio_iommu_request(iommu_client.tube, &request) {
                        Ok(VirtioIOMMUResponse::VfioResponse(VirtioIOMMUVfioResult::Ok)) => (),
                        resp => {
                            error!("Unexpected message response: {:?}", resp);
                            // Ignore the result because there is nothing we can do with a failure.
                            let _ = vm.remove_memory_region(slot);
                            return VmMemoryResponse::Err(SysError::new(EINVAL));
                        }
                    };

                    iommu_client.gpu_memory.insert(slot);
                }

                let pfn = guest_addr.0 >> 12;
                VmMemoryResponse::RegisterMemory { pfn, slot }
            }
            UnregisterMemory(slot) => match vm.remove_memory_region(slot) {
                Ok(_) => {
                    if let Some(iommu_client) = iommu_client {
                        if iommu_client.gpu_memory.remove(&slot) {
                            let request = VirtioIOMMURequest::VfioCommand(
                                VirtioIOMMUVfioCommand::VfioDmabufUnmap(slot),
                            );

                            match virtio_iommu_request(iommu_client.tube, &request) {
                                Ok(VirtioIOMMUResponse::VfioResponse(
                                    VirtioIOMMUVfioResult::Ok,
                                )) => VmMemoryResponse::Ok,
                                resp => {
                                    error!("Unexpected message response: {:?}", resp);
                                    VmMemoryResponse::Err(SysError::new(EINVAL))
                                }
                            }
                        } else {
                            VmMemoryResponse::Ok
                        }
                    } else {
                        VmMemoryResponse::Ok
                    }
                }
                Err(e) => VmMemoryResponse::Err(e),
            },
            DynamicallyFreeMemoryRange {
                guest_address,
                size,
            } => match vm.handle_inflate(guest_address, size) {
                Ok(_) => VmMemoryResponse::Ok,
                Err(e) => VmMemoryResponse::Err(e),
            },
            DynamicallyReclaimMemoryRange {
                guest_address,
                size,
            } => match vm.handle_deflate(guest_address, size) {
                Ok(_) => VmMemoryResponse::Ok,
                Err(e) => VmMemoryResponse::Err(e),
            },
            IoEvent {
                evt,
                allocation,
                offset,
                datamatch,
                register,
            } => {
                let len = match datamatch {
                    Datamatch::AnyLength => 1,
                    Datamatch::U8(_) => 1,
                    Datamatch::U16(_) => 2,
                    Datamatch::U32(_) => 4,
                    Datamatch::U64(_) => 8,
                };
                let addr = match sys_allocator
                    .mmio_allocator_any()
                    .address_from_pci_offset(allocation, offset, len)
                {
                    Ok(addr) => addr,
                    Err(e) => {
                        error!("error getting target address: {:#}", e);
                        return VmMemoryResponse::Err(SysError::new(EINVAL));
                    }
                };
                let res = if register {
                    vm.register_ioevent(&evt, IoEventAddress::Mmio(addr), datamatch)
                } else {
                    vm.unregister_ioevent(&evt, IoEventAddress::Mmio(addr), datamatch)
                };
                match res {
                    Ok(_) => VmMemoryResponse::Ok,
                    Err(e) => VmMemoryResponse::Err(e),
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum VmMemoryResponse {
    /// The request to register memory into guest address space was successfully done at page frame
    /// number `pfn` and memory slot number `slot`.
    RegisterMemory {
        pfn: u64,
        slot: MemSlot,
    },
    Ok,
    Err(SysError),
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
    /// Add one msi route entry into the IRQ chip.
    AddMsiRoute {
        gsi: u32,
        msi_address: u64,
        msi_data: u32,
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
            AddMsiRoute {
                gsi,
                msi_address,
                msi_data,
            } => {
                let route = IrqRoute {
                    gsi,
                    source: IrqSource::Msi {
                        address: msi_address,
                        data: msi_data,
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
pub enum BatControlResult {
    Ok,
    NoBatDevice,
    NoSuchHealth,
    NoSuchProperty,
    NoSuchStatus,
    NoSuchBatType,
    StringParseIntErr,
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
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BatteryType {
    Goldfish,
}

impl Default for BatteryType {
    fn default() -> Self {
        BatteryType::Goldfish
    }
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
            _ => Err(BatControlResult::NoSuchProperty),
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
        }
    }
}

/// Used for VM to control battery properties.
pub struct BatControl {
    pub type_: BatteryType,
    pub control_tube: Tube,
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
#[derive(Serialize, Deserialize, Debug)]
pub enum PvClockCommand {
    Suspend,
    Resume,
}

/// Message used by virtio-pvclock to communicate command results.
#[derive(Serialize, Deserialize, Debug)]
pub enum PvClockCommandResponse {
    Ok,
    Err(SysError),
}

/// Commands for vmm-swap feature
#[derive(Serialize, Deserialize, Debug)]
pub enum SwapCommand {
    Enable,
    SwapOut,
    Disable,
    Status,
}

cfg_if::cfg_if! {
    if #[cfg(feature = "swap")] {
        use swap::Status as SwapStatus;
    } else {
        #[derive(Serialize, Deserialize, Debug, Clone)]
        pub enum SwapStatus {}
    }
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
    /// Suspend the VM's VCPUs until resume.
    Suspend,
    /// Swap the memory content into files on a disk
    Swap(SwapCommand),
    /// Resume the VM's VCPUs that were previously suspended.
    Resume,
    /// Inject a general-purpose event.
    Gpe(u32),
    /// Inject a PCI PME
    PciPme(u16),
    /// Make the VM's RT VCPU real-time.
    MakeRT,
    /// Command for balloon driver.
    BalloonCommand(BalloonControlCommand),
    /// Send a command to a disk chosen by `disk_index`.
    /// `disk_index` is a 0-based count of `--disk`, `--rwdisk`, and `-r` command-line options.
    DiskCommand {
        disk_index: usize,
        command: DiskControlCommand,
    },
    /// Command to use controller.
    UsbCommand(UsbControlCommand),
    #[cfg(feature = "gpu")]
    /// Command to modify the gpu.
    GpuCommand(GpuControlCommand),
    /// Command to set battery.
    BatCommand(BatteryType, BatControlCommand),
    /// Command to add/remove multiple pci devices
    HotPlugCommand {
        device: HotPlugDeviceInfo,
        add: bool,
    },
    /// Command to Snapshot devices
    Snapshot(SnapshotCommand),
    /// Command to Restore devices
    Restore(RestoreCommand),
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
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum RegisteredEvent {
    VirtioBalloonWssReport,
    VirtioBalloonResize,
    VirtioBalloonOOMDeflation,
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
// In this function, there may be a time where vCPUs are not
fn get_vcpu_state(
    kick_vcpus: impl Fn(VcpuControl),
    state_from_vcpu_channel: &mpsc::Receiver<VmRunMode>,
    vcpu_num: usize,
) -> anyhow::Result<VmRunMode> {
    kick_vcpus(VcpuControl::GetStates);
    if vcpu_num == 0 {
        bail!("vcpu_num is zero");
    }
    let mut current_mode_vec: Vec<VmRunMode> = Vec::new();
    for _ in 0..vcpu_num {
        match state_from_vcpu_channel.recv() {
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
    /// * `state_from_vcpu_channel` - A channel to collect each vCPU state.
    /// * `vcpu_num` - The number of vCPUs.
    pub fn new(
        kick_vcpus: &'a impl Fn(VcpuControl),
        state_from_vcpu_channel: &mpsc::Receiver<VmRunMode>,
        vcpu_num: usize,
    ) -> anyhow::Result<Self> {
        // get initial vcpu state
        let saved_run_mode = get_vcpu_state(kick_vcpus, state_from_vcpu_channel, vcpu_num)?;
        match saved_run_mode {
            VmRunMode::Running => {
                kick_vcpus(VcpuControl::RunState(VmRunMode::Suspending));
                // Blocking call, waiting for response to ensure vCPU state was updated.
                // In case of failure, where a vCPU still has the state running, start up vcpus and
                // abort operation.
                let current_mode = get_vcpu_state(kick_vcpus, state_from_vcpu_channel, vcpu_num)?;
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

impl VmRequest {
    /// Executes this request on the given Vm and other mutable state.
    ///
    /// This does not return a result, instead encapsulating the success or failure in a
    /// `VmResponse` with the intended purpose of sending the response back over the  socket that
    /// received this `VmRequest`.
    pub fn execute(
        &self,
        run_mode: &mut Option<VmRunMode>,
        #[cfg(feature = "balloon")] balloon_host_tube: Option<&Tube>,
        #[cfg(feature = "balloon")] balloon_stats_id: &mut u64,
        disk_host_tubes: &[Tube],
        pm: &mut Option<Arc<Mutex<dyn PmResource + Send>>>,
        #[cfg(feature = "gpu")] gpu_control_tube: &Tube,
        usb_control_tube: Option<&Tube>,
        bat_control: &mut Option<BatControl>,
        kick_vcpus: impl Fn(VcpuControl),
        force_s2idle: bool,
        #[cfg(feature = "swap")] swap_controller: Option<&swap::SwapController>,
        device_control_tube: &Tube,
        state_from_vcpu_channel: &mpsc::Receiver<VmRunMode>,
        vcpu_size: usize,
        irq_handler_control: &Tube,
    ) -> VmResponse {
        match *self {
            VmRequest::Exit => {
                *run_mode = Some(VmRunMode::Exiting);
                VmResponse::Ok
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
            VmRequest::Suspend => {
                *run_mode = Some(VmRunMode::Suspending);
                VmResponse::Ok
            }
            VmRequest::Swap(SwapCommand::Enable) => {
                #[cfg(feature = "swap")]
                if let Some(swap_controller) = swap_controller {
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
            VmRequest::Swap(SwapCommand::Disable) => {
                #[cfg(feature = "swap")]
                if let Some(swap_controller) = swap_controller {
                    return match swap_controller.disable() {
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
            VmRequest::Resume => {
                *run_mode = Some(VmRunMode::Running);

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

                VmResponse::Ok
            }
            VmRequest::Gpe(gpe) => {
                if let Some(pm) = pm.as_ref() {
                    pm.lock().gpe_evt(gpe);
                    VmResponse::Ok
                } else {
                    error!("{:#?} not supported", *self);
                    VmResponse::Err(SysError::new(ENOTSUP))
                }
            }
            VmRequest::PciPme(requester_id) => {
                if let Some(pm) = pm.as_ref() {
                    pm.lock().pme_evt(requester_id);
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
            VmRequest::BalloonCommand(BalloonControlCommand::Adjust { num_bytes }) => {
                if let Some(balloon_host_tube) = balloon_host_tube {
                    match balloon_host_tube.send(&BalloonTubeCommand::Adjust {
                        num_bytes,
                        allow_failure: false,
                    }) {
                        Ok(_) => VmResponse::Ok,
                        Err(_) => VmResponse::Err(SysError::last()),
                    }
                } else {
                    VmResponse::Err(SysError::new(ENOTSUP))
                }
            }
            #[cfg(feature = "balloon")]
            VmRequest::BalloonCommand(BalloonControlCommand::Stats) => {
                if let Some(balloon_host_tube) = balloon_host_tube {
                    // NB: There are a few reasons stale balloon stats could be left
                    // in balloon_host_tube:
                    //  - the send succeeds, but the recv fails because the device
                    //      is not ready yet. So when the device is ready, there are
                    //      extra stats requests queued.
                    //  - the send succeed, but the recv times out. When the device
                    //      does return the stats, there will be no consumer.
                    //
                    // To guard against this, add an `id` to the stats request. If
                    // the id returned to us doesn't match, we keep trying to read
                    // until it does.
                    *balloon_stats_id = (*balloon_stats_id).wrapping_add(1);
                    let sent_id = *balloon_stats_id;
                    match balloon_host_tube.send(&BalloonTubeCommand::Stats { id: sent_id }) {
                        Ok(_) => {
                            loop {
                                match balloon_host_tube.recv() {
                                    Ok(BalloonTubeResult::Stats {
                                        stats,
                                        balloon_actual,
                                        id,
                                    }) => {
                                        if sent_id != id {
                                            // Keep trying to get the fresh stats.
                                            continue;
                                        }
                                        break VmResponse::BalloonStats {
                                            stats,
                                            balloon_actual,
                                        };
                                    }
                                    Err(e) => {
                                        error!("balloon socket recv failed: {}", e);
                                        break VmResponse::Err(SysError::last());
                                    }
                                    Ok(BalloonTubeResult::Adjusted { .. }) => {
                                        unreachable!("unexpected adjusted response")
                                    }
                                }
                            }
                        }
                        Err(_) => VmResponse::Err(SysError::last()),
                    }
                } else {
                    VmResponse::Err(SysError::new(ENOTSUP))
                }
            }
            #[cfg(not(feature = "balloon"))]
            VmRequest::BalloonCommand(_) => VmResponse::Err(SysError::new(ENOTSUP)),
            VmRequest::DiskCommand {
                disk_index,
                ref command,
            } => match &disk_host_tubes.get(disk_index) {
                Some(tube) => handle_disk_command(command, tube),
                None => VmResponse::Err(SysError::new(ENODEV)),
            },
            #[cfg(feature = "gpu")]
            VmRequest::GpuCommand(ref cmd) => {
                let res = gpu_control_tube.send(cmd);
                if let Err(e) = res {
                    error!("fail to send command to gpu control socket: {}", e);
                    return VmResponse::Err(SysError::new(EIO));
                }
                match gpu_control_tube.recv() {
                    Ok(response) => VmResponse::GpuResponse(response),
                    Err(e) => {
                        error!("fail to recv command from gpu control socket: {}", e);
                        VmResponse::Err(SysError::new(EIO))
                    }
                }
            }
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
                        if battery.type_ != type_ {
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
            VmRequest::HotPlugCommand { device: _, add: _ } => VmResponse::Ok,
            VmRequest::Snapshot(SnapshotCommand::Take { ref snapshot_path }) => {
                let f = || -> anyhow::Result<SnapshotControlResult> {
                    let _guard =
                        VcpuSuspendGuard::new(&kick_vcpus, state_from_vcpu_channel, vcpu_size)?;
                    device_control_tube
                        .send(&DeviceControlCommand::SnapshotDevices {
                            snapshot_path: snapshot_path.clone(),
                        })
                        .context("send command to devices control socket")?;
                    device_control_tube
                        .recv()
                        .context("receive from devices control socket")?;

                    // We want to flush all pending IRQs to the LAPICs. There are two cases:
                    //
                    // MSIs: these are directly delivered to the LAPIC. We must verify the handler
                    // thread cycles once to deliver these interrupts.
                    //
                    // Legacy interrupts: in the case of a split IRQ chip, these interrupts may
                    // flow through the userspace IOAPIC. If the hypervisor does not support
                    // irqfds (e.g. WHPX), a single iteration will only flush the IRQ to the
                    // IOAPIC. The underlying MSI will be asserted at this point, but if the
                    // IRQ handler doesn't run another iteration, it won't be delivered to the
                    // LAPIC. This is why we cycle the handler thread twice (doing so ensures we
                    // process the underlying MSI).
                    //
                    // We can handle both of these cases by iterating until there are no tokens
                    // serviced on the requested iteration. Note that in the legacy case, this
                    // ensures at least two iterations.
                    //
                    // Note: within CrosVM, *all* interrupts are eventually converted into the
                    // same mechanicism that MSIs use. This is why we say "underlying" MSI for
                    // a legacy IRQ.
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
                        }
                        flush_attempts += 1;
                        if flush_attempts > EXPECTED_MAX_IRQ_FLUSH_ITERATIONS {
                            warn!("flushing IRQs for snapshot may be stalled after iteration {}, expected <= {} iterations", flush_attempts, EXPECTED_MAX_IRQ_FLUSH_ITERATIONS);
                        }
                    }
                    info!("flushed IRQs in {} iterations", flush_attempts);

                    Ok(SnapshotControlResult::Ok)
                };
                match f() {
                    Ok(res) => VmResponse::SnapshotResponse(res),
                    Err(e) => {
                        error!("failed to handle snapshot: {:?}", e);
                        VmResponse::Err(SysError::new(EIO))
                    }
                }
            }
            VmRequest::Restore(RestoreCommand::Apply { ref restore_path }) => {
                let f = || {
                    let _guard =
                        VcpuSuspendGuard::new(&kick_vcpus, state_from_vcpu_channel, vcpu_size)?;
                    device_control_tube
                        .send(&DeviceControlCommand::RestoreDevices {
                            restore_path: restore_path.clone(),
                        })
                        .context("send command to devices control socket")?;
                    device_control_tube
                        .recv()
                        .context("receive from devices control socket")
                };
                match f() {
                    Ok(res) => VmResponse::RestoreResponse(res),
                    Err(e) => {
                        error!("failed to handle restore: {:?}", e);
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
        }
    }
}

/// Indication of success or failure of a `VmRequest`.
///
/// Success is usually indicated `VmResponse::Ok` unless there is data associated with the response.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[must_use]
pub enum VmResponse {
    /// Indicates the request was executed successfully.
    Ok,
    /// Indicates the request encountered some error during execution.
    Err(SysError),
    /// The request to register memory into guest address space was successfully done at page frame
    /// number `pfn` and memory slot number `slot`.
    RegisterMemory { pfn: u64, slot: u32 },
    /// Results of balloon control commands.
    BalloonStats {
        stats: BalloonStats,
        balloon_actual: u64,
    },
    /// Results of usb control commands.
    UsbResponse(UsbControlResult),
    #[cfg(feature = "gpu")]
    /// Results of gpu control commands.
    GpuResponse(GpuControlResult),
    /// Results of battery control commands.
    BatResponse(BatControlResult),
    /// Results of swap status command.
    SwapStatus(SwapStatus),
    /// Results of snapshot commands.
    SnapshotResponse(SnapshotControlResult),
    /// Results of restore commands.
    RestoreResponse(RestoreControlResult),
}

impl Display for VmResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::VmResponse::*;

        match self {
            Ok => write!(f, "ok"),
            Err(e) => write!(f, "error: {}", e),
            RegisterMemory { pfn, slot } => write!(
                f,
                "memory registered to page frame number {:#x} and memory slot {}",
                pfn, slot
            ),
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
            UsbResponse(result) => write!(f, "usb control request get result {:?}", result),
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
            SnapshotResponse(result) => write!(f, "snapshot control request result {:?}", result),
            RestoreResponse(result) => write!(f, "restore control request result {:?}", result),
        }
    }
}

/// Enum that comes from the Gpu device that will be received by the main event loop.
#[derive(Serialize, Deserialize, Debug)]
pub enum GpuSendToService {
    SendWindowState {
        window_event: Option<WindowEvent>,
        hwnd: usize,
        visibility: WindowVisibility,
        mode: WindowMode,
        aspect_ratio: AspectRatio,
        // TODO(b/203662783): Once we make the controller decide the initial size, this can be removed.
        initial_guest_display_size: DisplaySize,
        recommended_guest_display_density: GuestDisplayDensity,
    },
    SendExitWindowRequest,
    SendMouseModeState {
        mouse_mode: MouseMode,
    },
    SendGpuDevice {
        description: String,
    },
}

/// Enum that serves as a general purose Gpu device message that is sent to the main loop.
#[derive(Serialize, Deserialize, Debug)]
pub enum GpuSendToMain {
    // Send these messages to the controller.
    SendToService(GpuSendToService),
    // Send to Ac97 device to set mute state.
    MuteAc97(bool),
}

/// Enum to send control requests to all Ac97 audio devices.
#[derive(Serialize, Deserialize, Debug)]
pub enum Ac97Control {
    Mute(bool),
}

/// Enum that send controller Ipc requests from the main event loop to the GPU device.
#[derive(Serialize, Deserialize, Debug)]
pub enum ServiceSendToGpu {
    ShowWindow {
        mode: WindowMode,
        aspect_ratio: AspectRatio,
        guest_display_size: DisplaySize,
    },
    HideWindow,
    Shutdown,
    MouseInputMode {
        mouse_mode: MouseMode,
    },
}

#[cfg(test)]
mod tests {
    use base::Event;

    use super::*;

    #[test]
    fn sock_send_recv_event() {
        let (req, res) = Tube::pair().unwrap();
        let e1 = Event::new().unwrap();
        res.send(&e1).unwrap();

        let recv_event: Event = req.recv().unwrap();
        recv_event.signal().unwrap();
        e1.wait().unwrap();
    }
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
        mem_slot: MemSlot,
        gfn: u64,
        size: u64,
        dma_buf: SafeDescriptor,
    },
    // Unmap a dma-buf from vfio iommu table
    VfioDmabufUnmap(MemSlot),
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

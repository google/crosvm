// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Handles IPC for controlling the main VM process.
//!
//! The VM Control IPC protocol is synchronous, meaning that each `VmRequest` sent over a connection
//! will receive a `VmResponse` for that request next time data is received over that connection.
//!
//! The wire message format is a little-endian C-struct of fixed size, along with a file descriptor
//! if the request type expects one.

#[cfg(all(target_arch = "x86_64", feature = "gdb"))]
pub mod gdb;

pub mod client;

use std::convert::TryInto;
use std::fmt::{self, Display};
use std::fs::File;
use std::os::raw::c_int;
use std::path::PathBuf;
use std::result::Result as StdResult;
use std::str::FromStr;
use std::sync::{mpsc, Arc};

use std::thread::JoinHandle;

use remain::sorted;
use thiserror::Error;

use libc::{EINVAL, EIO, ENODEV, ENOTSUP, ERANGE};
use serde::{Deserialize, Serialize};

pub use balloon_control::BalloonStats;
use balloon_control::{BalloonTubeCommand, BalloonTubeResult};

use base::{
    error, with_as_descriptor, AsRawDescriptor, Error as SysError, Event, ExternalMapping,
    FromRawDescriptor, IntoRawDescriptor, Killable, MappedRegion, MemoryMappingArena,
    MemoryMappingBuilder, MemoryMappingBuilderUnix, MmapError, Protection, Result, SafeDescriptor,
    SharedMemory, Tube, SIGRTMIN,
};
use hypervisor::{IrqRoute, IrqSource, Vm};
use resources::{Alloc, MmioType, SystemAllocator};
use rutabaga_gfx::{
    DrmFormat, ImageAllocationInfo, RutabagaGralloc, RutabagaGrallocFlags, RutabagaHandle,
    VulkanInfo,
};
use sync::Mutex;
use vm_memory::GuestAddress;

/// Struct that describes the offset and stride of a plane located in GPU memory.
#[derive(Clone, Copy, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct GpuMemoryPlaneDesc {
    pub stride: u32,
    pub offset: u32,
}

/// Struct that describes a GPU memory allocation that consists of up to 3 planes.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct GpuMemoryDesc {
    pub planes: [GpuMemoryPlaneDesc; 3],
}

#[cfg(all(target_arch = "x86_64", feature = "gdb"))]
pub use crate::gdb::*;
pub use hypervisor::MemSlot;

/// Control the state of a particular VM CPU.
#[derive(Clone, Debug)]
pub enum VcpuControl {
    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    Debug(VcpuDebug),
    RunState(VmRunMode),
    MakeRT,
}

/// Mode of execution for the VM.
#[derive(Debug, Clone, PartialEq)]
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

pub trait PmResource {
    fn pwrbtn_evt(&mut self) {}
    fn gpe_evt(&mut self, _gpe: u32) {}
    fn register_gpe_notify_dev(&mut self, _gpe: u32, _notify_dev: Arc<Mutex<dyn GpeNotify>>) {}
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum DiskControlResult {
    Ok,
    Err(SysError),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum UsbControlCommand {
    AttachDevice {
        bus: u8,
        addr: u8,
        vid: u16,
        pid: u16,
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

#[derive(Serialize, Deserialize, Debug)]
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

/// Source of a `VmMemoryRequest::RegisterMemory` mapping.
#[derive(Serialize, Deserialize)]
pub enum VmMemorySource {
    /// Register shared memory represented by the given descriptor.
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
        physical_device_idx: u32,
        size: u64,
    },
    /// Register the current rutabaga external mapping.
    ExternalMapping { size: u64 },
}

impl VmMemorySource {
    /// Map the resource and return its mapping and size in bytes.
    pub fn map(
        self,
        map_request: Arc<Mutex<Option<ExternalMapping>>>,
        gralloc: &mut RutabagaGralloc,
        read_only: bool,
    ) -> Result<(Box<dyn MappedRegion>, u64)> {
        let (mem_region, size) = match self {
            VmMemorySource::Descriptor {
                descriptor,
                offset,
                size,
            } => (map_descriptor(&descriptor, offset, size, read_only)?, size),
            VmMemorySource::SharedMemory(shm) => {
                (map_descriptor(&shm, 0, shm.size(), read_only)?, shm.size())
            }
            VmMemorySource::Vulkan {
                descriptor,
                handle_type,
                memory_idx,
                physical_device_idx,
                size,
            } => {
                let mapped_region = match gralloc.import_and_map(
                    RutabagaHandle {
                        os_handle: descriptor,
                        handle_type,
                    },
                    VulkanInfo {
                        memory_idx,
                        physical_device_idx,
                    },
                    size,
                ) {
                    Ok(mapped_region) => mapped_region,
                    Err(e) => {
                        error!("gralloc failed to import and map: {}", e);
                        return Err(SysError::new(EINVAL));
                    }
                };
                (mapped_region, size)
            }
            VmMemorySource::ExternalMapping { size } => {
                let mem = map_request
                    .lock()
                    .take()
                    .ok_or_else(|| VmMemoryResponse::Err(SysError::new(EINVAL)))
                    .unwrap();
                let mapped_region: Box<dyn MappedRegion> = Box::new(mem);
                (mapped_region, size)
            }
        };
        Ok((mem_region, size))
    }
}

/// Destination of a `VmMemoryRequest::RegisterMemory` mapping in guest address space.
#[derive(Serialize, Deserialize)]
pub enum VmMemoryDestination {
    /// Map at an offset within an existing PCI BAR allocation.
    ExistingAllocation { allocation: Alloc, offset: u64 },
    /// Create a new anonymous allocation in MMIO space.
    NewAllocation,
    /// Map at the specified guest physical address.
    GuestPhysicalAddress(u64),
}

impl VmMemoryDestination {
    /// Allocate and return the guest address of a memory mapping destination.
    pub fn allocate(self, allocator: &mut SystemAllocator, size: u64) -> Result<GuestAddress> {
        let addr = match self {
            VmMemoryDestination::ExistingAllocation { allocation, offset } => allocator
                .mmio_allocator(MmioType::High)
                .address_from_pci_offset(allocation, offset, size)
                .map_err(|_e| SysError::new(EINVAL))?,
            VmMemoryDestination::NewAllocation => {
                let alloc = allocator.get_anon_alloc();
                allocator
                    .mmio_allocator(MmioType::High)
                    .allocate(size, alloc, "vmcontrol_register_memory".to_string())
                    .map_err(|_e| SysError::new(EINVAL))?
            }
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
        read_only: bool,
    },
    /// Allocate GPU buffer of a given size/format and register the memory into guest address space.
    /// The response variant is `VmResponse::AllocateAndRegisterGpuMemory`
    AllocateAndRegisterGpuMemory {
        width: u32,
        height: u32,
        format: u32,
        /// Where to map the memory in the guest.
        dest: VmMemoryDestination,
    },
    /// Unregister the given memory slot that was previously registered with `RegisterMemory`.
    UnregisterMemory(MemSlot),
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
        map_request: Arc<Mutex<Option<ExternalMapping>>>,
        gralloc: &mut RutabagaGralloc,
    ) -> VmMemoryResponse {
        use self::VmMemoryRequest::*;
        match self {
            RegisterMemory {
                source,
                dest,
                read_only,
            } => {
                let (mapped_region, size) = match source.map(map_request, gralloc, read_only) {
                    Ok((region, size)) => (region, size),
                    Err(e) => return VmMemoryResponse::Err(e),
                };

                let guest_addr = match dest.allocate(sys_allocator, size) {
                    Ok(addr) => addr,
                    Err(e) => return VmMemoryResponse::Err(e),
                };

                let slot = match vm.add_memory_region(guest_addr, mapped_region, read_only, false) {
                    Ok(slot) => slot,
                    Err(e) => return VmMemoryResponse::Err(e),
                };
                let pfn = guest_addr.0 >> 12;
                VmMemoryResponse::RegisterMemory { pfn, slot }
            }
            UnregisterMemory(slot) => match vm.remove_memory_region(slot) {
                Ok(_) => VmMemoryResponse::Ok,
                Err(e) => VmMemoryResponse::Err(e),
            },
            AllocateAndRegisterGpuMemory {
                width,
                height,
                format,
                dest,
            } => {
                let (mapped_region, size, descriptor, gpu_desc) =
                    match Self::allocate_gpu_memory(gralloc, width, height, format) {
                        Ok(v) => v,
                        Err(e) => return VmMemoryResponse::Err(e),
                    };

                let guest_addr = match dest.allocate(sys_allocator, size) {
                    Ok(addr) => addr,
                    Err(e) => return VmMemoryResponse::Err(e),
                };

                let slot = match vm.add_memory_region(guest_addr, mapped_region, false, false) {
                    Ok(slot) => slot,
                    Err(e) => return VmMemoryResponse::Err(e),
                };
                let pfn = guest_addr.0 >> 12;

                VmMemoryResponse::AllocateAndRegisterGpuMemory {
                    descriptor,
                    pfn,
                    slot,
                    desc: gpu_desc,
                }
            }
        }
    }

    fn allocate_gpu_memory(
        gralloc: &mut RutabagaGralloc,
        width: u32,
        height: u32,
        format: u32,
    ) -> Result<(Box<dyn MappedRegion>, u64, SafeDescriptor, GpuMemoryDesc)> {
        let img = ImageAllocationInfo {
            width,
            height,
            drm_format: DrmFormat::from(format),
            // Linear layout is a requirement as virtio wayland guest expects
            // this for CPU access to the buffer. Scanout and texturing are
            // optional as the consumer (wayland compositor) is expected to
            // fall-back to a less efficient meachnisms for presentation if
            // neccesary. In practice, linear buffers for commonly used formats
            // will also support scanout and texturing.
            flags: RutabagaGrallocFlags::empty().use_linear(true),
        };

        let reqs = match gralloc.get_image_memory_requirements(img) {
            Ok(reqs) => reqs,
            Err(e) => {
                error!("gralloc failed to get image requirements: {}", e);
                return Err(SysError::new(EINVAL));
            }
        };

        let handle = match gralloc.allocate_memory(reqs) {
            Ok(handle) => handle,
            Err(e) => {
                error!("gralloc failed to allocate memory: {}", e);
                return Err(SysError::new(EINVAL));
            }
        };

        let mut desc = GpuMemoryDesc::default();
        for i in 0..3 {
            desc.planes[i] = GpuMemoryPlaneDesc {
                stride: reqs.strides[i],
                offset: reqs.offsets[i],
            }
        }

        // Safe because ownership is transferred to SafeDescriptor via
        // into_raw_descriptor
        let descriptor =
            unsafe { SafeDescriptor::from_raw_descriptor(handle.os_handle.into_raw_descriptor()) };

        let mapped_region = map_descriptor(&descriptor, 0, reqs.size, false)?;
        Ok((mapped_region, reqs.size, descriptor, desc))
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
    /// The request to allocate and register GPU memory into guest address space was successfully
    /// done at page frame number `pfn` and memory slot number `slot` for buffer with `desc`.
    AllocateAndRegisterGpuMemory {
        descriptor: SafeDescriptor,
        pfn: u64,
        slot: MemSlot,
        desc: GpuMemoryDesc,
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

#[derive(Serialize, Deserialize, Debug)]
pub enum VmMsyncRequest {
    /// Flush the content of a memory mapping to its backing file.
    /// `slot` selects the arena (as returned by `Vm::add_mmap_arena`).
    /// `offset` is the offset of the mapping to sync within the arena.
    /// `size` is the size of the mapping to sync within the arena.
    MsyncArena {
        slot: MemSlot,
        offset: usize,
        size: usize,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum VmMsyncResponse {
    Ok,
    Err(SysError),
}

impl VmMsyncRequest {
    /// Executes this request on the given Vm.
    ///
    /// # Arguments
    /// * `vm` - The `Vm` to perform the request on.
    ///
    /// This does not return a result, instead encapsulating the success or failure in a
    /// `VmMsyncResponse` with the intended purpose of sending the response back over the socket
    /// that received this `VmMsyncResponse`.
    pub fn execute(&self, vm: &mut impl Vm) -> VmMsyncResponse {
        use self::VmMsyncRequest::*;
        match *self {
            MsyncArena { slot, offset, size } => match vm.msync_memory_region(slot, offset, size) {
                Ok(()) => VmMsyncResponse::Ok,
                Err(e) => VmMsyncResponse::Err(e),
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
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

#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq)]
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

#[derive(Serialize, Deserialize, Debug)]
pub enum FsMappingRequest {
    /// Create an anonymous memory mapping that spans the entire region described by `Alloc`.
    AllocateSharedMemoryRegion(Alloc),
    /// Create a memory mapping.
    CreateMemoryMapping {
        /// The slot for a MemoryMappingArena, previously returned by a response to an
        /// `AllocateSharedMemoryRegion` request.
        slot: u32,
        /// The file descriptor that should be mapped.
        fd: SafeDescriptor,
        /// The size of the mapping.
        size: usize,
        /// The offset into the file from where the mapping should start.
        file_offset: u64,
        /// The memory protection to be used for the mapping.  Protections other than readable and
        /// writable will be silently dropped.
        prot: u32,
        /// The offset into the shared memory region where the mapping should be placed.
        mem_offset: usize,
    },
    /// Remove a memory mapping.
    RemoveMemoryMapping {
        /// The slot for a MemoryMappingArena.
        slot: u32,
        /// The offset into the shared memory region.
        offset: usize,
        /// The size of the mapping.
        size: usize,
    },
}

impl FsMappingRequest {
    pub fn execute(&self, vm: &mut dyn Vm, allocator: &mut SystemAllocator) -> VmResponse {
        use self::FsMappingRequest::*;
        match *self {
            AllocateSharedMemoryRegion(Alloc::PciBar {
                bus,
                dev,
                func,
                bar,
            }) => {
                match allocator
                    .mmio_allocator(MmioType::High)
                    .get(&Alloc::PciBar {
                        bus,
                        dev,
                        func,
                        bar,
                    }) {
                    Some((addr, length, _)) => {
                        let arena = match MemoryMappingArena::new(*length as usize) {
                            Ok(a) => a,
                            Err(MmapError::SystemCallFailed(e)) => return VmResponse::Err(e),
                            _ => return VmResponse::Err(SysError::new(EINVAL)),
                        };

                        match vm.add_memory_region(
                            GuestAddress(*addr),
                            Box::new(arena),
                            false,
                            false,
                        ) {
                            Ok(slot) => VmResponse::RegisterMemory {
                                pfn: addr >> 12,
                                slot,
                            },
                            Err(e) => VmResponse::Err(e),
                        }
                    }
                    None => VmResponse::Err(SysError::new(EINVAL)),
                }
            }
            CreateMemoryMapping {
                slot,
                ref fd,
                size,
                file_offset,
                prot,
                mem_offset,
            } => {
                match vm.add_fd_mapping(
                    slot,
                    mem_offset,
                    size,
                    fd,
                    file_offset,
                    Protection::from(prot as c_int & (libc::PROT_READ | libc::PROT_WRITE)),
                ) {
                    Ok(()) => VmResponse::Ok,
                    Err(e) => VmResponse::Err(e),
                }
            }
            RemoveMemoryMapping { slot, offset, size } => {
                match vm.remove_mapping(slot, offset, size) {
                    Ok(()) => VmResponse::Ok,
                    Err(e) => VmResponse::Err(e),
                }
            }
            _ => VmResponse::Err(SysError::new(EINVAL)),
        }
    }
}
/// A request to the main process to perform some operation on the VM.
///
/// Unless otherwise noted, each request should expect a `VmResponse::Ok` to be received on success.
#[derive(Serialize, Deserialize, Debug)]
pub enum VmRequest {
    /// Break the VM's run loop and exit.
    Exit,
    /// Trigger a power button event in the guest.
    Powerbtn,
    /// Suspend the VM's VCPUs until resume.
    Suspend,
    /// Resume the VM's VCPUs that were previously suspended.
    Resume,
    /// Inject a general-purpose event.
    Gpe(u32),
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
    /// Command to set battery.
    BatCommand(BatteryType, BatControlCommand),
    /// Command to add/remove vfio pci device
    VfioCommand { vfio_path: PathBuf, add: bool },
}

fn map_descriptor(
    descriptor: &dyn AsRawDescriptor,
    offset: u64,
    size: u64,
    read_only: bool,
) -> Result<Box<dyn MappedRegion>> {
    let size: usize = size.try_into().map_err(|_e| SysError::new(ERANGE))?;
    let prot = if read_only {
        Protection::read()
    } else {
        Protection::read_write()
    };
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

impl VmRequest {
    /// Executes this request on the given Vm and other mutable state.
    ///
    /// This does not return a result, instead encapsulating the success or failure in a
    /// `VmResponse` with the intended purpose of sending the response back over the  socket that
    /// received this `VmRequest`.
    pub fn execute(
        &self,
        run_mode: &mut Option<VmRunMode>,
        balloon_host_tube: Option<&Tube>,
        balloon_stats_id: &mut u64,
        disk_host_tubes: &[Tube],
        pm: &mut Option<Arc<Mutex<dyn PmResource>>>,
        usb_control_tube: Option<&Tube>,
        bat_control: &mut Option<BatControl>,
        vcpu_handles: &[(JoinHandle<()>, mpsc::Sender<VcpuControl>)],
    ) -> VmResponse {
        match *self {
            VmRequest::Exit => {
                *run_mode = Some(VmRunMode::Exiting);
                VmResponse::Ok
            }
            VmRequest::Powerbtn => {
                if pm.is_some() {
                    pm.as_ref().unwrap().lock().pwrbtn_evt();
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
            VmRequest::Resume => {
                *run_mode = Some(VmRunMode::Running);
                VmResponse::Ok
            }
            VmRequest::Gpe(gpe) => {
                if pm.is_some() {
                    pm.as_ref().unwrap().lock().gpe_evt(gpe);
                    VmResponse::Ok
                } else {
                    error!("{:#?} not supported", *self);
                    VmResponse::Err(SysError::new(ENOTSUP))
                }
            }
            VmRequest::MakeRT => {
                for (handle, channel) in vcpu_handles {
                    if let Err(e) = channel.send(VcpuControl::MakeRT) {
                        error!("failed to send MakeRT: {}", e);
                    }
                    let _ = handle.kill(SIGRTMIN() + 0);
                }
                VmResponse::Ok
            }
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
            VmRequest::DiskCommand {
                disk_index,
                ref command,
            } => {
                // Forward the request to the block device process via its control socket.
                if let Some(sock) = disk_host_tubes.get(disk_index) {
                    if let Err(e) = sock.send(command) {
                        error!("disk socket send failed: {}", e);
                        VmResponse::Err(SysError::new(EINVAL))
                    } else {
                        match sock.recv() {
                            Ok(DiskControlResult::Ok) => VmResponse::Ok,
                            Ok(DiskControlResult::Err(e)) => VmResponse::Err(e),
                            Err(e) => {
                                error!("disk socket recv failed: {}", e);
                                VmResponse::Err(SysError::new(EINVAL))
                            }
                        }
                    }
                } else {
                    VmResponse::Err(SysError::new(ENODEV))
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
            VmRequest::VfioCommand {
                vfio_path: _,
                add: _,
            } => VmResponse::Ok,
        }
    }
}

/// Indication of success or failure of a `VmRequest`.
///
/// Success is usually indicated `VmResponse::Ok` unless there is data associated with the response.
#[derive(Serialize, Deserialize, Debug)]
pub enum VmResponse {
    /// Indicates the request was executed successfully.
    Ok,
    /// Indicates the request encountered some error during execution.
    Err(SysError),
    /// The request to register memory into guest address space was successfully done at page frame
    /// number `pfn` and memory slot number `slot`.
    RegisterMemory { pfn: u64, slot: u32 },
    /// The request to allocate and register GPU memory into guest address space was successfully
    /// done at page frame number `pfn` and memory slot number `slot` for buffer with `desc`.
    AllocateAndRegisterGpuMemory {
        descriptor: SafeDescriptor,
        pfn: u64,
        slot: u32,
        desc: GpuMemoryDesc,
    },
    /// Results of balloon control commands.
    BalloonStats {
        stats: BalloonStats,
        balloon_actual: u64,
    },
    /// Results of usb control commands.
    UsbResponse(UsbControlResult),
    /// Results of battery control commands.
    BatResponse(BatControlResult),
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
            AllocateAndRegisterGpuMemory { pfn, slot, .. } => write!(
                f,
                "gpu memory allocated and registered to page frame number {:#x} and memory slot {}",
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
            BatResponse(result) => write!(f, "{}", result),
        }
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
        #[serde(with = "with_as_descriptor")]
        container: File,
    },
    // Delete the vfio device attached to virtio-iommu.
    VfioDeviceDel {
        endpoint_addr: u32,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum VirtioIOMMUVfioResult {
    Ok,
    NotInPCIRanges,
    NoAvailableContainer,
    NoSuchDevice,
}

impl Display for VirtioIOMMUVfioResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::VirtioIOMMUVfioResult::*;

        match self {
            Ok => write!(f, "successfully"),
            NotInPCIRanges => write!(f, "not in the pci ranges of virtio-iommu"),
            NoAvailableContainer => write!(f, "no available vfio container"),
            NoSuchDevice => write!(f, "no such a vfio device"),
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

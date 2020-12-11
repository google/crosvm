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

use std::fmt::{self, Display};
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::mem::ManuallyDrop;
use std::result::Result as StdResult;
use std::str::FromStr;
use std::sync::Arc;

use libc::{EINVAL, EIO, ENODEV};

use base::{
    error, AsRawDescriptor, Error as SysError, Event, ExternalMapping, FromRawDescriptor,
    IntoRawDescriptor, MappedRegion, MemoryMappingBuilder, MmapError, RawDescriptor, Result,
    SafeDescriptor,
};
use hypervisor::{IrqRoute, IrqSource, Vm};
use msg_socket::{MsgError, MsgOnSocket, MsgReceiver, MsgResult, MsgSender, MsgSocket};
use resources::{Alloc, GpuMemoryDesc, MmioType, SystemAllocator};
use sync::Mutex;
use vm_memory::GuestAddress;

#[cfg(all(target_arch = "x86_64", feature = "gdb"))]
pub use crate::gdb::*;
pub use hypervisor::MemSlot;

/// Control the state of a particular VM CPU.
#[derive(Debug)]
pub enum VcpuControl {
    #[cfg(all(target_arch = "x86_64", feature = "gdb"))]
    Debug(VcpuDebug),
    RunState(VmRunMode),
}

/// A file descriptor either borrowed or owned by this.
#[derive(Debug)]
pub enum MaybeOwnedDescriptor {
    /// Owned by this enum variant, and will be destructed automatically if not moved out.
    Owned(SafeDescriptor),
    /// A file descriptor borrwed by this enum.
    Borrowed(RawDescriptor),
}

impl AsRawDescriptor for MaybeOwnedDescriptor {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        match self {
            MaybeOwnedDescriptor::Owned(f) => f.as_raw_descriptor(),
            MaybeOwnedDescriptor::Borrowed(descriptor) => *descriptor,
        }
    }
}

impl AsRawDescriptor for &MaybeOwnedDescriptor {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        match self {
            MaybeOwnedDescriptor::Owned(f) => f.as_raw_descriptor(),
            MaybeOwnedDescriptor::Borrowed(descriptor) => *descriptor,
        }
    }
}

// When sent, it could be owned or borrowed. On the receiver end, it always owned.
impl MsgOnSocket for MaybeOwnedDescriptor {
    fn uses_descriptor() -> bool {
        true
    }
    fn fixed_size() -> Option<usize> {
        Some(0)
    }
    fn descriptor_count(&self) -> usize {
        1usize
    }
    unsafe fn read_from_buffer(
        buffer: &[u8],
        descriptors: &[RawDescriptor],
    ) -> MsgResult<(Self, usize)> {
        let (file, size) = File::read_from_buffer(buffer, descriptors)?;
        let safe_descriptor = SafeDescriptor::from_raw_descriptor(file.into_raw_descriptor());
        Ok((MaybeOwnedDescriptor::Owned(safe_descriptor), size))
    }
    fn write_to_buffer(
        &self,
        _buffer: &mut [u8],
        descriptors: &mut [RawDescriptor],
    ) -> MsgResult<usize> {
        if descriptors.is_empty() {
            return Err(MsgError::WrongDescriptorBufferSize);
        }

        descriptors[0] = self.as_raw_descriptor();
        Ok(1)
    }
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

/// The maximum number of devices that can be listed in one `UsbControlCommand`.
///
/// This value was set to be equal to `xhci_regs::MAX_PORTS` for convenience, but it is not
/// necessary for correctness. Importing that value directly would be overkill because it would
/// require adding a big dependency for a single const.
pub const USB_CONTROL_MAX_PORTS: usize = 16;

#[derive(MsgOnSocket, Debug)]
pub enum BalloonControlCommand {
    /// Set the size of the VM's balloon.
    Adjust {
        num_bytes: u64,
    },
    Stats,
}

// BalloonStats holds stats returned from the stats_queue.
#[derive(Default, MsgOnSocket, Debug)]
pub struct BalloonStats {
    pub swap_in: Option<u64>,
    pub swap_out: Option<u64>,
    pub major_faults: Option<u64>,
    pub minor_faults: Option<u64>,
    pub free_memory: Option<u64>,
    pub total_memory: Option<u64>,
    pub available_memory: Option<u64>,
    pub disk_caches: Option<u64>,
    pub hugetlb_allocations: Option<u64>,
    pub hugetlb_failures: Option<u64>,
}

impl Display for BalloonStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{")?;
        if let Some(swap_in) = self.swap_in {
            write!(f, "\n    swap_in: {}", swap_in)?;
        }
        if let Some(swap_out) = self.swap_out {
            write!(f, "\n    swap_out: {}", swap_out)?;
        }
        if let Some(major_faults) = self.major_faults {
            write!(f, "\n    major_faults: {}", major_faults)?;
        }
        if let Some(minor_faults) = self.minor_faults {
            write!(f, "\n    minor_faults: {}", minor_faults)?;
        }
        if let Some(free_memory) = self.free_memory {
            write!(f, "\n    free_memory: {}", free_memory)?;
        }
        if let Some(total_memory) = self.total_memory {
            write!(f, "\n    total_memory: {}", total_memory)?;
        }
        if let Some(available_memory) = self.available_memory {
            write!(f, "\n    available_memory: {}", available_memory)?;
        }
        if let Some(disk_caches) = self.disk_caches {
            write!(f, "\n    disk_caches: {}", disk_caches)?;
        }
        if let Some(hugetlb_allocations) = self.hugetlb_allocations {
            write!(f, "\n    hugetlb_allocations: {}", hugetlb_allocations)?;
        }
        if let Some(hugetlb_failures) = self.hugetlb_failures {
            write!(f, "\n    hugetlb_failures: {}", hugetlb_failures)?;
        }
        write!(f, "\n}}")
    }
}

#[derive(MsgOnSocket, Debug)]
pub enum BalloonControlResult {
    Stats {
        stats: BalloonStats,
        balloon_actual: u64,
    },
}

#[derive(MsgOnSocket, Debug)]
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

#[derive(MsgOnSocket, Debug)]
pub enum DiskControlResult {
    Ok,
    Err(SysError),
}

#[derive(MsgOnSocket, Debug)]
pub enum UsbControlCommand {
    AttachDevice {
        bus: u8,
        addr: u8,
        vid: u16,
        pid: u16,
        descriptor: Option<MaybeOwnedDescriptor>,
    },
    DetachDevice {
        port: u8,
    },
    ListDevice {
        ports: [u8; USB_CONTROL_MAX_PORTS],
    },
}

#[derive(MsgOnSocket, Copy, Clone, Debug, Default)]
pub struct UsbControlAttachedDevice {
    pub port: u8,
    pub vendor_id: u16,
    pub product_id: u16,
}

impl UsbControlAttachedDevice {
    fn valid(self) -> bool {
        self.port != 0
    }
}

#[derive(MsgOnSocket, Debug)]
pub enum UsbControlResult {
    Ok { port: u8 },
    NoAvailablePort,
    NoSuchDevice,
    NoSuchPort,
    FailedToOpenDevice,
    Devices([UsbControlAttachedDevice; USB_CONTROL_MAX_PORTS]),
}

impl Display for UsbControlResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::UsbControlResult::*;

        match self {
            Ok { port } => write!(f, "ok {}", port),
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
        }
    }
}

#[derive(MsgOnSocket, Debug)]
pub enum VmMemoryRequest {
    /// Register shared memory represented by the given descriptor into guest address space.
    /// The response variant is `VmResponse::RegisterMemory`.
    RegisterMemory(MaybeOwnedDescriptor, usize),
    /// Similiar to `VmMemoryRequest::RegisterMemory`, but doesn't allocate new address space.
    /// Useful for cases where the address space is already allocated (PCI regions).
    RegisterFdAtPciBarOffset(Alloc, MaybeOwnedDescriptor, usize, u64),
    /// Similar to RegisterFdAtPciBarOffset, but is for buffers in the current address space.
    RegisterHostPointerAtPciBarOffset(Alloc, u64),
    /// Unregister the given memory slot that was previously registered with `RegisterMemory*`.
    UnregisterMemory(MemSlot),
    /// Allocate GPU buffer of a given size/format and register the memory into guest address space.
    /// The response variant is `VmResponse::AllocateAndRegisterGpuMemory`
    AllocateAndRegisterGpuMemory {
        width: u32,
        height: u32,
        format: u32,
    },
    /// Register mmaped memory into the hypervisor's EPT.
    RegisterMmapMemory {
        descriptor: MaybeOwnedDescriptor,
        size: usize,
        offset: u64,
        gpa: u64,
    },
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
        &self,
        vm: &mut impl Vm,
        sys_allocator: &mut SystemAllocator,
        map_request: Arc<Mutex<Option<ExternalMapping>>>,
    ) -> VmMemoryResponse {
        use self::VmMemoryRequest::*;
        match *self {
            RegisterMemory(ref descriptor, size) => {
                match register_memory(vm, sys_allocator, descriptor, size, None) {
                    Ok((pfn, slot)) => VmMemoryResponse::RegisterMemory { pfn, slot },
                    Err(e) => VmMemoryResponse::Err(e),
                }
            }
            RegisterFdAtPciBarOffset(alloc, ref descriptor, size, offset) => {
                match register_memory(vm, sys_allocator, descriptor, size, Some((alloc, offset))) {
                    Ok((pfn, slot)) => VmMemoryResponse::RegisterMemory { pfn, slot },
                    Err(e) => VmMemoryResponse::Err(e),
                }
            }
            UnregisterMemory(slot) => match vm.remove_memory_region(slot) {
                Ok(_) => VmMemoryResponse::Ok,
                Err(e) => VmMemoryResponse::Err(e),
            },
            RegisterHostPointerAtPciBarOffset(alloc, offset) => {
                let mem = map_request
                    .lock()
                    .take()
                    .ok_or_else(|| VmMemoryResponse::Err(SysError::new(EINVAL)))
                    .unwrap();

                match register_memory_hva(vm, sys_allocator, Box::new(mem), (alloc, offset)) {
                    Ok((pfn, slot)) => VmMemoryResponse::RegisterMemory { pfn, slot },
                    Err(e) => VmMemoryResponse::Err(e),
                }
            }
            AllocateAndRegisterGpuMemory {
                width,
                height,
                format,
            } => {
                let (mut fd, desc) = match sys_allocator.gpu_memory_allocator() {
                    Some(gpu_allocator) => match gpu_allocator.allocate(width, height, format) {
                        Ok(v) => v,
                        Err(e) => return VmMemoryResponse::Err(e),
                    },
                    None => return VmMemoryResponse::Err(SysError::new(ENODEV)),
                };
                // Determine size of buffer using 0 byte seek from end. This is preferred over
                // `stride * height` as it's not limited to packed pixel formats.
                let size = match fd.seek(SeekFrom::End(0)) {
                    Ok(v) => v,
                    Err(e) => return VmMemoryResponse::Err(SysError::from(e)),
                };
                match register_memory(vm, sys_allocator, &fd, size as usize, None) {
                    Ok((pfn, slot)) => VmMemoryResponse::AllocateAndRegisterGpuMemory {
                        // Safe because ownership is transferred to SafeDescriptor via
                        // into_raw_descriptor
                        descriptor: MaybeOwnedDescriptor::Owned(unsafe {
                            SafeDescriptor::from_raw_descriptor(fd.into_raw_descriptor())
                        }),
                        pfn,
                        slot,
                        desc,
                    },
                    Err(e) => VmMemoryResponse::Err(e),
                }
            }
            RegisterMmapMemory {
                ref descriptor,
                size,
                offset,
                gpa,
            } => {
                let mmap = match MemoryMappingBuilder::new(size)
                    .from_descriptor(descriptor)
                    .offset(offset as u64)
                    .build()
                {
                    Ok(v) => v,
                    Err(_e) => return VmMemoryResponse::Err(SysError::new(EINVAL)),
                };
                match vm.add_memory_region(GuestAddress(gpa), Box::new(mmap), false, false) {
                    Ok(_) => VmMemoryResponse::Ok,
                    Err(e) => VmMemoryResponse::Err(e),
                }
            }
        }
    }
}

#[derive(MsgOnSocket, Debug)]
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
        descriptor: MaybeOwnedDescriptor,
        pfn: u64,
        slot: MemSlot,
        desc: GpuMemoryDesc,
    },
    Ok,
    Err(SysError),
}

#[derive(MsgOnSocket, Debug)]
pub enum VmIrqRequest {
    /// Allocate one gsi, and associate gsi to irqfd with register_irqfd()
    AllocateOneMsi { irqfd: MaybeOwnedDescriptor },
    /// Add one msi route entry into the IRQ chip.
    AddMsiRoute {
        gsi: u32,
        msi_address: u64,
        msi_data: u32,
    },
}

/// Data to set up an IRQ event or IRQ route on the IRQ chip.
/// VmIrqRequest::execute can't take an `IrqChip` argument, because of a dependency cycle between
/// devices and vm_control, so it takes a Fn that processes an `IrqSetup`.
pub enum IrqSetup<'a> {
    Event(u32, &'a Event),
    Route(IrqRoute),
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
            AllocateOneMsi { ref irqfd } => {
                if let Some(irq_num) = sys_allocator.allocate_irq() {
                    // Because of the limitation of `MaybeOwnedDescriptor` not fitting into
                    // `register_irqfd` which expects an `&Event`, we use the unsafe `from_raw_fd`
                    // to assume that the descriptor given is an `Event`, and we ignore the
                    // ownership question using `ManuallyDrop`. This is safe because `ManuallyDrop`
                    // prevents any Drop implementation from triggering on `irqfd` which already has
                    // an owner, and the `Event` methods are never called. The underlying descriptor
                    // is merely passed to the kernel which doesn't care about ownership and deals
                    // with incorrect FDs, in the case of bugs on our part.
                    let evt = unsafe {
                        ManuallyDrop::new(Event::from_raw_descriptor(irqfd.as_raw_descriptor()))
                    };

                    match set_up_irq(IrqSetup::Event(irq_num, &evt)) {
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
        }
    }
}

#[derive(MsgOnSocket, Debug)]
pub enum VmIrqResponse {
    AllocateOneMsi { gsi: u32 },
    Ok,
    Err(SysError),
}

#[derive(MsgOnSocket, Debug)]
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

#[derive(MsgOnSocket, Debug)]
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

#[derive(MsgOnSocket, Debug)]
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

#[derive(MsgOnSocket, Copy, Clone, Debug, PartialEq)]
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

#[derive(MsgOnSocket, Debug)]
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

#[derive(MsgOnSocket, Debug)]
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

#[derive(MsgOnSocket, Debug)]
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

#[derive(MsgOnSocket, Debug)]
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
    pub control_socket: BatControlRequestSocket,
}

pub type BalloonControlRequestSocket = MsgSocket<BalloonControlCommand, BalloonControlResult>;
pub type BalloonControlResponseSocket = MsgSocket<BalloonControlResult, BalloonControlCommand>;

pub type BatControlRequestSocket = MsgSocket<BatControlCommand, BatControlResult>;
pub type BatControlResponseSocket = MsgSocket<BatControlResult, BatControlCommand>;

pub type DiskControlRequestSocket = MsgSocket<DiskControlCommand, DiskControlResult>;
pub type DiskControlResponseSocket = MsgSocket<DiskControlResult, DiskControlCommand>;

pub type UsbControlSocket = MsgSocket<UsbControlCommand, UsbControlResult>;

pub type VmMemoryControlRequestSocket = MsgSocket<VmMemoryRequest, VmMemoryResponse>;
pub type VmMemoryControlResponseSocket = MsgSocket<VmMemoryResponse, VmMemoryRequest>;

pub type VmIrqRequestSocket = MsgSocket<VmIrqRequest, VmIrqResponse>;
pub type VmIrqResponseSocket = MsgSocket<VmIrqResponse, VmIrqRequest>;

pub type VmMsyncRequestSocket = MsgSocket<VmMsyncRequest, VmMsyncResponse>;
pub type VmMsyncResponseSocket = MsgSocket<VmMsyncResponse, VmMsyncRequest>;

pub type VmControlRequestSocket = MsgSocket<VmRequest, VmResponse>;
pub type VmControlResponseSocket = MsgSocket<VmResponse, VmRequest>;

/// A request to the main process to perform some operation on the VM.
///
/// Unless otherwise noted, each request should expect a `VmResponse::Ok` to be received on success.
#[derive(MsgOnSocket, Debug)]
pub enum VmRequest {
    /// Break the VM's run loop and exit.
    Exit,
    /// Suspend the VM's VCPUs until resume.
    Suspend,
    /// Resume the VM's VCPUs that were previously suspended.
    Resume,
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
}

fn register_memory(
    vm: &mut impl Vm,
    allocator: &mut SystemAllocator,
    descriptor: &dyn AsRawDescriptor,
    size: usize,
    pci_allocation: Option<(Alloc, u64)>,
) -> Result<(u64, MemSlot)> {
    let mmap = match MemoryMappingBuilder::new(size)
        .from_descriptor(descriptor)
        .build()
    {
        Ok(v) => v,
        Err(MmapError::SystemCallFailed(e)) => return Err(e),
        _ => return Err(SysError::new(EINVAL)),
    };

    let addr = match pci_allocation {
        Some(pci_allocation) => allocator
            .mmio_allocator(MmioType::High)
            .address_from_pci_offset(pci_allocation.0, pci_allocation.1, size as u64)
            .map_err(|_e| SysError::new(EINVAL))?,
        None => {
            let alloc = allocator.get_anon_alloc();
            allocator
                .mmio_allocator(MmioType::High)
                .allocate(size as u64, alloc, "vmcontrol_register_memory".to_string())
                .map_err(|_e| SysError::new(EINVAL))?
        }
    };

    let slot = vm.add_memory_region(GuestAddress(addr), Box::new(mmap), false, false)?;

    Ok((addr >> 12, slot))
}

fn register_memory_hva(
    vm: &mut impl Vm,
    allocator: &mut SystemAllocator,
    mem: Box<dyn MappedRegion>,
    pci_allocation: (Alloc, u64),
) -> Result<(u64, MemSlot)> {
    let addr = allocator
        .mmio_allocator(MmioType::High)
        .address_from_pci_offset(pci_allocation.0, pci_allocation.1, mem.size() as u64)
        .map_err(|_e| SysError::new(EINVAL))?;

    let slot = vm.add_memory_region(GuestAddress(addr), mem, false, false)?;
    Ok((addr >> 12, slot))
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
        balloon_host_socket: &BalloonControlRequestSocket,
        disk_host_sockets: &[DiskControlRequestSocket],
        usb_control_socket: &UsbControlSocket,
        bat_control: &mut Option<BatControl>,
    ) -> VmResponse {
        match *self {
            VmRequest::Exit => {
                *run_mode = Some(VmRunMode::Exiting);
                VmResponse::Ok
            }
            VmRequest::Suspend => {
                *run_mode = Some(VmRunMode::Suspending);
                VmResponse::Ok
            }
            VmRequest::Resume => {
                *run_mode = Some(VmRunMode::Running);
                VmResponse::Ok
            }
            VmRequest::BalloonCommand(BalloonControlCommand::Adjust { num_bytes }) => {
                match balloon_host_socket.send(&BalloonControlCommand::Adjust { num_bytes }) {
                    Ok(_) => VmResponse::Ok,
                    Err(_) => VmResponse::Err(SysError::last()),
                }
            }
            VmRequest::BalloonCommand(BalloonControlCommand::Stats) => {
                match balloon_host_socket.send(&BalloonControlCommand::Stats {}) {
                    Ok(_) => match balloon_host_socket.recv() {
                        Ok(BalloonControlResult::Stats {
                            stats,
                            balloon_actual,
                        }) => VmResponse::BalloonStats {
                            stats,
                            balloon_actual,
                        },
                        Err(e) => {
                            error!("balloon socket recv failed: {}", e);
                            VmResponse::Err(SysError::last())
                        }
                    },
                    Err(_) => VmResponse::Err(SysError::last()),
                }
            }
            VmRequest::DiskCommand {
                disk_index,
                ref command,
            } => {
                // Forward the request to the block device process via its control socket.
                if let Some(sock) = disk_host_sockets.get(disk_index) {
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
                let res = usb_control_socket.send(cmd);
                if let Err(e) = res {
                    error!("fail to send command to usb control socket: {}", e);
                    return VmResponse::Err(SysError::new(EIO));
                }
                match usb_control_socket.recv() {
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

                        let res = battery.control_socket.send(cmd);
                        if let Err(e) = res {
                            error!("fail to send command to bat control socket: {}", e);
                            return VmResponse::Err(SysError::new(EIO));
                        }

                        match battery.control_socket.recv() {
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
        }
    }
}

/// Indication of success or failure of a `VmRequest`.
///
/// Success is usually indicated `VmResponse::Ok` unless there is data associated with the response.
#[derive(MsgOnSocket, Debug)]
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
        descriptor: MaybeOwnedDescriptor,
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
            BalloonStats {
                stats,
                balloon_actual,
            } => write!(
                f,
                "balloon size: {}\nballoon stats: {}",
                balloon_actual, stats
            ),
            UsbResponse(result) => write!(f, "usb control request get result {:?}", result),
            BatResponse(result) => write!(f, "{}", result),
        }
    }
}

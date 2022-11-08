// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A crate for abstracting the underlying kernel hypervisor used in crosvm.
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub mod aarch64;
pub mod caps;

#[cfg(all(windows, feature = "haxm"))]
pub mod haxm;
#[cfg(unix)]
pub mod kvm;
#[cfg(all(windows, feature = "whpx"))]
pub mod whpx;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86_64;

use std::os::raw::c_int;

use base::AsRawDescriptor;
use base::Event;
use base::MappedRegion;
use base::Protection;
use base::Result;
use base::SafeDescriptor;
use serde::Deserialize;
use serde::Serialize;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub use crate::aarch64::*;
pub use crate::caps::*;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use crate::x86_64::*;

/// An index in the list of guest-mapped memory regions.
pub type MemSlot = u32;

/// A trait for checking hypervisor capabilities.
pub trait Hypervisor: Send {
    /// Makes a shallow clone of this `Hypervisor`.
    fn try_clone(&self) -> Result<Self>
    where
        Self: Sized;

    /// Checks if a particular `HypervisorCap` is available.
    fn check_capability(&self, cap: HypervisorCap) -> bool;
}

/// A wrapper for using a VM and getting/setting its state.
pub trait Vm: Send {
    /// Makes a shallow clone of this `Vm`.
    fn try_clone(&self) -> Result<Self>
    where
        Self: Sized;

    /// Checks if a particular `VmCap` is available.
    ///
    /// This is distinct from the `Hypervisor` version of this method because some extensions depend
    /// on the particular `Vm` instance. This method is encouraged because it more accurately
    /// reflects the usable capabilities.
    fn check_capability(&self, c: VmCap) -> bool;

    /// Enable the VM capabilities.
    fn enable_capability(&self, capability: VmCap, flags: u32) -> Result<bool>;

    /// Get the guest physical address size in bits.
    fn get_guest_phys_addr_bits(&self) -> u8;

    /// Gets the guest-mapped memory for the Vm.
    fn get_memory(&self) -> &GuestMemory;

    /// Inserts the given `MappedRegion` into the VM's address space at `guest_addr`.
    ///
    /// The slot that was assigned the memory mapping is returned on success.  The slot can be given
    /// to `Vm::remove_memory_region` to remove the memory from the VM's address space and take back
    /// ownership of `mem_region`.
    ///
    /// Note that memory inserted into the VM's address space must not overlap with any other memory
    /// slot's region.
    ///
    /// If `read_only` is true, the guest will be able to read the memory as normal, but attempts to
    /// write will trigger a mmio VM exit, leaving the memory untouched.
    ///
    /// If `log_dirty_pages` is true, the slot number can be used to retrieve the pages written to
    /// by the guest with `get_dirty_log`.
    fn add_memory_region(
        &mut self,
        guest_addr: GuestAddress,
        mem_region: Box<dyn MappedRegion>,
        read_only: bool,
        log_dirty_pages: bool,
    ) -> Result<MemSlot>;

    /// Does a synchronous msync of the memory mapped at `slot`, syncing `size` bytes starting at
    /// `offset` from the start of the region.  `offset` must be page aligned.
    fn msync_memory_region(&mut self, slot: MemSlot, offset: usize, size: usize) -> Result<()>;

    /// Removes and drops the `UserMemoryRegion` that was previously added at the given slot.
    fn remove_memory_region(&mut self, slot: MemSlot) -> Result<Box<dyn MappedRegion>>;

    /// Creates an emulated device.
    fn create_device(&self, kind: DeviceKind) -> Result<SafeDescriptor>;

    /// Gets the bitmap of dirty pages since the last call to `get_dirty_log` for the memory at
    /// `slot`.  Only works on VMs that support `VmCap::DirtyLog`.
    ///
    /// The size of `dirty_log` must be at least as many bits as there are pages in the memory
    /// region `slot` represents. For example, if the size of `slot` is 16 pages, `dirty_log` must
    /// be 2 bytes or greater.
    fn get_dirty_log(&self, slot: MemSlot, dirty_log: &mut [u8]) -> Result<()>;

    /// Registers an event to be signaled whenever a certain address is written to.
    ///
    /// The `datamatch` parameter can be used to limit signaling `evt` to only the cases where the
    /// value being written is equal to `datamatch`. Note that the size of `datamatch` is important
    /// and must match the expected size of the guest's write.
    ///
    /// In all cases where `evt` is signaled, the ordinary vmexit to userspace that would be
    /// triggered is prevented.
    fn register_ioevent(
        &mut self,
        evt: &Event,
        addr: IoEventAddress,
        datamatch: Datamatch,
    ) -> Result<()>;

    /// Unregisters an event previously registered with `register_ioevent`.
    ///
    /// The `evt`, `addr`, and `datamatch` set must be the same as the ones passed into
    /// `register_ioevent`.
    fn unregister_ioevent(
        &mut self,
        evt: &Event,
        addr: IoEventAddress,
        datamatch: Datamatch,
    ) -> Result<()>;

    /// Trigger any matching registered io events based on an MMIO or PIO write at `addr`. The
    /// `data` slice represents the contents and length of the write, which is used to compare with
    /// the registered io events' Datamatch values. If the hypervisor does in-kernel IO event
    /// delivery, this is a no-op.
    fn handle_io_events(&self, addr: IoEventAddress, data: &[u8]) -> Result<()>;

    /// Retrieves the current timestamp of the paravirtual clock as seen by the current guest.
    /// Only works on VMs that support `VmCap::PvClock`.
    fn get_pvclock(&self) -> Result<ClockState>;

    /// Sets the current timestamp of the paravirtual clock as seen by the current guest.
    /// Only works on VMs that support `VmCap::PvClock`.
    fn set_pvclock(&self, state: &ClockState) -> Result<()>;

    /// Maps `size` bytes starting at `fs_offset` bytes from within the given `fd`
    /// at `offset` bytes from the start of the arena with `prot` protections.
    /// `offset` must be page aligned.
    ///
    /// # Arguments
    /// * `offset` - Page aligned offset into the arena in bytes.
    /// * `size` - Size of memory region in bytes.
    /// * `fd` - File descriptor to mmap from.
    /// * `fd_offset` - Offset in bytes from the beginning of `fd` to start the mmap.
    /// * `prot` - Protection (e.g. readable/writable) of the memory region.
    fn add_fd_mapping(
        &mut self,
        slot: u32,
        offset: usize,
        size: usize,
        fd: &dyn AsRawDescriptor,
        fd_offset: u64,
        prot: Protection,
    ) -> Result<()>;

    /// Remove `size`-byte mapping starting at `offset`.
    fn remove_mapping(&mut self, slot: u32, offset: usize, size: usize) -> Result<()>;

    /// Frees the given segment of guest memory to be reclaimed by the host OS.
    /// This is intended for use with virtio-balloon, where a guest driver determines
    /// unused ranges and requests they be freed. Use without the guest's knowledge is sure
    /// to break something. As per virtio-balloon spec, the given address and size
    /// are intended to be page-aligned.
    ///
    /// # Arguments
    /// * `guest_address` - Address in the guest's "physical" memory to begin the unmapping
    /// * `size` - The size of the region to unmap, in bytes
    fn handle_inflate(&mut self, guest_address: GuestAddress, size: u64) -> Result<()>;

    /// Reallocates memory and maps it to provide to the guest. This is intended to be used
    /// exclusively in tandem with `handle_inflate`, and will return an `Err` Result otherwise.
    ///
    /// # Arguments
    /// * `guest_address` - Address in the guest's "physical" memory to begin the mapping
    /// * `size` - The size of the region to map, in bytes
    fn handle_deflate(&mut self, guest_address: GuestAddress, size: u64) -> Result<()>;
}

/// A unique fingerprint for a particular `VcpuRunHandle`, used in `Vcpu` impls to ensure the
/// `VcpuRunHandle ` they receive is the same one that was returned from `take_run_handle`.
#[derive(Clone, PartialEq, Eq)]
pub struct VcpuRunHandleFingerprint(u64);

impl VcpuRunHandleFingerprint {
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// A handle returned by a `Vcpu` to be used with `Vcpu::run` to execute a virtual machine's VCPU.
///
/// This is used to ensure that the caller has bound the `Vcpu` to a thread with
/// `Vcpu::take_run_handle` and to execute hypervisor specific cleanup routines when dropped.
pub struct VcpuRunHandle {
    drop_fn: fn(),
    fingerprint: VcpuRunHandleFingerprint,
    // Prevents Send+Sync for this type.
    phantom: std::marker::PhantomData<*mut ()>,
}

impl VcpuRunHandle {
    /// Used by `Vcpu` impls to create a unique run handle, that when dropped, will call the given
    /// `drop_fn`.
    pub fn new(drop_fn: fn()) -> Self {
        // Creates a probably unique number with a hash of the current thread id and epoch time.
        use std::hash::Hash;
        use std::hash::Hasher;
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::time::Instant::now().hash(&mut hasher);
        std::thread::current().id().hash(&mut hasher);
        Self {
            drop_fn,
            fingerprint: VcpuRunHandleFingerprint(hasher.finish()),
            phantom: std::marker::PhantomData,
        }
    }

    /// Gets the unique fingerprint which may be copied and compared freely.
    pub fn fingerprint(&self) -> &VcpuRunHandleFingerprint {
        &self.fingerprint
    }
}

impl Drop for VcpuRunHandle {
    fn drop(&mut self) {
        (self.drop_fn)();
    }
}

/// Operation for Io and Mmio
#[derive(Copy, Clone, Debug)]
pub enum IoOperation {
    Read,
    Write {
        /// Data to be written.
        ///
        /// For 64 bit architecture, Mmio and Io only work with at most 8 bytes of data.
        data: [u8; 8],
    },
}

/// Parameters describing an MMIO or PIO from the guest.
#[derive(Copy, Clone, Debug)]
pub struct IoParams {
    pub address: u64,
    pub size: usize,
    pub operation: IoOperation,
}

/// A virtual CPU holding a virtualized hardware thread's state, such as registers and interrupt
/// state, which may be used to execute virtual machines.
///
/// To run, `take_run_handle` must be called to lock the vcpu to a thread. Then the returned
/// `VcpuRunHandle` can be used for running.
pub trait Vcpu: downcast_rs::DowncastSync {
    /// Makes a shallow clone of this `Vcpu`.
    fn try_clone(&self) -> Result<Self>
    where
        Self: Sized;

    /// Casts this architecture specific trait object to the base trait object `Vcpu`.
    fn as_vcpu(&self) -> &dyn Vcpu;

    /// Returns a unique `VcpuRunHandle`. A `VcpuRunHandle` is required to run the guest.
    ///
    /// Assigns a vcpu to the current thread so that signal handlers can call
    /// set_local_immediate_exit().  An optional signal number will be temporarily blocked while
    /// assigning the vcpu to the thread and later blocked when `VcpuRunHandle` is destroyed.
    ///
    /// Returns an error, `EBUSY`, if the current thread already contains a Vcpu.
    fn take_run_handle(&self, signal_num: Option<c_int>) -> Result<VcpuRunHandle>;

    /// Runs the VCPU until it exits, returning the reason for the exit.
    ///
    /// Note that the state of the VCPU and associated VM must be setup first for this to do
    /// anything useful. The given `run_handle` must be the same as the one returned by
    /// `take_run_handle` for this `Vcpu`.
    fn run(&mut self, run_handle: &VcpuRunHandle) -> Result<VcpuExit>;

    /// Returns the vcpu id.
    fn id(&self) -> usize;

    /// Sets the bit that requests an immediate exit.
    fn set_immediate_exit(&self, exit: bool);

    /// Sets/clears the bit for immediate exit for the vcpu on the current thread.
    fn set_local_immediate_exit(exit: bool)
    where
        Self: Sized;

    /// Returns a function pointer that invokes `set_local_immediate_exit` in a
    /// signal-safe way when called.
    fn set_local_immediate_exit_fn(&self) -> extern "C" fn();

    /// Handles an incoming MMIO request from the guest.
    ///
    /// This function should be called after `Vcpu::run` returns `VcpuExit::Mmio`, and in the same
    /// thread as run().
    ///
    /// Once called, it will determine whether a MMIO read or MMIO write was the reason for the MMIO
    /// exit, call `handle_fn` with the respective IoParams to perform the MMIO read or write, and
    /// set the return data in the vcpu so that the vcpu can resume running.
    fn handle_mmio(&self, handle_fn: &mut dyn FnMut(IoParams) -> Option<[u8; 8]>) -> Result<()>;

    /// Handles an incoming PIO from the guest.
    ///
    /// This function should be called after `Vcpu::run` returns `VcpuExit::Io`, and in the same
    /// thread as run().
    ///
    /// Once called, it will determine whether an input or output was the reason for the Io exit,
    /// call `handle_fn` with the respective IoParams to perform the input/output operation, and set
    /// the return data in the vcpu so that the vcpu can resume running.
    fn handle_io(&self, handle_fn: &mut dyn FnMut(IoParams) -> Option<[u8; 8]>) -> Result<()>;

    /// Handles the HYPERV_HYPERCALL exit from a vcpu.
    ///
    /// This function should be called after `Vcpu::run` returns `VcpuExit::HypervHcall`, and in the
    /// same thread as run.
    ///
    /// Once called, it will parse the appropriate input parameters to the provided function to
    /// handle the hyperv call, and then set the return data into the vcpu so it can resume running.
    fn handle_hyperv_hypercall(&self, func: &mut dyn FnMut(HypervHypercall) -> u64) -> Result<()>;

    /// Handles a RDMSR exit from the guest.
    ///
    /// This function should be called after `Vcpu::run` returns `VcpuExit::RdMsr`,
    /// and in the same thread as run.
    ///
    /// It will put `data` into the guest buffer and return.
    fn handle_rdmsr(&self, data: u64) -> Result<()>;

    /// Handles a WRMSR exit from the guest by removing any error indication for the operation.
    ///
    /// This function should be called after `Vcpu::run` returns `VcpuExit::WrMsr`,
    /// and in the same thread as run.
    fn handle_wrmsr(&self);

    /// Signals to the hypervisor that this guest is being paused by userspace.  Only works on Vms
    /// that support `VmCap::PvClockSuspend`.
    fn pvclock_ctrl(&self) -> Result<()>;

    /// Specifies set of signals that are blocked during execution of `RunnableVcpu::run`.  Signals
    /// that are not blocked will cause run to return with `VcpuExit::Intr`.  Only works on Vms that
    /// support `VmCap::SignalMask`.
    fn set_signal_mask(&self, signals: &[c_int]) -> Result<()>;

    /// Enables a hypervisor-specific extension on this Vcpu.  `cap` is a constant defined by the
    /// hypervisor API (e.g., kvm.h).  `args` are the arguments for enabling the feature, if any.
    ///
    /// # Safety
    /// This function is marked as unsafe because `args` may be interpreted as pointers for some
    /// capabilities. The caller must ensure that any pointers passed in the `args` array are
    /// allocated as the kernel expects, and that mutable pointers are owned.
    unsafe fn enable_raw_capability(&self, cap: u32, args: &[u64; 4]) -> Result<()>;
}

downcast_rs::impl_downcast!(sync Vcpu);

/// An address either in programmable I/O space or in memory mapped I/O space.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, std::hash::Hash)]
pub enum IoEventAddress {
    Pio(u64),
    Mmio(u64),
}

/// Used in `Vm::register_ioevent` to indicate a size and optionally value to match.
#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub enum Datamatch {
    AnyLength,
    U8(Option<u8>),
    U16(Option<u16>),
    U32(Option<u32>),
    U64(Option<u64>),
}

/// A reason why a VCPU exited. One of these returns every time `Vcpu::run` is called.
#[derive(Debug, Clone, Copy)]
pub enum VcpuExit {
    /// An io instruction needs to be emulated.
    /// vcpu handle_io should be called to handle the io operation
    Io,
    /// A mmio instruction needs to be emulated.
    /// vcpu handle_mmio should be called to handle the mmio operation
    Mmio,
    IoapicEoi {
        vector: u8,
    },
    HypervHypercall,
    Unknown,
    Exception,
    Hypercall,
    Debug,
    Hlt,
    IrqWindowOpen,
    Shutdown,
    FailEntry {
        hardware_entry_failure_reason: u64,
    },
    Intr,
    SetTpr,
    TprAccess,
    S390Sieic,
    S390Reset,
    Dcr,
    Nmi,
    InternalError,
    Osi,
    PaprHcall,
    S390Ucontrol,
    Watchdog,
    S390Tsch,
    Epr,
    SystemEventShutdown,
    SystemEventReset,
    SystemEventCrash,
    SystemEventS2Idle,
    RdMsr {
        index: u32,
    },
    WrMsr {
        index: u32,
        data: u64,
    },
    /// An invalid vcpu register was set while running.
    InvalidVpRegister,
    /// incorrect setup for vcpu requiring an unsupported feature
    UnsupportedFeature,
    /// vcpu run was user cancelled
    Canceled,
    /// an unrecoverable exception was encountered (different from Exception)
    UnrecoverableException,
    /// vcpu stopped due to an msr access.
    MsrAccess,
    /// vcpu stopped due to a cpuid request.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Cpuid {
        entry: CpuIdEntry,
    },
    /// vcpu stopped due to calling rdtsc
    RdTsc,
    /// vcpu stopped for an apic smi trap
    ApicSmiTrap,
    /// vcpu stopped due to an apic trap
    ApicInitSipiTrap,
    /// vcpu stoppted due to bus lock
    BusLock,
}

/// A hypercall with parameters being made from the guest.
#[derive(Debug)]
pub enum HypervHypercall {
    HypervSynic {
        msr: u32,
        control: u64,
        evt_page: u64,
        msg_page: u64,
    },
    HypervHcall {
        input: u64,
        params: [u64; 2],
    },
}

/// A device type to create with `Vm.create_device`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceKind {
    /// VFIO device for direct access to devices from userspace
    Vfio,
    /// ARM virtual general interrupt controller v2
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    ArmVgicV2,
    /// ARM virtual general interrupt controller v3
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    ArmVgicV3,
}

/// The source chip of an `IrqSource`
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrqSourceChip {
    PicPrimary,
    PicSecondary,
    Ioapic,
    Gic,
}

/// A source of IRQs in an `IrqRoute`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrqSource {
    Irqchip { chip: IrqSourceChip, pin: u32 },
    Msi { address: u64, data: u32 },
}

/// A single route for an IRQ.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrqRoute {
    pub gsi: u32,
    pub source: IrqSource,
}

/// The state of the paravirtual clock.
#[derive(Debug, Default, Copy, Clone)]
pub struct ClockState {
    /// Current pv clock timestamp, as seen by the guest
    pub clock: u64,
    /// Hypervisor-specific feature flags for the pv clock
    pub flags: u32,
}

/// The MPState represents the state of a processor.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MPState {
    /// the vcpu is currently running (x86/x86_64,arm/arm64)
    Runnable,
    /// the vcpu is an application processor (AP) which has not yet received an INIT signal
    /// (x86/x86_64)
    Uninitialized,
    /// the vcpu has received an INIT signal, and is now ready for a SIPI (x86/x86_64)
    InitReceived,
    /// the vcpu has executed a HLT instruction and is waiting for an interrupt (x86/x86_64)
    Halted,
    /// the vcpu has just received a SIPI (vector accessible via KVM_GET_VCPU_EVENTS) (x86/x86_64)
    SipiReceived,
    /// the vcpu is stopped (arm/arm64)
    Stopped,
}

/// Whether the VM should be run in protected mode or not.
#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProtectionType {
    /// The VM should be run in the unprotected mode, where the host has access to its memory.
    Unprotected,
    /// The VM should be run in protected mode, so the host cannot access its memory directly. It
    /// should be booted via the protected VM firmware, so that it can access its secrets.
    Protected,
    /// The VM should be run in protected mode, so the host cannot access its memory directly. It
    /// should be booted via a custom VM firmware, useful for debugging and testing.
    ProtectedWithCustomFirmware,
    /// The VM should be run in protected mode, but booted directly without pVM firmware. The host
    /// will still be unable to access the VM memory, but it won't be given any secrets.
    ProtectedWithoutFirmware,
    /// The VM should be run in unprotected mode, but with the same memory layout as protected mode,
    /// protected VM firmware loaded, and simulating protected mode as much as possible. This is
    /// useful for debugging the protected VM firmware and other protected mode issues.
    UnprotectedWithFirmware,
}

impl ProtectionType {
    /// Returns whether the hypervisor will prevent us from accessing the VM's memory.
    pub fn isolates_memory(&self) -> bool {
        matches!(
            self,
            Self::Protected | Self::ProtectedWithCustomFirmware | Self::ProtectedWithoutFirmware
        )
    }

    /// Returns whether the VMM needs to load the pVM firmware.
    pub fn loads_firmware(&self) -> bool {
        matches!(
            self,
            Self::UnprotectedWithFirmware | Self::ProtectedWithCustomFirmware
        )
    }

    /// Returns whether the VM runs a pVM firmware.
    pub fn runs_firmware(&self) -> bool {
        self.loads_firmware() || matches!(self, Self::Protected)
    }
}

#[derive(Clone, Copy)]
pub struct Config {
    #[cfg(target_arch = "aarch64")]
    /// enable the Memory Tagging Extension in the guest
    pub mte: bool,
    pub protection_type: ProtectionType,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            #[cfg(target_arch = "aarch64")]
            mte: false,
            protection_type: ProtectionType::Unprotected,
        }
    }
}

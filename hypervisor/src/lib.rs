// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A crate for abstracting the underlying kernel hypervisor used in crosvm.
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub mod aarch64;
pub mod caps;
pub mod kvm;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86_64;

use std::ops::{Deref, DerefMut};

use sys_util::{GuestAddress, GuestMemory, MappedRegion, Result, SafeDescriptor};

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub use crate::aarch64::*;
pub use crate::caps::*;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use crate::x86_64::*;

/// An index in the list of guest-mapped memory regions.
pub type MemSlot = u32;

/// A trait for checking hypervisor capabilities.
pub trait Hypervisor {
    /// Checks if a particular `HypervisorCap` is available.
    fn check_capability(&self, cap: &HypervisorCap) -> bool;
}

/// A wrapper for using a VM and getting/setting its state.
pub trait Vm: Send + Sized {
    /// Makes a shallow clone of this `Vm`.
    fn try_clone(&self) -> Result<Self>;

    /// Checks if a particular `VmCap` is available.
    ///
    /// This is distinct from the `Hypervisor` version of this method because some extensions depend
    /// on the particular `Vm` existence.  This method is encouraged because it more accurately
    /// reflects the usable capabilities.
    fn check_capability(&self, c: VmCap) -> bool;

    /// Checks if a particular hypervisor-specific capability is available.
    ///
    /// # Arguments
    ///
    /// * `cap` - hypervisor-specific constant defined by the hypervisor API (e.g., kvm.h)
    fn check_raw_capability(&self, cap: u32) -> bool;

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
    fn remove_memory_region(&mut self, slot: MemSlot) -> Result<()>;

    /// Creates an emulated device.
    fn create_device(&self, kind: DeviceKind) -> Result<SafeDescriptor>;

    /// Retrieves the current timestamp of the paravirtual clock as seen by the current guest.
    /// Only works on VMs that support `VmCap::PvClock`.
    fn get_pvclock(&self) -> Result<ClockState>;

    /// Sets the current timestamp of the paravirtual clock as seen by the current guest.
    /// Only works on VMs that support `VmCap::PvClock`.
    fn set_pvclock(&self, state: &ClockState) -> Result<()>;
}

/// A wrapper around using a VCPU.
/// `Vcpu` provides all functionality except for running. To run, `to_runnable` must be called to
/// lock the vcpu to a thread. Then the returned `RunnableVcpu` can be used for running.
pub trait Vcpu: Send + Sized {
    type Runnable: RunnableVcpu;

    /// Consumes `self` and returns a `RunnableVcpu`. A `RunnableVcpu` is required to run the guest.
    fn to_runnable(self) -> Result<Self::Runnable>;

    /// Request the Vcpu to exit the next time it can accept an interrupt.
    fn request_interrupt_window(&self) -> Result<()>;
}

/// A Vcpu that has a thread and can be run. Created by calling `to_runnable` on a `Vcpu`.
/// Implements `Deref` to a `Vcpu` so all `Vcpu` methods are usable, with the addition of the `run`
/// function to execute the guest.
pub trait RunnableVcpu: Deref<Target = <Self as RunnableVcpu>::Vcpu> + DerefMut {
    type Vcpu: Vcpu;

    /// Runs the VCPU until it exits, returning the reason for the exit.
    ///
    /// Note that the state of the VCPU and associated VM must be setup first for this to do
    /// anything useful.
    fn run(&self) -> Result<VcpuExit>;
}

/// A reason why a VCPU exited. One of these returns every time `Vcpu::run` is called.
#[derive(Debug)]
pub enum VcpuExit {
    /// An out port instruction was run on the given port with the given data.
    IoOut {
        port: u16,
        size: usize,
        data: [u8; 8],
    },
    /// An in port instruction was run on the given port.
    ///
    /// The date that the instruction receives should be set with `set_data` before `Vcpu::run` is
    /// called again.
    IoIn {
        port: u16,
        size: usize,
    },
    /// A read instruction was run against the given MMIO address.
    ///
    /// The date that the instruction receives should be set with `set_data` before `Vcpu::run` is
    /// called again.
    MmioRead {
        address: u64,
        size: usize,
    },
    /// A write instruction was run against the given MMIO address with the given data.
    MmioWrite {
        address: u64,
        size: usize,
        data: [u8; 8],
    },
    IoapicEoi {
        vector: u8,
    },
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
    /// The cpu triggered a system level event which is specified by the type field.
    /// The first field is the event type and the second field is flags.
    /// The possible event types are shutdown, reset, or crash.  So far there
    /// are not any flags defined.
    SystemEvent(u32 /* event_type */, u64 /* flags */),
}

/// A device type to create with `Vm.create_device`
#[derive(Clone, Copy, Debug, PartialEq)]
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

/// The state of the paravirtual clock
#[derive(Debug, Default, Copy, Clone)]
pub struct ClockState {
    /// Current pv clock timestamp, as seen by the guest
    pub clock: u64,
    /// Hypervisor-specific feature flags for the pv clock
    pub flags: u32,
}

/// The state of one VCPU register.
#[derive(Debug, Default, Copy, Clone)]
pub struct Register {
    pub id: u64,
    pub value: u64,
}

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

use sys_util::{GuestMemory, Result};

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub use crate::aarch64::*;
pub use crate::caps::*;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use crate::x86_64::*;

/// A trait for checking hypervisor capabilities.
pub trait Hypervisor {
    /// Checks if a particular `HypervisorCap` is available.
    fn check_capability(&self, cap: &HypervisorCap) -> bool;
}

/// A wrapper for using a VM and getting/setting its state.
pub trait Vm: Send + Sized {
    /// Makes a shallow clone this `Vm`.
    fn try_clone(&self) -> Result<Self>;

    /// Gets the guest-mapped memory for the Vm.
    fn get_memory(&self) -> &GuestMemory;
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

/// A memory region in the current process that can be mapped into the guest's memory.
///
/// Safe when implementers guarantee `ptr`..`ptr+size` is an mmaped region owned by this object that
/// can't be unmapped during the `MappedRegion`'s lifetime.
pub unsafe trait MappedRegion: Send + Sync {
    /// Returns a pointer to the beginning of the memory region. Should only be
    /// used for passing this region to ioctls for setting guest memory.
    fn as_ptr(&self) -> *mut u8;

    /// Returns the size of the memory region in bytes.
    fn size(&self) -> usize;

    /// Flushes changes to this memory region to the backing file.
    fn msync(&self) -> Result<()>;
}

/// A reason why a VCPU exited. One of these returns every time `Vcpu::run` is called.
#[derive(Debug)]
pub enum VcpuExit {
    Unknown,
}

pub struct IrqRoute {}

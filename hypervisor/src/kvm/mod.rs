// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
mod aarch64;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86_64;

use std::ops::{Deref, DerefMut};
use std::os::raw::c_char;

use libc::{open, O_CLOEXEC, O_RDWR};

use sys_util::{
    errno_result, AsRawDescriptor, FromRawDescriptor, GuestMemory, RawDescriptor, Result,
    SafeDescriptor,
};

use crate::{Hypervisor, HypervisorCap, RunnableVcpu, Vcpu, VcpuExit, Vm};

pub struct Kvm {
    kvm: SafeDescriptor,
}

impl Kvm {
    /// Opens `/dev/kvm/` and returns a Kvm object on success.
    pub fn new() -> Result<Kvm> {
        // Open calls are safe because we give a constant nul-terminated string and verify the
        // result.
        let ret = unsafe { open("/dev/kvm\0".as_ptr() as *const c_char, O_RDWR | O_CLOEXEC) };
        if ret < 0 {
            return errno_result();
        }
        // Safe because we verify that ret is valid and we own the fd.
        Ok(Kvm {
            kvm: unsafe { SafeDescriptor::from_raw_descriptor(ret) },
        })
    }
}

impl AsRawDescriptor for Kvm {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.kvm.as_raw_descriptor()
    }
}

impl Hypervisor for Kvm {
    fn check_capability(&self, _cap: &HypervisorCap) -> bool {
        unimplemented!("check_capability for Kvm is not yet implemented");
    }
}

/// A wrapper around creating and using a KVM VM.
pub struct KvmVm {
    guest_mem: GuestMemory,
}

impl KvmVm {
    /// Constructs a new `KvmVm` using the given `Kvm` instance.
    pub fn new(_kvm: &Kvm, guest_mem: GuestMemory) -> Result<KvmVm> {
        Ok(KvmVm { guest_mem })
    }

    fn create_kvm_vcpu(&self, _id: usize) -> Result<KvmVcpu> {
        Ok(KvmVcpu {})
    }
}

impl Vm for KvmVm {
    fn get_guest_mem(&self) -> &GuestMemory {
        &self.guest_mem
    }
}

/// A wrapper around creating and using a KVM Vcpu.
pub struct KvmVcpu {}

impl Vcpu for KvmVcpu {
    type Runnable = RunnableKvmVcpu;

    fn to_runnable(self) -> Result<Self::Runnable> {
        Ok(RunnableKvmVcpu {
            vcpu: self,
            phantom: Default::default(),
        })
    }

    fn request_interrupt_window(&self) -> Result<()> {
        Ok(())
    }
}

/// A KvmVcpu that has a thread and can be run.
pub struct RunnableKvmVcpu {
    vcpu: KvmVcpu,

    // vcpus must stay on the same thread once they start.
    // Add the PhantomData pointer to ensure RunnableKvmVcpu is not `Send`.
    phantom: std::marker::PhantomData<*mut u8>,
}

impl RunnableVcpu for RunnableKvmVcpu {
    type Vcpu = KvmVcpu;

    fn run(&self) -> Result<VcpuExit> {
        Ok(VcpuExit::Unknown)
    }
}

impl Deref for RunnableKvmVcpu {
    type Target = <Self as RunnableVcpu>::Vcpu;

    fn deref(&self) -> &Self::Target {
        &self.vcpu
    }
}

impl DerefMut for RunnableKvmVcpu {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.vcpu
    }
}

#[cfg(test)]
mod tests {
    use super::Kvm;

    #[test]
    fn new() {
        Kvm::new().unwrap();
    }
}

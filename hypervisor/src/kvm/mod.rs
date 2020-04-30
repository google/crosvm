// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::{CpuId, Hypervisor, HypervisorCap};
use libc::{open, O_CLOEXEC, O_RDWR};
use std::os::raw::c_char;
use sys_util::{
    errno_result, AsRawDescriptor, FromRawDescriptor, RawDescriptor, Result, SafeDescriptor,
};

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

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_supported_cpuid(&self) -> Result<CpuId> {
        unimplemented!("get_supported_cpuid for Kvm is not yet implemented");
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_emulated_cpuid(&self) -> Result<CpuId> {
        unimplemented!("get_emulated_cpuid for Kvm is not yet implemented");
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

// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A crate for abstracting the underlying kernel hypervisor used in crosvm.
pub mod caps;
pub mod kvm;
pub mod types;

use sys_util::Result;

pub use crate::caps::*;
pub use crate::types::*;

/// A trait for managing the underlying cpu information for the hypervisor and to check its capabilities.
trait Hypervisor {
    // Checks if a particular `HypervisorCap` is available.
    fn check_capability(&self, cap: &HypervisorCap) -> bool;
    // Get the system supported CPUID values.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_supported_cpuid(&self) -> Result<CpuId>;
    // Get the system emulated CPUID values.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_emulated_cpuid(&self) -> Result<CpuId>;
}

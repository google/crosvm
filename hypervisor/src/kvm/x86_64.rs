// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use kvm_sys::*;
use libc::E2BIG;
use sys_util::{ioctl_with_mut_ptr, Error, Result};

use super::{Kvm, KvmVcpu, KvmVm};
use crate::{CpuId, CpuIdEntry, HypervisorX86_64, Regs, VcpuX86_64, VmX86_64};

type KvmCpuId = kvm::CpuId;

impl Kvm {
    pub fn get_cpuid(&self, kind: u64) -> Result<CpuId> {
        const KVM_MAX_ENTRIES: usize = 256;
        self.get_cpuid_with_initial_capacity(kind, KVM_MAX_ENTRIES)
    }

    fn get_cpuid_with_initial_capacity(&self, kind: u64, initial_capacity: usize) -> Result<CpuId> {
        let mut entries: usize = initial_capacity;

        loop {
            let mut kvm_cpuid = KvmCpuId::new(entries);

            let ret = unsafe {
                // ioctl is unsafe. The kernel is trusted not to write beyond the bounds of the
                // memory allocated for the struct. The limit is read from nent within KvmCpuId,
                // which is set to the allocated size above.
                ioctl_with_mut_ptr(self, kind, kvm_cpuid.as_mut_ptr())
            };
            if ret < 0 {
                let err = Error::last();
                match err.errno() {
                    E2BIG => {
                        // double the available memory for cpuid entries for kvm.
                        if let Some(val) = entries.checked_mul(2) {
                            entries = val;
                        } else {
                            return Err(err);
                        }
                    }
                    _ => return Err(err),
                }
            } else {
                return Ok(CpuId::from(&kvm_cpuid));
            }
        }
    }
}

impl<'a> From<&'a KvmCpuId> for CpuId {
    fn from(kvm_cpuid: &'a KvmCpuId) -> CpuId {
        let kvm_entries = kvm_cpuid.entries_slice();
        let mut cpu_id_entries = Vec::with_capacity(kvm_entries.len());

        for entry in kvm_entries {
            let cpu_id_entry = CpuIdEntry {
                function: entry.function,
                index: entry.index,
                eax: entry.eax,
                ebx: entry.ebx,
                ecx: entry.ecx,
                edx: entry.edx,
            };
            cpu_id_entries.push(cpu_id_entry)
        }
        CpuId { cpu_id_entries }
    }
}

impl HypervisorX86_64 for Kvm {
    fn get_supported_cpuid(&self) -> Result<CpuId> {
        self.get_cpuid(KVM_GET_SUPPORTED_CPUID())
    }

    fn get_emulated_cpuid(&self) -> Result<CpuId> {
        self.get_cpuid(KVM_GET_EMULATED_CPUID())
    }
}

impl VmX86_64 for KvmVm {
    type Vcpu = KvmVcpu;

    fn create_vcpu(&self, id: usize) -> Result<Self::Vcpu> {
        self.create_kvm_vcpu(id)
    }
}

impl VcpuX86_64 for KvmVcpu {
    fn get_regs(&self) -> Result<Regs> {
        Ok(Regs {})
    }
}

#[cfg(test)]
mod tests {
    use super::Kvm;
    use crate::HypervisorX86_64;
    use kvm_sys::*;

    #[test]
    fn get_supported_cpuid() {
        let hypervisor = Kvm::new().unwrap();
        let cpuid = hypervisor.get_supported_cpuid().unwrap();
        assert!(cpuid.cpu_id_entries.len() > 0);
    }

    #[test]
    fn get_emulated_cpuid() {
        let hypervisor = Kvm::new().unwrap();
        let cpuid = hypervisor.get_emulated_cpuid().unwrap();
        assert!(cpuid.cpu_id_entries.len() > 0);
    }

    #[test]
    fn entries_double_on_error() {
        let hypervisor = Kvm::new().unwrap();
        let cpuid = hypervisor
            .get_cpuid_with_initial_capacity(KVM_GET_SUPPORTED_CPUID(), 4)
            .unwrap();
        assert!(cpuid.cpu_id_entries.len() > 4);
    }
}

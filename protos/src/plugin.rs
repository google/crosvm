// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub use crate::generated::plugin::*;

/// Converts protobuf representation of CpuId data into KVM format.
pub fn cpuid_proto_to_kvm(entry: &CpuidEntry) -> kvm_sys::kvm_cpuid_entry2 {
    // Safe: C structures are expected to be zero-initialized.
    let mut e: kvm_sys::kvm_cpuid_entry2 = unsafe { std::mem::zeroed() };
    e.function = entry.function;
    if entry.has_index {
        e.flags = kvm_sys::KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
    }
    e.index = entry.index;
    e.eax = entry.eax;
    e.ebx = entry.ebx;
    e.ecx = entry.ecx;
    e.edx = entry.edx;

    e
}

/// Converts KVM representation of CpuId data into protobuf format.
pub fn cpuid_kvm_to_proto(entry: &kvm_sys::kvm_cpuid_entry2) -> CpuidEntry {
    let mut e = CpuidEntry::new();
    e.function = entry.function;
    e.has_index = entry.flags & kvm_sys::KVM_CPUID_FLAG_SIGNIFCANT_INDEX != 0;
    e.index = entry.index;
    e.eax = entry.eax;
    e.ebx = entry.ebx;
    e.ecx = entry.ecx;
    e.edx = entry.edx;

    e
}

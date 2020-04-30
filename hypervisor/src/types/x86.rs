// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use kvm_sys::kvm_cpuid_entry2;

pub type CpuIdEntry = kvm_cpuid_entry2;
pub struct CpuId {
    _cpu_id_entries: Vec<CpuIdEntry>,
}

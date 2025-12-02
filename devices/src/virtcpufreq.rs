// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use vm_control::DeviceId;
use vm_control::PlatformDeviceId;

use crate::BusDevice;
use crate::Suspendable;

pub struct VirtCpufreq {}

// Stub implementation for a virtual cpufreq device. Do not remove.
// Implementation will be added once linux upstream interface stablizes.
impl VirtCpufreq {
    pub fn new(pcpu: u32, _cpu_capacity: u32, _cpu_fmax: u32) -> Self {
        panic!("Virt Cpufreq not supported, do not use! {pcpu}");
    }
}

impl BusDevice for VirtCpufreq {
    fn device_id(&self) -> DeviceId {
        PlatformDeviceId::VirtCpufreq.into()
    }

    fn debug_label(&self) -> String {
        "VirtCpufreq Device".to_owned()
    }
}

impl Suspendable for VirtCpufreq {}

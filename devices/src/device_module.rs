// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Result;
use hypervisor::ProtectionType;
use hypervisor::Vm;
#[cfg(any(target_os = "android", target_os = "linux"))]
use jail::JailConfig;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use minijail::Minijail;
use resources::SystemAllocator;
use vm_control::AnyControlTube;

use crate::virtio::VirtioDevice;

/// Arguments to `VirtioDeviceModule::create`.
pub struct VirtioDeviceArgs<'a> {
    pub vm: &'a dyn Vm,
    pub resources: &'a mut SystemAllocator,
    pub add_control_tube: &'a mut dyn FnMut(AnyControlTube),
    pub protection_type: ProtectionType,
}

/// A module that creates a single virtio device and provides hooks to integrate it into the VMM.
///
/// The goal of this API is to allow nearly all of a device's code to live together, including
/// logic that was historically spread across the code base, like wiring up control tubes. To add a
/// new device, you should just need to write one of these modules, add cmdline params, and insert
/// the module into `crosvm::config::Config`.
///
/// Generally, types implementing this trait should only contain data derived from the cmdline
/// arguments. If a device needs, say, some information from the hypervisor, then pass that data
/// through `VirtioDeviceArgs`.
///
/// Requires serde because `Config` requires serde (for Windows).
pub trait VirtioDeviceModule: serde::Serialize + serde::de::DeserializeOwned {
    /// Name of the device used to determine init processing order.
    fn sort_name(&self) -> &'static str;

    /// Create an instance of this device.
    fn create(&self, cx: &mut VirtioDeviceArgs<'_>) -> Result<Box<dyn VirtioDevice>>;

    /// Optionally create a jail for this device.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    fn create_jail(&self, jail_config: &JailConfig) -> Result<Option<Minijail>>;
}

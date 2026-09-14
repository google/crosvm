// Copyright 2026 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Stub implementation of vendor virtio devices.
//! Downstream may replace this crate by pointing the `vendor_devices` workspace dependency to a
//! platform specific crate.

use anyhow::bail;
use anyhow::Result;
use argh::FromArgValue;
use devices::virtio::VirtioDevice;
use devices::VirtioDeviceArgs;
use devices::VirtioDeviceModule;
#[cfg(any(target_os = "android", target_os = "linux"))]
use jail::JailConfig;
#[cfg(any(target_os = "android", target_os = "linux"))]
use minijail::Minijail;
use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
/// Replace the "Unsupported" variant in downstream crate with the available platform devices
pub enum VendorDeviceModule {
    Unsupported,
}

impl VirtioDeviceModule for VendorDeviceModule {
    fn sort_name(&self) -> &'static str {
        "vendor_device"
    }

    /// The trait methods should match against the VendorDeviceModule variants and dispatch
    /// to the module implementation:
    ///     match self {
    ///         Self::MyDeviceA(m) => m.create(cx),
    ///         Self::MyDeviceB(m) => m.create(cx),
    ///     }
    fn create(&self, _cx: &mut VirtioDeviceArgs<'_>) -> Result<Box<dyn VirtioDevice>> {
        bail!("no vendor devices are supported in this build")
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    fn create_jail(&self, _jail_config: &JailConfig) -> Result<Option<Minijail>> {
        bail!("no vendor devices are supported in this build")
    }
}

/// Receives a string identifier from the command line and returns the corresponding module
/// if it exists.
/// Example implementation:
///     match value {
///         "mydev" => Ok(VendorDeviceModule::MyDevice(MyDeviceModule)),
///         _ => Err(format!("unknown vendor device: {value}")),
///     }
impl FromArgValue for VendorDeviceModule {
    fn from_arg_value(_value: &str) -> std::result::Result<Self, String> {
        Err("no vendor devices are supported in this build".to_string())
    }
}

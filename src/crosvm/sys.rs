// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(any(target_os = "android", target_os = "linux"))]
pub(crate) mod linux;

#[cfg(windows)]
pub(crate) mod windows;

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        use linux as platform;

        #[cfg(feature = "gpu")]
        pub(crate) use linux::gpu::GpuRenderServerParameters;
    } else if #[cfg(windows)] {
        use windows as platform;
        #[cfg(feature = "pci-hotplug")]
        compile_error!("pci-hotplug not supported on windows");
    } else {
        compile_error!("Unsupported platform");
    }
}

pub(crate) use platform::cmdline;
pub(crate) use platform::config;
pub(crate) use platform::config::HypervisorKind;
#[cfg(feature = "crash-report")]
pub(crate) use platform::setup_emulator_crash_reporting;

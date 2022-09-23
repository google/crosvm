// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(unix)]
pub(crate) mod unix;

#[cfg(windows)]
pub(crate) mod windows;

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        use unix as platform;

        #[cfg(feature = "gpu")]
        pub(crate) use unix::gpu::GpuRenderServerParameters;
        #[cfg(all(feature = "virgl_renderer_next", feature = "plugin"))]
        pub(crate) use unix::gpu::start_gpu_render_server;
        #[cfg(all(feature = "virgl_renderer_next", feature = "plugin"))]
        pub(crate) use unix::jail_helpers;
    } else if #[cfg(windows)] {
        use windows as platform;
    } else {
        compile_error!("Unsupported platform");
    }
}

pub(crate) use platform::cmdline;
pub(crate) use platform::config;
#[cfg(feature = "gpu")]
pub(crate) use platform::config::validate_gpu_config;
pub(crate) use platform::config::HypervisorKind;
#[cfg(feature = "crash-report")]
pub(crate) use platform::setup_emulator_crash_reporting;

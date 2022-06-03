// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub(crate) mod unix;
        use unix as platform;
    } else {
        compile_error!("Unsupported platform");
    }
}

pub(crate) use platform::main::{
    check_serial_params, cleanup, get_arguments, net_vq_pairs_expected, set_arguments,
    start_device, DevicesSubcommand,
};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) use platform::main::use_host_cpu_topology;

#[cfg(feature = "gpu")]
pub(crate) use platform::main::is_gpu_backend_deprecated;

#[cfg(feature = "gfxstream")]
pub(crate) use platform::main::use_vulkan;

#[cfg(feature = "audio")]
pub(crate) use platform::main::{check_ac97_backend, parse_ac97_options};

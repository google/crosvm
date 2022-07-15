// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub(crate) mod unix;
        use unix as platform;
        pub(crate) use crate::crosvm::sys::unix::{run_config, ExitState};
    } else if #[cfg(windows)] {
        pub(crate) mod windows;
        use windows as platform;
        pub(crate) use windows::ExitState;
        pub(crate) use windows::run_config;
    } else {
        compile_error!("Unsupported platform");
    }
}

pub(crate) use platform::main::{
    cleanup, error_to_exit_code, get_library_watcher, init_log, run_command, start_device,
};

#[cfg(feature = "kiwi")]
pub(crate) use platform::main::sandbox_lower_token;

#[cfg(not(feature = "crash-report"))]
pub(crate) use platform::set_panic_hook;

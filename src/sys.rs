// Copyright 2022 The ChromiumOS Authors
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

pub(crate) use platform::main::cleanup;
pub(crate) use platform::main::error_to_exit_code;
pub(crate) use platform::main::get_library_watcher;
pub(crate) use platform::main::init_log;
pub(crate) use platform::main::run_command;
#[cfg(feature = "sandbox")]
pub(crate) use platform::main::sandbox_lower_token;
pub(crate) use platform::main::start_device;
#[cfg(not(feature = "crash-report"))]
pub(crate) use platform::set_panic_hook;

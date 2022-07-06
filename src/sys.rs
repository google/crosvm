// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub(crate) mod unix;
        use unix as platform;
        pub(crate) use crate::crosvm::sys::unix::{run_config, ExitState};
    } else {
        compile_error!("Unsupported platform");
    }
}

pub(crate) use platform::main::{cleanup, init_log, run_command, start_device};

#[cfg(not(feature = "crash-report"))]
pub(crate) use platform::set_panic_hook;

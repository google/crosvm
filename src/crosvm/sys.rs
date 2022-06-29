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

pub(crate) use platform::cmdline;
pub(crate) use platform::config;

#[cfg(feature = "gpu")]
pub(crate) use platform::config::validate_gpu_config;

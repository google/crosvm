// Copyright 2022 The Chromium OS Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A wrapper module for platform dependent code.

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        pub mod linux;
        use linux as platform;
    } else if #[cfg(windows)] {
        pub mod windows;
        use windows as platform;
    } else {
        compile_error!("Unsupported platform");
    }
}

pub(crate) use platform::PlatformEndpoint;

pub use platform::SystemStream;

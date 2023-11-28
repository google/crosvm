// Copyright 2022 The Chromium OS Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A wrapper module for platform dependent code.

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub mod unix;
        use unix as platform;
    } else if #[cfg(windows)] {
        pub mod windows;
        use windows as platform;
    } else {
        compile_error!("Unsupported platform");
    }
}

pub(crate) use platform::PlatformConnection;

pub use platform::SystemStream;

// Copyright 2022 The Chromium OS Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A wrapper module for platform dependent code.

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        mod unix;
        pub use unix::*;
    } else if #[cfg(windows)] {
        mod windows;
        pub use windows::*;
    } else {
        compile_error!("Unsupported platform");
    }
}

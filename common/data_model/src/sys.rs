// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A wrapper module for platform dependent code.

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        mod linux;
        pub use linux::*;
    } else if #[cfg(windows)] {
        mod windows;
        pub use windows::*;
    } else {
        compile_error!("Unsupported platform");
    }
}

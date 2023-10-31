// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(any(target_os = "android", target_os = "linux"))]
pub mod linux;

#[cfg(windows)]
pub mod windows;

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        pub use linux as platform;
        pub use linux::*;
    } else if #[cfg(windows)] {
        pub use windows as platform;
        pub use windows::*;
    } else {
        compile_error!("Unsupported platform");
    }
}

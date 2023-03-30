// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(any(target_os = "android", target_os = "linux"))]
pub mod unix;

#[cfg(target_os = "fuchsia")]
pub mod fuchsia;

#[cfg(windows)]
pub mod windows;

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        pub use unix as platform;
    } else if #[cfg(windows)] {
        pub use windows as platform;
    } else if #[cfg(target_os = "fuchsia")] {
        pub use fuchsia as platform;
    } else {
        compile_error!("Unsupported platform");
    }
}

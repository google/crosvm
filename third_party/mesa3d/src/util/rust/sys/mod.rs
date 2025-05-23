// Copyright 2025 Google
// SPDX-License-Identifier: MIT

#[cfg(any(target_os = "android", target_os = "linux"))]
pub mod linux;

#[cfg(any(target_os = "fuchsia", target_os = "macos", target_os = "nto"))]
pub mod stub;

#[cfg(windows)]
pub mod windows;

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        pub use linux as platform;
    } else if #[cfg(windows)] {
        pub use windows as platform;
    } else if #[cfg(any(target_os = "fuchsia", target_os = "macos", target_os = "nto"))] {
        pub use stub as platform;
    } else {
        compile_error!("Unsupported platform");
    }
}

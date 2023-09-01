// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(any(target_os = "android", target_os = "linux"))]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(unix)]
pub mod unix;

#[cfg(windows)]
pub mod windows;

pub mod platform {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    pub use super::linux::*;

    #[cfg(target_os = "macos")]
    pub use super::macos::*;

    #[cfg(unix)]
    pub use super::unix::*;

    #[cfg(windows)]
    pub use super::windows::*;
}

pub use platform::*;

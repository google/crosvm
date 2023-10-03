// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

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

pub use platform::TapT;

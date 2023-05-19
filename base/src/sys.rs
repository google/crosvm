// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(unix)]
pub mod unix;

#[cfg(windows)]
pub mod windows;

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub use unix as platform;
        pub use platform::*;
    } else if #[cfg(windows)] {
        pub use windows as platform;
        pub use platform::*;
    } else {
        compile_error!("Unsupported platform");
    }
}

// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(not(target_os = "fuchsia"))]

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub(crate) mod unix;
        use unix as platform;
    } else if #[cfg(windows)] {
        pub(crate) mod windows;
        use windows as platform;
    } else {
        compile_error!("Unsupported platform");
    }
}

pub(crate) use platform::descriptor_analysis;
pub(crate) use platform::SystemStream;

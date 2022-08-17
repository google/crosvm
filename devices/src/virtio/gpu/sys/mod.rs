// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub(crate) mod unix;
        pub use unix::UnixFrontendExt;
        pub(crate) use unix::UnixResourceBridges as ResourceBridges;
        pub use unix::UnixDisplayMode as DisplayMode;
        pub(crate) use unix::UnixDisplayModeArg as DisplayModeArg;
    } else if #[cfg(windows)] {
        pub(crate) mod windows;
        pub(crate) use windows::WinResourceBridges as ResourceBridges;
        pub type DisplayMode = windows::WinDisplayMode<windows::DisplayDataProvider>;
        pub(crate) use windows::WinDisplayModeArg as DisplayModeArg;
    }
}

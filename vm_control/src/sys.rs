// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub mod unix;
        use unix as platform;
        pub use platform::{VmMsyncRequest, VmMsyncResponse, FsMappingRequest};
        #[cfg(feature = "gpu")]
        pub use platform::gpu::UnixDisplayMode as DisplayMode;
    } else if #[cfg(windows)] {
        pub mod windows;
        pub use windows as platform;
        #[cfg(feature = "gpu")]
        pub type DisplayMode = platform::gpu::WinDisplayMode<platform::gpu::DisplayDataProvider>;
    } else {
        compile_error!("Unsupported platform");
    }
}

pub use platform::handle_request;
pub(crate) use platform::kill_handle;

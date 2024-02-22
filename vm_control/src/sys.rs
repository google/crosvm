// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        pub mod linux;
        use linux as platform;
        pub use platform::{VmMsyncRequest, VmMsyncResponse, FsMappingRequest};
        #[cfg(feature = "gpu")]
        pub use platform::gpu::UnixDisplayMode as DisplayMode;
        pub use platform::handle_request_with_timeout;
        #[cfg(feature = "gpu")]
        pub use platform::gpu::UnixMouseMode as MouseMode;
    } else if #[cfg(windows)] {
        pub mod windows;
        pub use windows as platform;
        #[cfg(feature = "gpu")]
        pub type DisplayMode = platform::gpu::WinDisplayMode<platform::gpu::DisplayDataProvider>;
        #[cfg(feature = "gpu")]
        pub use platform::gpu::WinMouseMode as MouseMode;
    } else {
        compile_error!("Unsupported platform");
    }
}

pub use platform::handle_request;
pub use platform::prepare_shared_memory_region;
pub use platform::should_prepare_memory_region;

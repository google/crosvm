// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub mod unix;
        use unix as platform;
        pub use platform::{VmMsyncRequest, VmMsyncResponse, FsMappingRequest};
    } else if #[cfg(windows)] {
        pub mod windows;
        pub use windows as platform;
    } else {
        compile_error!("Unsupported platform");
    }
}

pub use platform::handle_request;
pub(crate) use platform::kill_handle;

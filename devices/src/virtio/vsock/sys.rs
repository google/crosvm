// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        mod unix;
        use unix as platform;
        pub use crate::virtio::vhost::Vsock;
    } else if #[cfg(windows)] {
        mod windows;
        use windows as platform;
        pub use windows::Vsock;
    }
}

pub use platform::VsockConfig;

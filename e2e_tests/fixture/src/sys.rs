// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        pub(super) mod linux;
        use linux as platform;
    } else if #[cfg(windows)] {
        pub(super) mod windows;
        use windows as platform;
    }
}

pub(super) use platform::binary_name;
pub(super) use platform::SerialArgs;
pub(super) use platform::TestVmSys;

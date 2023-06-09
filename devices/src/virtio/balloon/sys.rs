// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        mod unix;
        use unix as platform;
    } else if #[cfg(windows)] {
        mod windows;
        use windows as platform;
    }
}

pub(in crate::virtio::balloon) use platform::balloon_target_reached;
pub(in crate::virtio::balloon) use platform::free_memory;
pub(in crate::virtio::balloon) use platform::reclaim_memory;

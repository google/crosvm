// Copyright 2022 The Chromium OS Authors. All rights reserved.
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

pub(in crate::virtio::balloon) use platform::free_memory;
pub(in crate::virtio::balloon) use platform::reclaim_memory;
pub(in crate::virtio::balloon) use platform::send_adjusted_response;
pub(in crate::virtio::balloon) use platform::send_adjusted_response_async;
pub(in crate::virtio::balloon) use platform::send_adjusted_response_if_needed;

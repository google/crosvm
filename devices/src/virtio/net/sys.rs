// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        mod linux;
        use linux as platform;
    } else if #[cfg(target_os = "macos")] {
        mod macos;
        use macos as platform;
    } else if #[cfg(windows)] {
        pub mod windows;
        use windows as platform;
    }
}

pub struct PendingBuffer {
    /// According to virtio-spec, the maximum incoming packet will be to 65550 bytes long
    /// (the maximum size of a TCP or UDP packet, plus the 14 byte ethernet header)
    /// The 12byte struct virtio_net_hdr is prepended to this, therefore making it for 65562
    pub buffer: Box<[u8; 65562]>,
    pub length: u32,
}

impl PendingBuffer {
    pub fn new() -> Self {
        PendingBuffer {
            buffer: Box::new([0u8; 65562]),
            length: 0,
        }
    }
}

pub(crate) use platform::process_mrg_rx;
pub(crate) use platform::process_rx;
pub(crate) use platform::process_tx;
pub(crate) use platform::validate_and_configure_tap;
pub(crate) use platform::virtio_features_to_tap_offload;

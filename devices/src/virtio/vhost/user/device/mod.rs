// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod block;
mod handler;

pub use block::run_block_device;

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        #[cfg(feature = "gpu")]
        mod gpu;
        mod console;
        #[cfg(feature = "audio_cras")]
        mod cras_snd;
        mod fs;
        mod net;
        mod vsock;
        mod vvu;
        mod wl;

        pub use vsock::run_vsock_device;
        pub use wl::run_wl_device;
        pub use console::run_console_device;
        #[cfg(feature = "audio_cras")]
        pub use cras_snd::run_cras_snd_device;
        pub use fs::run_fs_device;
        pub use net::run_net_device;
        #[cfg(feature = "gpu")]
        pub use gpu::run_gpu_device;
    } else if #[cfg(windows)] {
        #[cfg(feature = "slirp")]
        mod net;
        #[cfg(feature = "slirp")]
        pub use net::run_net_device;
        #[cfg(feature = "slirp")]
        pub use net::sys::windows::NetBackendConfig;

    }
}

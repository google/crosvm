// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod handler;

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        mod block;
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

        pub use block::{run_block_device, Options as BlockOptions};
        pub use vsock::{run_vsock_device, Options as VsockOptions};
        pub use wl::{run_wl_device, parse_wayland_sock, Options as WlOptions};
        pub use console::{run_console_device, Options as ConsoleOptions};
        #[cfg(feature = "audio_cras")]
        pub use cras_snd::{run_cras_snd_device, Options as CrasSndOptions};
        pub use fs::{run_fs_device, Options as FsOptions};
        pub use net::{run_net_device, Options as NetOptions};
        #[cfg(feature = "gpu")]
        pub use gpu::{run_gpu_device, Options as GpuOptions};
    } else if #[cfg(windows)] {
        #[cfg(feature = "slirp")]
        mod net;
        #[cfg(feature = "slirp")]
        pub use net::run_net_device;
        #[cfg(feature = "slirp")]
        pub use net::sys::windows::NetBackendConfig;

    }
}

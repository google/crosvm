// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod block;
mod console;
#[cfg(feature = "audio_cras")]
mod cras_snd;
mod fs;
#[cfg(feature = "gpu")]
mod gpu;
mod handler;
mod net;
mod vsock;
mod vvu;
mod wl;

pub use block::run_block_device;
pub use console::run_console_device;
#[cfg(feature = "audio_cras")]
pub use cras_snd::run_cras_snd_device;
pub use fs::run_fs_device;
#[cfg(feature = "gpu")]
pub use gpu::run_gpu_device;

#[cfg(any(all(windows, feature = "slirp"), not(windows)))]
pub use net::run_net_device;
pub use vsock::run_vsock_device;
pub use wl::run_wl_device;

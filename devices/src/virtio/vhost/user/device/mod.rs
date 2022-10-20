// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod block;
#[cfg(feature = "gpu")]
pub mod gpu;
mod handler;
mod listener;

pub use block::run_block_device;
pub use block::Options as BlockOptions;
use cros_async::Executor;
#[cfg(feature = "gpu")]
pub use gpu::run_gpu_device;
#[cfg(feature = "gpu")]
pub use gpu::Options as GpuOptions;
pub use handler::VhostBackendReqConnectionState;
pub use handler::VhostUserBackend;
pub use listener::sys::VhostUserListener;
pub use listener::VhostUserListenerTrait;

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        mod console;
        #[cfg(feature = "audio")]
        mod snd;
        mod fs;
        mod net;
        mod vsock;
        mod vvu;
        mod wl;

        pub use vsock::{run_vsock_device, Options as VsockOptions};
        pub use wl::{run_wl_device, parse_wayland_sock, Options as WlOptions};
        pub use console::{create_vu_console_device, run_console_device, Options as ConsoleOptions};
        #[cfg(feature = "audio")]
        pub use snd::{run_snd_device, Options as SndOptions};
        pub use fs::{run_fs_device, Options as FsOptions};
        pub use net::{run_net_device, Options as NetOptions};
    } else if #[cfg(windows)] {
        #[cfg(feature = "slirp")]
        mod net;
        #[cfg(feature = "slirp")]
        pub use net::{run_net_device, Options as NetOptions};
        #[cfg(feature = "slirp")]
        pub use net::sys::windows::NetBackendConfig;

    }
}

/// A trait for vhost-user devices.
///
/// Upon being given an [[Executor]], a device can be converted into a [[VhostUserBackend]], which
/// can then process the requests from the front-end.
///
/// We don't build `VhostUserBackend`s directly because in the case of jailing, the device is built
/// in the main process but it runs in the jailed child process. Since `Executor`s cannot be passed
/// to other processes, we cannot access the device's executor at build time and thus need to
/// perform this 2-step dance before we can run the vhost-user device jailed.
pub trait VhostUserDevice {
    /// The maximum number of queues that this device can manage.
    fn max_queue_num(&self) -> usize;

    /// Turn this device into a `VhostUserBackend`, ready to process requests.
    ///
    /// If the device needs to perform something after being jailed, this is also the right place
    /// to do it.
    fn into_backend(self: Box<Self>, ex: &Executor) -> anyhow::Result<Box<dyn VhostUserBackend>>;
}

// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod block;
#[cfg(feature = "gpu")]
pub mod gpu;
mod handler;
mod listener;
#[cfg(feature = "net")]
mod net;
#[cfg(feature = "audio")]
pub mod snd;

pub use block::run_block_device;
pub use block::Options as BlockOptions;
use cros_async::Executor;
#[cfg(feature = "gpu")]
pub use gpu::run_gpu_device;
#[cfg(feature = "gpu")]
pub use gpu::Options as GpuOptions;
pub use handler::VhostBackendReqConnectionState;
pub use handler::VhostUserDevice;
pub use listener::sys::VhostUserListener;
pub use listener::VhostUserListenerTrait;
#[cfg(feature = "net")]
pub use net::run_net_device;
#[cfg(feature = "net")]
pub use net::NetBackend;
#[cfg(feature = "net")]
pub use net::Options as NetOptions;
#[cfg(feature = "audio")]
pub use snd::run_snd_device;
#[cfg(feature = "audio")]
pub use snd::Options as SndOptions;

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        mod console;
        mod fs;
        mod vsock;
        mod wl;

        pub use vsock::{run_vsock_device, Options as VsockOptions, VhostUserVsockDevice};
        pub use wl::{run_wl_device, parse_wayland_sock, Options as WlOptions};
        pub use console::{create_vu_console_device, run_console_device, Options as ConsoleOptions};
        pub use fs::{run_fs_device, Options as FsOptions};
    } else if #[cfg(windows)] {
        #[cfg(all(feature = "net", feature = "slirp"))]
        pub use net::sys::windows::NetBackendConfig;
    }
}

/// A trait for not-yet-built vhost-user devices.
///
/// Upon being given an [[Executor]], a builder can be converted into a [[vmm_vhost::Backend]],
/// which can then process the requests from the front-end.
///
/// We don't build the device directly to ensure that the device only starts threads in the jailed
/// process, not in the main process. [[VhostUserDeviceBuilder::build()]] is called only after
/// jailing, which ensures that any operations by the device are done in the jailed process.
///
/// TODO: Ideally this would return a [[VhostUserDevice]] instead of [[vmm_vhost::Backend]]. Only
/// the vhost-user vhost-vsock device uses the latter and it can probably be migrated to
/// [[VhostUserDevice]].
pub trait VhostUserDeviceBuilder {
    /// Create the vhost-user device.
    ///
    /// `ex` is an executor the device can use to schedule its tasks.
    fn build(self: Box<Self>, ex: &Executor) -> anyhow::Result<Box<dyn vmm_vhost::Backend>>;
}

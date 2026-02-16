// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::bail;
use argh::FromArgs;
use cros_async::IntoAsync;
use net_util::TapT;
use vm_memory::GuestMemory;

use crate::virtio;
use crate::virtio::vhost_user_backend::net::NetBackend;

/// Platform specific impl of VhostUserDevice::start_queue.
pub(in crate::virtio::vhost_user_backend::net) fn start_queue<T: 'static + IntoAsync + TapT>(
    _backend: &mut NetBackend<T>,
    _idx: usize,
    _queue: virtio::Queue,
    _mem: GuestMemory,
) -> anyhow::Result<()> {
    bail!("vhost-user net queue start is not supported on macOS")
}

#[derive(FromArgs)]
#[argh(subcommand, name = "net")]
/// Net device
pub struct Options {
    #[argh(option, arg_name = "SOCKET_PATH")]
    /// socket path for the device
    device: Vec<String>,
}

/// Starts a vhost-user net device.
/// Returns an error if the given `args` is invalid or the device fails to run.
pub fn start_device(_opts: Options) -> anyhow::Result<()> {
    bail!("vhost-user net device is not supported on macOS")
}

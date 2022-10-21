// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::bail;
use anyhow::Context;
use argh::FromArgs;
use base::info;
use cros_async::Executor;
use hypervisor::ProtectionType;

use crate::virtio::base_features;
use crate::virtio::block::block::DiskOption;
use crate::virtio::vhost::user::device::listener::sys::VhostUserListener;
use crate::virtio::vhost::user::device::listener::VhostUserListenerTrait;
use crate::virtio::vhost::user::VhostUserDevice;
use crate::virtio::BlockAsync;

#[derive(FromArgs)]
#[argh(subcommand, name = "block")]
/// Block device
pub struct Options {
    #[argh(option, arg_name = "PATH<:read-only>")]
    /// path and options of the disk file.
    file: String,
    #[argh(option, arg_name = "PATH")]
    /// path to a vhost-user socket
    socket: Option<String>,
    #[argh(option, arg_name = "STRING")]
    /// VFIO-PCI device name (e.g. '0000:00:07.0')
    vfio: Option<String>,
}

/// Starts a vhost-user block device.
/// Returns an error if the given `args` is invalid or the device fails to run.
pub fn start_device(opts: Options) -> anyhow::Result<()> {
    if !(opts.socket.is_some() ^ opts.vfio.is_some()) {
        bail!("Exactly one of `--socket` or `--vfio` is required");
    }

    let ex = Executor::new().context("failed to create executor")?;

    let mut fileopts = opts.file.split(":").collect::<Vec<_>>();
    let filename = fileopts.remove(0);

    let disk = DiskOption {
        path: filename.into(),
        read_only: fileopts.contains(&"read-only"),
        root: false,
        sparse: false,
        o_direct: false,
        block_size: 512,
        id: None,
    };

    let block = Box::new(BlockAsync::new(
        base_features(ProtectionType::Unprotected),
        disk.open()?,
        disk.read_only,
        disk.sparse,
        disk.block_size,
        None,
        None,
        None,
        None,
    )?)
    .into_backend(&ex)?;

    let listener = VhostUserListener::new_from_socket_or_vfio(
        &opts.socket,
        &opts.vfio,
        block.max_queue_num(),
        None,
    )?;
    info!("vhost-user disk device ready, starting run loop...");
    // run_until() returns an Result<Result<..>> which the ? operator lets us flatten.
    ex.run_until(listener.run_backend(block, &ex))?
}

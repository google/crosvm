// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Context;
use argh::FromArgs;
use base::RawDescriptor;
use cros_async::Executor;
use hypervisor::ProtectionType;

use crate::virtio::base_features;
use crate::virtio::block::DiskOption;
use crate::virtio::vhost_user_backend::BackendConnection;
use crate::virtio::BlockAsync;

#[derive(FromArgs)]
#[argh(subcommand, name = "block")]
/// Block device
pub struct Options {
    #[argh(option, arg_name = "PATH", hidden_help)]
    /// deprecated - please use --socket-path instead
    socket: Option<String>,
    #[argh(option, arg_name = "PATH")]
    /// path to the vhost-user socket to bind to.
    /// If this flag is set, --fd cannot be specified.
    socket_path: Option<String>,
    #[argh(option, arg_name = "FD")]
    /// file descriptor of a connected vhost-user socket.
    /// If this flag is set, --socket-path cannot be specified.
    fd: Option<RawDescriptor>,

    #[argh(option, arg_name = "PATH<:read-only>")]
    /// path and options of the disk file.
    file: String,
}

/// Starts a vhost-user block device.
/// Returns an error if the given `args` is invalid or the device fails to run.
pub fn start_device(opts: Options) -> anyhow::Result<()> {
    let ex = Executor::new().context("failed to create executor")?;

    let mut fileopts = opts.file.split(':').collect::<Vec<_>>();
    let filename = fileopts.remove(0);

    let disk = DiskOption {
        path: filename.into(),
        read_only: fileopts.contains(&"read-only"),
        sparse: false,
        ..DiskOption::default()
    };

    let block = Box::new(BlockAsync::new(
        base_features(ProtectionType::Unprotected),
        disk.open()?,
        &disk,
        None,
        None,
        None,
    )?);

    let conn =
        BackendConnection::from_opts(opts.socket.as_deref(), opts.socket_path.as_deref(), opts.fd)?;

    conn.run_device(ex, block)
}

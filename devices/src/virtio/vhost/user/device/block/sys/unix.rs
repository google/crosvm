// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::OpenOptions;

use anyhow::{bail, Context};
use argh::FromArgs;
use cros_async::Executor;
use disk::create_async_disk_file;
use hypervisor::ProtectionType;

use crate::virtio::base_features;
use crate::virtio::vhost::user::device::{
    block::BlockBackend,
    handler::VhostUserBackend,
    listener::{sys::VhostUserListener, VhostUserListenerTrait},
};

impl BlockBackend {
    /// Creates a new block backend.
    ///
    /// * `ex`: executor used to run this device task.
    /// * `filename`: Name of the disk image file.
    /// * `options`: Vector of file options.
    ///   - `read-only`
    pub(in crate::virtio::vhost::user::device::block) fn new(
        ex: &Executor,
        filename: &str,
        options: Vec<&str>,
    ) -> anyhow::Result<Self> {
        let read_only = options.contains(&"read-only");
        let sparse = false;
        let block_size = 512;
        let f = OpenOptions::new()
            .read(true)
            .write(!read_only)
            .create(false)
            .open(filename)
            .context("Failed to open disk file")?;
        let disk_image = create_async_disk_file(f).context("Failed to create async file")?;
        let base_features = base_features(ProtectionType::Unprotected);

        Self::new_from_async_disk(
            ex,
            disk_image.to_async_disk(ex)?,
            base_features,
            read_only,
            sparse,
            block_size,
        )
    }
}

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

    let block = Box::new(BlockBackend::new(&ex, filename, fileopts)?);
    let listener = VhostUserListener::new_from_socket_or_vfio(
        &opts.socket,
        &opts.vfio,
        block.max_queue_num(),
        None,
    )?;
    // run_until() returns an Result<Result<..>> which the ? operator lets us flatten.
    ex.run_until(listener.run_backend(block, &ex))?
}

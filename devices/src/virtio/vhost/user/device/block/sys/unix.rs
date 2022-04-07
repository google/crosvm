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
use crate::virtio::vhost::user::device::block::{BlockBackend, VhostUserBackend};
use crate::virtio::vhost::user::device::handler::DeviceRequestHandler;
use crate::virtio::vhost::user::device::vvu::pci::VvuPciDevice;

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
#[argh(description = "")]
struct Options {
    #[argh(
        option,
        description = "path and options of the disk file.",
        arg_name = "PATH<:read-only>"
    )]
    file: String,
    #[argh(option, description = "path to a vhost-user socket", arg_name = "PATH")]
    socket: Option<String>,
    #[argh(
        option,
        description = "VFIO-PCI device name (e.g. '0000:00:07.0')",
        arg_name = "STRING"
    )]
    vfio: Option<String>,
}

/// Starts a vhost-user block device.
/// Returns an error if the given `args` is invalid or the device fails to run.
pub(in crate::virtio::vhost::user::device::block) fn start_device(
    program_name: &str,
    args: &[&str],
) -> anyhow::Result<()> {
    let opts = match Options::from_args(&[program_name], args) {
        Ok(opts) => opts,
        Err(e) => {
            if e.status.is_err() {
                bail!(e.output);
            } else {
                println!("{}", e.output);
            }
            return Ok(());
        }
    };

    if !(opts.socket.is_some() ^ opts.vfio.is_some()) {
        bail!("Exactly one of `--socket` or `--vfio` is required");
    }

    let ex = Executor::new().context("failed to create executor")?;

    let mut fileopts = opts.file.split(":").collect::<Vec<_>>();
    let filename = fileopts.remove(0);

    let block = BlockBackend::new(&ex, filename, fileopts)?;
    let handler = DeviceRequestHandler::new(block);
    match (opts.socket, opts.vfio) {
        (Some(socket), None) => {
            // run_until() returns an Result<Result<..>> which the ? operator lets us flatten.
            ex.run_until(handler.run(socket, &ex))?
        }
        (None, Some(device_name)) => {
            let device = VvuPciDevice::new(device_name.as_str(), BlockBackend::MAX_QUEUE_NUM)?;
            ex.run_until(handler.run_vvu(device, &ex))?
        }
        _ => unreachable!("Must be checked above"),
    }
}

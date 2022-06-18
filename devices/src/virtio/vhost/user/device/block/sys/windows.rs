// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;

use anyhow::{bail, Context};
use argh::FromArgs;
use base::{enable_high_res_timers, info, Event, RawDescriptor};
use broker_ipc::{common_child_setup, CommonChildStartupArgs};
use cros_async::Executor;
use disk::{async_ok, AsyncDisk, SingleFileDisk};
use hypervisor::ProtectionType;
use tracing;
use tube_transporter::TubeToken;
use winapi::um::winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE};

use crate::virtio::base_features;
use crate::virtio::block::block::DiskOption;
use crate::virtio::vhost::user::device::block::BlockBackend;
use crate::virtio::vhost::user::device::handler::read_from_tube_transporter;
use crate::virtio::vhost::user::device::handler::DeviceRequestHandler;

impl BlockBackend {
    pub(in crate::virtio::vhost::user::device::block) fn new_from_files(
        ex: &Executor,
        files: Vec<File>,
        base_features: u64,
        read_only: bool,
        sparse: bool,
        block_size: u32,
    ) -> anyhow::Result<BlockBackend> {
        // Safe because the executor is initialized in main() below.
        let disk = Box::new(SingleFileDisk::new_from_files(files, ex)?) as Box<dyn AsyncDisk>;
        Self::new_from_async_disk(ex, disk, base_features, read_only, sparse, block_size)
    }
}

/// Opens a disk image for use by the backend.
fn open_disk_file(disk_option: &DiskOption, take_write_lock: bool) -> anyhow::Result<File> {
    let share_flags = if take_write_lock {
        FILE_SHARE_READ
    } else {
        FILE_SHARE_READ | FILE_SHARE_WRITE
    };
    OpenOptions::new()
        .read(true)
        .write(!disk_option.read_only)
        .share_mode(share_flags)
        .open(&disk_option.path)
        .context("Failed to open disk file")
}

#[derive(FromArgs)]
#[argh(description = "")]
struct Options {
    #[argh(
        option,
        description = "pipe handle end for Tube Transporter",
        arg_name = "HANDLE"
    )]
    bootstrap: usize,
}

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

    tracing::init();

    let raw_transport_tube = opts.bootstrap as RawDescriptor;

    let mut tubes = read_from_tube_transporter(raw_transport_tube)?;

    let vhost_user_tube = tubes.get_tube(TubeToken::VhostUser)?;
    let _control_tube = tubes.get_tube(TubeToken::Control)?;
    let bootstrap_tube = tubes.get_tube(TubeToken::Bootstrap)?;

    let startup_args: CommonChildStartupArgs = bootstrap_tube.recv::<CommonChildStartupArgs>()?;
    common_child_setup(startup_args)?;

    let disk_option: DiskOption = bootstrap_tube.recv::<DiskOption>()?;
    let exit_event = bootstrap_tube.recv::<Event>()?;

    // TODO(b/213146388): Replace below with `broker_ipc::common_child_setup`
    // once `src` directory is upstreamed.
    let _raise_timer_resolution =
        enable_high_res_timers().context("failed to set timer resolution")?;

    info!("using {} IO handles.", disk_option.io_concurrency.get());

    // We can only take the write lock if a single handle is used (otherwise we can't open multiple
    // handles).
    let take_write_lock = disk_option.io_concurrency.get() == 1;

    let mut files = Vec::new();
    for _ in 0..disk_option.io_concurrency.get() {
        files.push(open_disk_file(&disk_option, take_write_lock)?);
    }

    if !async_ok(&files[0])? {
        bail!("found non-raw image; only raw images are supported.");
    }

    let base_features = base_features(ProtectionType::Unprotected);

    let ex = Executor::new().context("failed to create executor")?;

    let block = BlockBackend::new_from_files(
        &ex,
        files,
        base_features,
        disk_option.read_only,
        disk_option.sparse,
        disk_option.block_size,
    )?;

    if sandbox::is_sandbox_target() {
        sandbox::TargetServices::get()
            .expect("failed to get target services")
            .unwrap()
            .lower_token();
    }

    // This is basically the event loop.
    let handler = DeviceRequestHandler::new(Box::new(block));

    if let Err(e) = ex.run_until(handler.run(vhost_user_tube, exit_event, &ex)) {
        bail!("error occurred: {}", e);
    }

    Ok(())
}

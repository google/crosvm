// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;

use anyhow::bail;
use anyhow::Context;
use argh::FromArgs;
use base::enable_high_res_timers;
use base::info;
use base::Event;
use base::RawDescriptor;
use broker_ipc::common_child_setup;
use broker_ipc::CommonChildStartupArgs;
use cros_async::Executor;
use hypervisor::ProtectionType;
use tracing;
use tube_transporter::TubeToken;

use crate::virtio::base_features;
use crate::virtio::block::block::DiskOption;
use crate::virtio::vhost::user::device::block::BlockBackend;
use crate::virtio::vhost::user::device::handler::sys::windows::read_from_tube_transporter;
use crate::virtio::vhost::user::device::handler::DeviceRequestHandler;
use crate::virtio::vhost::user::device::VhostUserDevice;
use crate::virtio::vhost::user::VhostUserBackend;
use crate::virtio::BlockAsync;

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "block", description = "")]
pub struct Options {
    #[argh(
        option,
        description = "pipe handle end for Tube Transporter",
        arg_name = "HANDLE"
    )]
    bootstrap: usize,
}

pub fn start_device(opts: Options) -> anyhow::Result<()> {
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

    let ex = Executor::new().context("failed to create executor")?;

    let block = Box::new(BlockAsync::new(
        base_features(ProtectionType::Unprotected),
        disk_option.open()?,
        disk_option.read_only,
        disk_option.sparse,
        disk_option.block_size,
        None,
        None,
    )?)
    .into_backend(&ex)?;

    // TODO(b/213170185): Uncomment once sandbox is upstreamed.
    //     if sandbox::is_sandbox_target() {
    //         sandbox::TargetServices::get()
    //             .expect("failed to get target services")
    //             .unwrap()
    //             .lower_token();
    //     }

    // This is basically the event loop.
    let handler = DeviceRequestHandler::new(block);

    info!("vhost-user disk device ready, starting run loop...");
    if let Err(e) = ex.run_until(handler.run(vhost_user_tube, exit_event, &ex)) {
        bail!("error occurred: {}", e);
    }

    Ok(())
}

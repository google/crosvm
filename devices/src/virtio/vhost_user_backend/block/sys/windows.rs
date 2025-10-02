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
use cros_async::sys::windows::ExecutorKindSys;
use cros_async::Executor;
use crosvm_cli::sys::windows::exit::Exit;
use crosvm_cli::sys::windows::exit::ExitContext;
use crosvm_cli::sys::windows::exit::ExitContextAnyhow;
use hypervisor::ProtectionType;
use proc_init::common_child_setup;
use proc_init::CommonChildStartupArgs;
use tube_transporter::TubeToken;

use crate::virtio::base_features;
use crate::virtio::block::DiskOption;
use crate::virtio::vhost_user_backend::block::BlockBackend;
use crate::virtio::vhost_user_backend::handler::sys::windows::read_from_tube_transporter;
use crate::virtio::vhost_user_backend::handler::sys::windows::run_handler;
use crate::virtio::vhost_user_backend::VhostUserDevice;
use crate::virtio::vhost_user_backend::VhostUserDeviceBuilder;
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
    cros_tracing::init();

    let raw_transport_tube = opts.bootstrap as RawDescriptor;

    let mut tubes = read_from_tube_transporter(raw_transport_tube)?;

    let vhost_user_tube = tubes.get_tube(TubeToken::VhostUser)?;
    let _control_tube = tubes.get_tube(TubeToken::Control)?;
    let bootstrap_tube = tubes.get_tube(TubeToken::Bootstrap)?;

    let startup_args: CommonChildStartupArgs = bootstrap_tube.recv::<CommonChildStartupArgs>()?;
    let _child_cleanup = common_child_setup(startup_args)?;

    let disk_option: DiskOption = bootstrap_tube.recv::<DiskOption>()?;
    let exit_event = bootstrap_tube.recv::<Event>()?;

    // TODO(b/213146388): Replace below with `proc_init::common_child_setup`
    // once `src` directory is upstreamed.
    let _raise_timer_resolution =
        enable_high_res_timers().context("failed to set timer resolution")?;

    info!("using {:?} executor.", disk_option.async_executor);

    let kind = disk_option.async_executor.unwrap_or_default();
    let ex = Executor::with_executor_kind(kind).context("failed to create executor")?;

    let block = Box::new(BlockAsync::new(
        base_features(ProtectionType::Unprotected),
        disk_option
            .open()
            .exit_context(Exit::OpenDiskImage, "failed to open disk image")?,
        &disk_option,
        None,
        None,
        None,
    )?);

    // TODO(b/213170185): Uncomment once sandbox is upstreamed.
    //     if sandbox::is_sandbox_target() {
    //         sandbox::TargetServices::get()
    //             .expect("failed to get target services")
    //             .unwrap()
    //             .lower_token();
    //     }

    // This is basically the event loop.
    let handler = block.build(&ex)?;

    info!("vhost-user disk device ready, starting run loop...");
    ex.run_until(run_handler(handler, vhost_user_tube, exit_event, &ex))
        .context("run_until error")?
        .context("run_handler error")
}

// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::bail;
use anyhow::Context;
use argh::FromArgs;
use base::info;
use base::Event;
use base::RawDescriptor;
use base::Tube;
use broker_ipc::common_child_setup;
use broker_ipc::CommonChildStartupArgs;
use cros_async::Executor;
use tube_transporter::TubeToken;

use crate::virtio::snd::parameters::Parameters;
use crate::virtio::vhost::user::device::handler::sys::windows::read_from_tube_transporter;
use crate::virtio::vhost::user::device::handler::DeviceRequestHandler;
use crate::virtio::vhost::user::device::snd::SndBackend;
use crate::virtio::vhost::user::device::snd::SND_EXECUTOR;

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "snd", description = "")]
pub struct Options {
    #[argh(
        option,
        description = "pipe handle end for Tube Transporter",
        arg_name = "HANDLE"
    )]
    bootstrap: usize,
}

/// Starts a vhost-user snd device.
/// Returns an error if the given `args` is invalid or the device fails to run.
pub fn run_snd_device(opts: Options) -> anyhow::Result<()> {
    let raw_transport_tube = opts.bootstrap as RawDescriptor;

    let mut tubes = read_from_tube_transporter(raw_transport_tube)?;

    let vhost_user_tube = tubes.get_tube(TubeToken::VhostUser)?;
    let bootstrap_tube = tubes.get_tube(TubeToken::Bootstrap)?;

    let startup_args: CommonChildStartupArgs = bootstrap_tube.recv::<CommonChildStartupArgs>()?;
    let _child_cleanup = common_child_setup(startup_args)?;

    let exit_event = bootstrap_tube.recv::<Event>()?;
    let params = bootstrap_tube.recv::<Parameters>()?;

    let ex = Executor::new().context("Failed to create executor")?;
    let _ = SND_EXECUTOR.set(ex.clone());

    let snd_device = Box::new(SndBackend::new(params)?);

    // TODO(b/213170185): Uncomment once sandbox is upstreamed.
    // if sandbox::is_sandbox_target() {
    //     sandbox::TargetServices::get()
    //         .expect("failed to get target services")
    //         .unwrap()
    //         .lower_token();
    // }

    let handler = DeviceRequestHandler::new(snd_device);

    info!("vhost-user snd device ready, starting run loop...");
    if let Err(e) = ex.run_until(handler.run(vhost_user_tube, exit_event, &ex)) {
        bail!("error occurred: {}", e);
    }

    Ok(())
}

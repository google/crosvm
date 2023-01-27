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
use serde::Deserialize;
use serde::Serialize;
use tube_transporter::TubeToken;

use crate::virtio::snd::parameters::Parameters;
use crate::virtio::vhost::user::device::handler::sys::windows::read_from_tube_transporter;
use crate::virtio::vhost::user::device::handler::sys::windows::run_handler;
use crate::virtio::vhost::user::device::handler::VhostUserRegularOps;
use crate::virtio::vhost::user::device::snd::SndBackend;
use crate::virtio::vhost::user::device::snd::SND_EXECUTOR;
use crate::virtio::vhost::user::device::VhostUserDevice;

pub mod generic;
pub use generic as product;

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

/// Main process end for a sound device.
#[derive(Deserialize, Serialize)]
pub struct SndVmmConfig {
    // Tube for setting up the vhost-user connection. May not exist if not using vhost-user.
    pub main_vhost_user_tube: Option<Tube>,
    // Product related configuration.
    pub product_config: product::SndVmmConfig,
}

/// Config arguments passed through the bootstrap Tube from the broker to the Snd backend
/// process.
#[derive(Deserialize, Serialize)]
pub struct SndBackendConfig {
    // Tube for setting up the vhost-user connection. May not exist if not using vhost-user.
    pub device_vhost_user_tube: Option<Tube>,
    // An event for an incoming exit request.
    pub exit_event: Event,
    // Sound device parameters.
    pub parameters: Parameters,
    // Product related configuration.
    pub product_config: product::SndBackendConfig,
}

/// Configuration for running a Snd device, split by a part sent to the main VMM and a part sent to
/// where the Snd worker will be running (either main process or a vhost-user process).
#[derive(Deserialize, Serialize)]
pub struct SndSplitConfig {
    // Config sent to the backend.
    pub backend_config: Option<SndBackendConfig>,
    // Config sent to the main process.
    pub vmm_config: Option<SndVmmConfig>,
}

/// Starts a vhost-user snd device.
/// Returns an error if the given `args` is invalid or the device fails to run.
pub fn run_snd_device(opts: Options) -> anyhow::Result<()> {
    let raw_transport_tube = opts.bootstrap as RawDescriptor;

    let mut tubes = read_from_tube_transporter(raw_transport_tube)?;

    let bootstrap_tube = tubes.get_tube(TubeToken::Bootstrap)?;

    let startup_args: CommonChildStartupArgs = bootstrap_tube.recv::<CommonChildStartupArgs>()?;
    let _child_cleanup = common_child_setup(startup_args)?;

    let mut config: SndBackendConfig = bootstrap_tube
        .recv()
        .context("failed to parse Snd backend config from bootstrap tube")?;

    let vhost_user_tube = config
        .device_vhost_user_tube
        .expect("vhost-user Snd tube must be set");

    let ex = Executor::new().context("Failed to create executor")?;
    let _ = SND_EXECUTOR.set(ex.clone());

    let snd_device = Box::new(SndBackend::new(config.parameters)?);

    // TODO(b/213170185): Uncomment once sandbox is upstreamed.
    // if sandbox::is_sandbox_target() {
    //     sandbox::TargetServices::get()
    //         .expect("failed to get target services")
    //         .unwrap()
    //         .lower_token();
    // }

    let handler = snd_device.into_req_handler(Box::new(VhostUserRegularOps), &ex)?;

    info!("vhost-user snd device ready, starting run loop...");
    if let Err(e) = ex.run_until(run_handler(
        handler,
        vhost_user_tube,
        config.exit_event,
        &ex,
    )) {
        bail!("error occurred: {}", e);
    }

    Ok(())
}

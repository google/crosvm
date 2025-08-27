// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::bail;
use anyhow::Context;
use argh::FromArgs;
use base::info;
use base::warn;
use base::Event;
use base::RawDescriptor;
use base::Tube;
use cros_async::Executor;
use proc_init::common_child_setup;
use proc_init::CommonChildStartupArgs;
use serde::Deserialize;
use serde::Serialize;
use tube_transporter::TubeToken;

use crate::virtio::snd::parameters::Parameters;
use crate::virtio::snd::sys::set_audio_thread_priority;
use crate::virtio::vhost::user::device::handler::sys::windows::read_from_tube_transporter;
use crate::virtio::vhost::user::device::handler::sys::windows::run_handler;
use crate::virtio::vhost::user::device::snd::SndBackend;
use crate::virtio::vhost::user::VhostUserDeviceBuilder;

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
    // GUID that will be passed into `IAudioClient::Initialize`.
    pub audio_client_guid: String,
    // Used to identify the device backend.
    pub card_index: usize,
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
    // This field is used to pass this GUID to `IAudioClient::Initialize`.
    pub audio_client_guid: String,
    // Used to append to logs in the vhost user device backends.
    pub card_index: usize,
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

    // TODO(b/213170185): Uncomment once sandbox is upstreamed.
    // if sandbox::is_sandbox_target() {
    //     sandbox::TargetServices::get()
    //         .expect("failed to get target services")
    //         .unwrap()
    //         .lower_token();
    // }

    run_snd_device_worker(config)
}

/// Run the SND device worker.
pub fn run_snd_device_worker(config: SndBackendConfig) -> anyhow::Result<()> {
    let card_index = config.card_index;
    let vhost_user_tube = config
        .device_vhost_user_tube
        .unwrap_or_else(|| panic!("[Card {}] vhost-user Snd tube must be set", card_index));

    let ex = Executor::new()
        .with_context(|| format!("[Card {}] Failed to create executor", card_index))?;

    let snd_device = Box::new(SndBackend::new(
        &ex,
        config.parameters,
        Some(config.audio_client_guid),
        config.card_index,
    )?);

    // Set the audio thread priority here. This assumes our executor is running on a single thread.
    let _thread_priority_handle = set_audio_thread_priority();
    if let Err(e) = _thread_priority_handle {
        warn!(
            "[Card {}] Failed to set audio thread to real time: {}",
            card_index, e
        );
    };

    let handler = snd_device.build(&ex)?;

    info!(
        "[Card {}] vhost-user snd device ready, starting run loop...",
        card_index
    );
    ex.run_until(run_handler(
        handler,
        vhost_user_tube,
        config.exit_event,
        &ex,
    ))
    .context("run_until error")?
    .context("run_handler error")
}

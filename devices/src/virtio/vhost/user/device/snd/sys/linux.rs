// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Context;
use argh::FromArgs;
use cros_async::Executor;

use crate::virtio::snd::parameters::Parameters;
use crate::virtio::vhost::user::device::listener::sys::VhostUserListener;
use crate::virtio::vhost::user::device::listener::VhostUserListenerTrait;
use crate::virtio::vhost::user::device::snd::SndBackend;

#[derive(FromArgs)]
#[argh(subcommand, name = "snd")]
/// Snd device
pub struct Options {
    #[argh(option, arg_name = "PATH")]
    /// path to bind a listening vhost-user socket
    socket: String,
    #[argh(
        option,
        arg_name = "CONFIG",
        from_str_fn(snd_parameters_from_str),
        default = "Default::default()",
        long = "config"
    )]
    /// comma separated key=value pairs for setting up cras snd devices.
    /// Possible key values:
    /// capture - Enable audio capture. Default to false.
    /// backend - Which backend to use for vhost-snd (null|cras).
    /// client_type - Set specific client type for cras backend.
    /// socket_type - Set socket type for cras backend.
    /// num_output_devices - Set number of output PCM devices.
    /// num_input_devices - Set number of input PCM devices.
    /// num_output_streams - Set number of output PCM streams per device.
    /// num_input_streams - Set number of input PCM streams per device.
    /// Example: [capture=true,backend=BACKEND,
    /// num_output_devices=1,num_input_devices=1,num_output_streams=1,num_input_streams=1]
    params: Parameters,
}

fn snd_parameters_from_str(input: &str) -> Result<Parameters, String> {
    serde_keyvalue::from_key_values(input).map_err(|e| e.to_string())
}

/// Starts a vhost-user snd device.
/// Returns an error if the given `args` is invalid or the device fails to run.
pub fn run_snd_device(opts: Options) -> anyhow::Result<()> {
    let ex = Executor::new().context("Failed to create executor")?;
    let snd_device = Box::new(SndBackend::new(&ex, opts.params)?);

    let listener = VhostUserListener::new_socket(&opts.socket, None)?;

    listener.run_device(ex, snd_device)
}

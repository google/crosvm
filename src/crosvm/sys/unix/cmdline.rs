// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use argh::FromArgs;
use devices::{
    virtio::vhost::user::{device, VhostUserParams},
    SerialParameters,
};

use crate::crosvm::config::JailConfig;

#[derive(FromArgs)]
#[argh(subcommand)]
/// Unix Devices
pub enum DevicesSubcommand {
    Console(device::ConsoleOptions),
    #[cfg(feature = "audio_cras")]
    Snd(device::SndOptions),
    Fs(device::FsOptions),
    #[cfg(feature = "gpu")]
    Gpu(device::GpuOptions),
    Vsock(device::VsockOptions),
    Wl(device::WlOptions),
}

#[argh_helpers::pad_description_for_argh]
#[derive(FromArgs)]
#[argh(subcommand, name = "devices")]
/// Start one or several jailed device processes.
pub struct DevicesCommand {
    #[argh(switch)]
    /// disable sandboxing. Will nullify the --jail option if it was present.
    pub disable_sandbox: bool,

    #[argh(
        option,
        arg_name = "jail configuration",
        default = "Default::default()"
    )]
    /// set up the jail configuration.
    /// Possible key values:
    ///     pivot-root=/path - Path to empty directory to use for
    ///         sandbox pivot root.
    ///     seccomp-policy-dir=/path - Path to seccomp .policy files
    ///     seccomp-log-failures=(true|false) - Log seccomp filter
    ///         failures instead of them being fatal.
    pub jail: JailConfig,

    #[argh(option, arg_name = "serial options")]
    /// start a serial device (see help from run command for options)
    pub serial: Vec<VhostUserParams<SerialParameters>>,
}

#[derive(FromArgs)]
#[argh(subcommand)]
/// Unix Commands
pub enum Commands {
    #[cfg(unix)]
    Devices(DevicesCommand),
}

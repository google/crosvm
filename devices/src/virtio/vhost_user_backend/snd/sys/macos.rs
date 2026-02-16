// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::bail;
use argh::FromArgs;
use base::RawDescriptor;

#[derive(FromArgs)]
#[argh(subcommand, name = "snd")]
/// Snd device
pub struct Options {
    #[argh(option, arg_name = "PATH", hidden_help)]
    /// deprecated - please use --socket-path instead
    socket: Option<String>,
    #[argh(option, arg_name = "PATH")]
    /// path to the vhost-user socket to bind to.
    /// If this flag is set, --fd cannot be specified.
    socket_path: Option<String>,
    #[argh(option, arg_name = "FD")]
    /// file descriptor of a connected vhost-user socket.
    /// If this flag is set, --socket-path cannot be specified.
    fd: Option<RawDescriptor>,
}

/// Starts a vhost-user snd device.
/// Returns an error if the given `args` is invalid or the device fails to run.
pub fn run_snd_device(_opts: Options) -> anyhow::Result<()> {
    bail!("vhost-user snd device is not supported on macOS")
}

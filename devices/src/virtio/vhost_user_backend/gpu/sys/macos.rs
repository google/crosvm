// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::bail;
use argh::FromArgs;
use base::RawDescriptor;

use crate::virtio::vhost_user_backend::gpu::GpuBackend;
use crate::virtio::GpuParameters;
use crate::virtio::Interrupt;

impl GpuBackend {
    pub fn start_platform_workers(&mut self, _interrupt: Interrupt) -> anyhow::Result<()> {
        // No platform-specific GPU workers on macOS
        Ok(())
    }
}

fn gpu_parameters_from_str(input: &str) -> Result<GpuParameters, String> {
    serde_json::from_str(input).map_err(|e| e.to_string())
}

#[derive(FromArgs)]
/// GPU device
#[argh(subcommand, name = "gpu")]
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
    #[argh(
        option,
        from_str_fn(gpu_parameters_from_str),
        default = "Default::default()",
        arg_name = "JSON"
    )]
    /// a JSON object of virtio-gpu parameters
    params: GpuParameters,
}

pub fn run_gpu_device(_opts: Options) -> anyhow::Result<()> {
    bail!("vhost-user GPU device is not supported on macOS")
}

// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod kumquat;
mod kumquat_gpu;

use clap::Parser;
use kumquat::KumquatBuilder;
use rutabaga_gfx::kumquat_support::RutabagaWritePipe;
use rutabaga_gfx::RutabagaIntoRawDescriptor;
use rutabaga_gfx::RutabagaResult;

#[derive(Parser, Debug)]
#[command(version, about = None, long_about = None)]
struct Args {
    /// Colon-separated list of virtio-gpu capsets.  For example,
    /// "--capset-names=gfxstream-vulkan:cross-domain"
    #[arg(long, default_value = "gfxstream-vulkan")]
    capset_names: String,

    /// Path to the emulated virtio-gpu socket.
    #[arg(long, default_value = "/tmp/kumquat-gpu-0")]
    gpu_socket_path: String,

    /// Opaque renderer specific features
    #[arg(long, default_value = "")]
    renderer_features: String,

    /// An OS-specific pipe descriptor to the parent process
    #[arg(long, default_value = "0")]
    pipe_descriptor: i64,
}

fn main() -> RutabagaResult<()> {
    let args = Args::parse();

    let mut kumquat = KumquatBuilder::new()
        .set_capset_names(args.capset_names)
        .set_gpu_socket((!args.gpu_socket_path.is_empty()).then(|| args.gpu_socket_path))
        .set_renderer_features(args.renderer_features)
        .build()?;

    if args.pipe_descriptor != 0 {
        let write_pipe = RutabagaWritePipe::new(args.pipe_descriptor.into_raw_descriptor());
        write_pipe.write(&1u64.to_ne_bytes())?;
    }

    loop {
        kumquat.run()?;
    }
}

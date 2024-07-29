// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod kumquat;
mod kumquat_gpu;

use std::convert::TryInto;
use std::fs::File;
use std::io::Error as IoError;
use std::io::ErrorKind as IoErrorKind;
use std::io::Write;
use std::path::PathBuf;

use clap::Parser;
use kumquat::Kumquat;
use kumquat_gpu::KumquatGpuConnection;
use rutabaga_gfx::kumquat_support::RutabagaListener;
use rutabaga_gfx::RutabagaError;
use rutabaga_gfx::RutabagaFromRawDescriptor;
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

    let mut kumquat = Kumquat::new(args.capset_names, args.renderer_features)?;
    let mut connection_id: u64 = 0;

    // Remove path if it exists
    let path = PathBuf::from(&args.gpu_socket_path);
    let _ = std::fs::remove_file(&path);

    let listener = RutabagaListener::bind(path)?;

    if args.pipe_descriptor != 0 {
        // SAFETY: We trust the user to provide a valid descriptor. The subsequent write call
        // should fail otherwise.
        let mut pipe: File = unsafe { File::from_raw_descriptor(args.pipe_descriptor.try_into()?) };
        pipe.write(&1u64.to_ne_bytes())?;
    }

    loop {
        match listener.accept() {
            Ok(stream) => {
                connection_id += 1;
                kumquat.add_connection(connection_id, KumquatGpuConnection::new(stream))?;
            }
            Err(RutabagaError::IoError(e)) => match e.kind() {
                IoErrorKind::WouldBlock => (),
                kind => return Err(IoError::from(kind).into()),
            },
            Err(e) => return Err(e),
        };

        kumquat.run()?;
    }
}

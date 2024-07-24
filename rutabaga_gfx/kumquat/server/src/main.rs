// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod kumquat;
mod kumquat_gpu;

use std::io::Error as IoError;
use std::io::ErrorKind as IoErrorKind;
use std::path::PathBuf;

use clap::Parser;
use kumquat::Kumquat;
use kumquat_gpu::KumquatGpuConnection;
use rutabaga_gfx::kumquat_support::RutabagaListener;
use rutabaga_gfx::RutabagaError;
use rutabaga_gfx::RutabagaResult;

#[derive(Parser, Debug)]
#[command(version, about = None, long_about = None)]
struct Args {
    /// Colon-separated list of virtio-gpu capsets.  For example,
    /// "--capset-names=gfxstream-vulkan:cross-domain"
    #[arg(long, default_value = "gfxstream-vulkan")]
    capset_names: String,

    /// Path to the emulated virtio-gpu socket.
    #[arg(long, default_value = "/tmp/rutabaga-0")]
    gpu_socket_path: String,
}

fn main() -> RutabagaResult<()> {
    let args = Args::parse();
    let mut kumquat = Kumquat::new(args.capset_names)?;
    let mut connection_id: u64 = 0;

    // Remove path if it exists
    let path = PathBuf::from(&args.gpu_socket_path);
    let _ = std::fs::remove_file(&path);

    let listener = RutabagaListener::bind(path)?;
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

// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod kumquat;
mod kumquat_gpu;

use std::io::ErrorKind as IoErrorKind;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

use clap::Parser;
use kumquat::Kumquat;
use kumquat_gpu::KumquatGpuConnection;
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

    let path = PathBuf::from(&args.gpu_socket_path);
    // Remove path if it exists
    let _ = std::fs::remove_file(path);

    let listener = UnixListener::bind(args.gpu_socket_path)?;

    listener.set_nonblocking(true)?;
    loop {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    connection_id = connection_id + 1;
                    kumquat.add_connection(connection_id, KumquatGpuConnection::new(stream))?;
                }
                Err(e) => match e.kind() {
                    IoErrorKind::WouldBlock => break,
                    _ => return Err(RutabagaError::Unsupported),
                },
            };
        }

        kumquat.run()?;
    }
}

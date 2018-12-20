// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::io;
use std::path::Path;
use std::process::{self, Command};

fn main() -> io::Result<()> {
    if pkg_config::Config::new()
        .statik(true)
        .probe("libtpm2")
        .is_ok()
    {
        // Use tpm2 package from the standard system location if available.
        return Ok(());
    }

    // Build with `RUSTFLAGS='--cfg hermetic'` to disallow building our own
    // libtpm2 in a production build context. Building from the libtpm2
    // submodule is a convenience only intended for developer environments.
    if cfg!(hermetic) {
        eprintln!("libtpm2 not found; unable to perform hermetic build");
        process::exit(1);
    }

    if !Path::new("libtpm2/.git").exists() {
        Command::new("git")
            .args(&["submodule", "update", "--init"])
            .status()?;
    }

    if !Path::new("libtpm2/build/libtpm2.a").exists() {
        let ncpu = num_cpus::get();
        let status = Command::new("make")
            .arg(format!("-j{}", ncpu))
            .current_dir("libtpm2")
            .status()?;
        if !status.success() {
            process::exit(status.code().unwrap_or(1));
        }
    }

    let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-search={}/libtpm2/build", dir);
    println!("cargo:rustc-link-lib=static=tpm2");
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
    Ok(())
}

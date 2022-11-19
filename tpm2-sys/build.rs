// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use anyhow::bail;
use anyhow::Result;

/// Returns the target triplet prefix for gcc commands. No prefix is required
/// for native builds.
fn get_cross_compile_prefix() -> String {
    let target = env::var("TARGET").unwrap();

    if env::var("HOST").unwrap() == target {
        return String::from("");
    }

    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let env = if target.ends_with("-gnueabihf") {
        String::from("gnueabihf")
    } else {
        env::var("CARGO_CFG_TARGET_ENV").unwrap()
    };
    format!("{}-{}-{}-", arch, os, env)
}

fn build_libtpm2(out_dir: &Path) -> Result<()> {
    let lib_path = out_dir.join("libtpm2.a");
    if lib_path.exists() {
        return Ok(());
    }

    if !Path::new("libtpm2/.git").exists() {
        bail!(
            "tpm2-sys/libtpm2 source does not exist, did you forget to \
            `git submodule update --init`?"
        );
    }

    let make_flags = env::var("CARGO_MAKEFLAGS").unwrap();
    let prefix = get_cross_compile_prefix();
    let status = Command::new("make")
        .env("MAKEFLAGS", make_flags)
        .arg(format!("AR={}ar", prefix))
        .arg(format!("CC={}gcc", prefix))
        .arg(format!("OBJCOPY={}objcopy", prefix))
        .arg("CFLAGS=-Wno-error")
        .arg(format!("obj={}", out_dir.display()))
        .current_dir("libtpm2")
        .status()?;
    if !status.success() {
        bail!("make failed with status: {}", status);
    }
    Ok(())
}

fn main() -> Result<()> {
    // Skip installing dependencies when generating documents.
    if std::env::var("CARGO_DOC").is_ok() {
        return Ok(());
    }

    // Use tpm2 package from the standard system location if available.
    if pkg_config::Config::new()
        .statik(true)
        .probe("libtpm2")
        .is_ok()
    {
        return Ok(());
    }

    // Otherwise build from source
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    build_libtpm2(&out_dir)?;

    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=tpm2");
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
    Ok(())
}

// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::{bail, Result};
use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

const MINIGBM_SRC: &str = "../third_party/minigbm";
const VIRGLRENDERER_SRC: &str = "../third_party/virglrenderer";

fn is_native_build() -> bool {
    env::var("HOST").unwrap() == env::var("TARGET").unwrap()
}

/// Returns the target triplet prefix for gcc commands. No prefix is required
/// for native builds.
fn get_cross_compile_prefix() -> String {
    if is_native_build() {
        return String::from("");
    }

    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let env = env::var("CARGO_CFG_TARGET_ENV").unwrap();
    return format!("{}-{}-{}-", arch, os, env);
}

/// For cross-compilation with meson, we need to pick a cross-file, which
/// live in /usr/local/share/meson/cross.
fn get_meson_cross_args() -> Vec<String> {
    if is_native_build() {
        Vec::new()
    } else {
        vec![
            "--cross-file".to_string(),
            env::var("CARGO_CFG_TARGET_ARCH").unwrap(),
        ]
    }
}

fn build_minigbm(out_dir: &Path) -> Result<()> {
    let lib_path = out_dir.join("libgbm.a");
    if lib_path.exists() {
        return Ok(());
    }

    if !Path::new("../third_party/minigbm/.git").exists() {
        bail!(
            "third_party/minigbm source does not exist, did you forget to \
            `git submodule update --init`?"
        );
    }

    let make_flags = env::var("CARGO_MAKEFLAGS").unwrap();
    let status = Command::new("make")
        .env("MAKEFLAGS", make_flags)
        .env("CROSS_COMPILE", get_cross_compile_prefix())
        .arg(format!("OUT={}", out_dir.display()))
        .arg("CC_STATIC_LIBRARY(libminigbm.pie.a)")
        .current_dir("../third_party/minigbm")
        .status()?;
    if !status.success() {
        bail!("make failed with status: {}", status);
    }

    // minigbm will be linked using the name gbm, make sure it can be found.
    fs::copy(out_dir.join("libminigbm.pie.a"), out_dir.join("libgbm.a"))?;
    Ok(())
}

fn build_virglrenderer(out_dir: &Path) -> Result<()> {
    let lib_path = out_dir.join("src/libvirglrenderer.a");
    if lib_path.exists() {
        return Ok(());
    }

    if !Path::new("../third_party/virglrenderer/.git").exists() {
        bail!(
            "third_party/virglrenderer source does not exist, did you forget to \
            `git submodule update --init`?"
        );
    }

    let minigbm_src_abs = PathBuf::from(MINIGBM_SRC).canonicalize()?;
    let status = Command::new("meson")
        .env("PKG_CONFIG_PATH", &minigbm_src_abs)
        .arg("setup")
        .arg("-Ddefault_library=static")
        .args(get_meson_cross_args())
        .arg(out_dir.as_os_str())
        .current_dir(VIRGLRENDERER_SRC)
        .status()?;
    if !status.success() {
        bail!("meson setup failed with status: {}", status);
    }

    // Add local minigbm paths to make sure virglrenderer can build against it.
    let mut cmd = Command::new("meson");
    cmd.env("CPATH", &minigbm_src_abs)
        .arg("compile")
        .arg("src/virglrenderer")
        .current_dir(out_dir);

    let status = cmd.status()?;
    if !status.success() {
        bail!("meson compile failed with status: {}", status);
    }
    Ok(())
}

fn virglrenderer() -> Result<()> {
    // System provided runtime dependencies.
    pkg_config::Config::new().probe("epoxy")?;
    pkg_config::Config::new().probe("libdrm")?;

    // Use virglrenderer package from the standard system location if available.
    if pkg_config::Config::new().probe("virglrenderer").is_ok() {
        return Ok(());
    }

    // Otherwise build from source.
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let minigbm_out = out_dir.join("minigbm");
    let virglrenderer_out = out_dir.join("virglrenderer");
    build_minigbm(&minigbm_out)?;
    build_virglrenderer(&virglrenderer_out)?;

    println!(
        "cargo:rustc-link-search={}/src",
        virglrenderer_out.display()
    );
    println!("cargo:rustc-link-search={}", minigbm_out.display());
    println!("cargo:rustc-link-lib=static=virglrenderer");
    println!("cargo:rustc-link-lib=static=gbm");
    Ok(())
}

fn main() -> Result<()> {
    #[cfg(feature = "virgl_renderer")]
    virglrenderer()?;

    Ok(())
}

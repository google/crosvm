// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(feature = "virgl_renderer")]
use std::env;
#[cfg(feature = "virgl_renderer")]
use std::fs;
#[cfg(feature = "virgl_renderer")]
use std::path::Path;
#[cfg(feature = "virgl_renderer")]
use std::path::PathBuf;
#[cfg(feature = "virgl_renderer")]
use std::process::Command;

#[cfg(feature = "virgl_renderer")]
use anyhow::bail;
use anyhow::Result;

#[cfg(feature = "virgl_renderer")]
const MINIGBM_SRC: &str = "../third_party/minigbm";
#[cfg(feature = "virgl_renderer")]
const VIRGLRENDERER_SRC: &str = "../third_party/virglrenderer";

#[cfg(feature = "virgl_renderer")]
fn is_native_build() -> bool {
    env::var("HOST").unwrap() == env::var("TARGET").unwrap()
}

/// Returns the target triplet prefix for gcc commands. No prefix is required
/// for native builds.
#[cfg(feature = "virgl_renderer")]
fn get_cross_compile_prefix() -> String {
    if is_native_build() {
        return String::from("");
    }

    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let env = env::var("CARGO_CFG_TARGET_ENV").unwrap();
    format!("{}-{}-{}-", arch, os, env)
}

/// For cross-compilation with meson, we need to pick a cross-file, which
/// live in /usr/local/share/meson/cross.
#[cfg(feature = "virgl_renderer")]
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

#[cfg(feature = "virgl_renderer")]
fn build_minigbm(out_dir: &Path) -> Result<()> {
    let lib_path = out_dir.join("libgbm.a");
    if lib_path.exists() {
        return Ok(());
    }

    if !Path::new(MINIGBM_SRC).join(".git").exists() {
        bail!(
            "{} source does not exist, did you forget to \
            `git submodule update --init`?",
            MINIGBM_SRC
        );
    }

    let make_flags = env::var("CARGO_MAKEFLAGS").unwrap();
    let status = Command::new("make")
        .env("MAKEFLAGS", make_flags)
        .env("CROSS_COMPILE", get_cross_compile_prefix())
        .arg(format!("OUT={}", out_dir.display()))
        .arg("CC_STATIC_LIBRARY(libminigbm.pie.a)")
        .current_dir(MINIGBM_SRC)
        .status()?;
    if !status.success() {
        bail!("make failed with status: {}", status);
    }

    // minigbm will be linked using the name gbm, make sure it can be found.
    fs::copy(out_dir.join("libminigbm.pie.a"), out_dir.join("libgbm.a"))?;
    Ok(())
}

#[cfg(feature = "virgl_renderer")]
fn build_virglrenderer(out_dir: &Path) -> Result<()> {
    let lib_path = out_dir.join("src/libvirglrenderer.a");
    if lib_path.exists() {
        return Ok(());
    }

    if !Path::new(VIRGLRENDERER_SRC).join(".git").exists() {
        bail!(
            "{} source does not exist, did you forget to \
            `git submodule update --init`?",
            VIRGLRENDERER_SRC
        );
    }

    let platforms = [
        "egl",
        #[cfg(feature = "x")]
        "glx",
    ];

    let minigbm_src_abs = PathBuf::from(MINIGBM_SRC).canonicalize()?;
    let status = Command::new("meson")
        .env("PKG_CONFIG_PATH", &minigbm_src_abs)
        .arg("setup")
        .arg(format!("-Dplatforms={}", platforms.join(",")))
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

#[cfg(feature = "virgl_renderer")]
fn virglrenderer_deps() -> Result<()> {
    // System provided runtime dependencies.
    pkg_config::Config::new().probe("epoxy")?;
    pkg_config::Config::new().probe("libdrm")?;
    Ok(())
}

#[cfg(feature = "virgl_renderer")]
fn virglrenderer() -> Result<()> {
    // Use virglrenderer package from the standard system location if available.
    if pkg_config::Config::new().probe("virglrenderer").is_ok() {
        virglrenderer_deps()?;
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

    virglrenderer_deps()?;

    Ok(())
}

#[cfg(all(feature = "gfxstream", not(feature = "gfxstream_stub")))]
fn gfxstream() -> Result<()> {
    let gfxstream_path = std::env::var("GFXSTREAM_PATH")?;
    println!("cargo:rustc-link-lib=gfxstream_backend");
    println!("cargo:rustc-link-search={}", gfxstream_path);
    Ok(())
}

fn main() -> Result<()> {
    // Skip installing dependencies when generating documents.
    if std::env::var("CARGO_DOC").is_ok() {
        return Ok(());
    }

    #[cfg(feature = "virgl_renderer")]
    virglrenderer()?;
    #[cfg(all(feature = "gfxstream", not(feature = "gfxstream_stub")))]
    gfxstream()?;

    Ok(())
}

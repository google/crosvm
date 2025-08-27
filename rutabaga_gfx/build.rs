// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;

use pkg_config::Error;

pub type PkgConfigResult<T> = std::result::Result<T, Error>;

fn minigbm() -> PkgConfigResult<()> {
    pkg_config::probe_library("gbm")?;
    Ok(())
}

fn virglrenderer() -> PkgConfigResult<()> {
    let lib = pkg_config::Config::new()
        .atleast_version("1.0.0")
        .probe("virglrenderer")?;
    if lib.defines.contains_key("VIRGL_RENDERER_UNSTABLE_APIS") {
        println!("cargo:rustc-cfg=virgl_renderer_unstable");
    }
    Ok(())
}

fn gfxstream() -> PkgConfigResult<()> {
    let mut gfxstream_path_env_override =
        // We use the unrecommended PROFILE environment variable here, because the Windows
        // downstream can set debug = true for the release profile to keep the symbol files.
        if env::var("PROFILE").as_deref() == Ok("debug") {
            env::var("GFXSTREAM_PATH_DEBUG")
        } else {
            env::var("GFXSTREAM_PATH_RELEASE")
        }
        .ok();
    gfxstream_path_env_override = gfxstream_path_env_override.filter(|s| !s.is_empty());
    if gfxstream_path_env_override.is_none() {
        gfxstream_path_env_override = env::var("GFXSTREAM_PATH").ok();
    }
    gfxstream_path_env_override = gfxstream_path_env_override.filter(|s| !s.is_empty());

    if let Some(gfxstream_path) = gfxstream_path_env_override {
        println!("cargo:rustc-link-lib=gfxstream_backend");
        println!("cargo:rustc-link-search={}", gfxstream_path);
        Ok(())
    } else {
        let gfxstream_lib = pkg_config::Config::new().probe("gfxstream_backend")?;
        let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();

        if gfxstream_lib.defines.contains_key("GFXSTREAM_UNSTABLE") {
            println!("cargo:rustc-cfg=gfxstream_unstable");
        } else {
            pkg_config::Config::new().probe("aemu_base")?;
            pkg_config::Config::new().probe("aemu_host_common")?;
            pkg_config::Config::new().probe("aemu_logging")?;
            pkg_config::Config::new().probe("aemu_snapshot")?;

            if target_os.contains("linux") {
                pkg_config::Config::new().probe("libdrm")?;
            }
        }

        let mut use_clang = target_os.contains("macos");
        if env::var("USE_CLANG").is_ok() {
            use_clang = true;
        }

        // Need to link against libc++ or libstdc++.  Apple is clang-only, while by default other
        // Unix platforms use libstdc++.
        if use_clang {
            println!("cargo:rustc-link-lib=dylib=c++");
        } else if target_os.contains("linux") || target_os.contains("nto") {
            println!("cargo:rustc-link-lib=dylib=stdc++");
        }

        Ok(())
    }
}

fn main() -> PkgConfigResult<()> {
    println!("cargo:rustc-check-cfg=cfg(fence_passing_option1)");
    println!("cargo:rustc-check-cfg=cfg(gfxstream_unstable)");
    println!("cargo:rustc-check-cfg=cfg(virgl_renderer_unstable)");
    let mut use_fence_passing_option1 = true;

    // Skip installing dependencies when generating documents.
    if env::var("CARGO_DOC").is_ok() {
        return Ok(());
    }

    if env::var("CARGO_FEATURE_VIRGL_RENDERER").is_ok() {
        virglrenderer()?;
        use_fence_passing_option1 = false;
    }

    if env::var("CARGO_FEATURE_MINIGBM").is_ok() {
        minigbm()?;
    }

    if env::var("CARGO_FEATURE_GFXSTREAM").is_ok()
        && env::var("CARGO_FEATURE_GFXSTREAM_STUB").is_err()
    {
        gfxstream()?;
    }

    if use_fence_passing_option1 {
        println!("cargo:rustc-cfg=fence_passing_option1");
    }

    Ok(())
}

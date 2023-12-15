// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;

fn is_native_build() -> bool {
    env::var("HOST").unwrap() == env::var("TARGET").unwrap()
}

fn use_system_minigbm() -> bool {
    println!("cargo:rerun-if-env-changed=CROSVM_BUILD_VARIANT");
    println!("cargo:rerun-if-env-changed=CROSVM_USE_SYSTEM_MINIGBM");
    env::var("CROSVM_BUILD_VARIANT").unwrap_or_default() == "chromeos"
        || env::var("CROSVM_USE_SYSTEM_MINIGBM").unwrap_or_else(|_| "0".to_string()) != "0"
}

fn use_system_virglrenderer() -> bool {
    println!("cargo:rerun-if-env-changed=CROSVM_BUILD_VARIANT");
    println!("cargo:rerun-if-env-changed=CROSVM_USE_SYSTEM_VIRGLRENDERER");
    env::var("CROSVM_BUILD_VARIANT").unwrap_or_default() == "chromeos"
        || env::var("CROSVM_USE_SYSTEM_VIRGLRENDERER").unwrap_or_else(|_| "0".to_string()) != "0"
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
    format!("{}-{}-{}-", arch, os, env)
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

fn env_prepend_pkg_config_path(new_path: &Path) -> Result<()> {
    const KEY: &str = "PKG_CONFIG_PATH";
    let new_path_string = new_path
        .to_str()
        .ok_or(anyhow!("failed to convert path to string"))?;
    if let Ok(original_value) = env::var(KEY) {
        env::set_var(KEY, format!("{}:{}", new_path_string, original_value));
    } else {
        env::set_var(KEY, new_path);
    };
    Ok(())
}

/// Builds from pinned commit as static library and probes the generated pkgconfig file to emit
/// cargo linking metadata
fn build_and_probe_minigbm(out_dir: &Path) -> Result<()> {
    const SOURCE_DIR: &str = "../third_party/minigbm";
    let pkgconfig_file = out_dir.join("gbm.pc");

    println!("cargo:rerun-if-changed={}", SOURCE_DIR);

    if !Path::new(SOURCE_DIR).join(".git").exists() {
        bail!(
            "{} source does not exist, did you forget to \
            `git submodule update --init`?",
            SOURCE_DIR
        );
    }

    // build static library
    let make_flags = env::var("CARGO_MAKEFLAGS").unwrap();
    let status = Command::new("make")
        .env("MAKEFLAGS", make_flags)
        .env("VERBOSE", "1")
        .env("CROSS_COMPILE", get_cross_compile_prefix())
        .arg(format!("OUT={}", out_dir.display()))
        .arg("CC_STATIC_LIBRARY(libminigbm.pie.a)")
        .current_dir(SOURCE_DIR)
        .status()?;
    if !status.success() {
        bail!("make failed with status: {}", status);
    }

    // copy headers to build output
    let src_dir = Path::new(SOURCE_DIR);
    fs::copy(src_dir.join("gbm.h"), out_dir.join("gbm.h"))?;
    fs::copy(
        src_dir.join("minigbm_helpers.h"),
        out_dir.join("minigbm_helpers.h"),
    )?;

    // minigbm will be linked using the name gbm, make sure it can be found.
    fs::copy(out_dir.join("libminigbm.pie.a"), out_dir.join("libgbm.a"))?;

    // write out a custom pkgconfig
    let mut conf = File::create(pkgconfig_file)?;
    let contents = format!(
        r#"prefix={install_dir}
includedir=${{prefix}}
libdir=${{prefix}}

Name: libgbm
Description: A small gbm implementation
Version: 18.0.0
Cflags: -I${{includedir}}
Libs: -L${{libdir}} -lgbm
Requires.private: libdrm >= 2.4.50
"#,
        install_dir = out_dir.display()
    );
    conf.write_all(contents.as_bytes())?;

    // let pkg_config crate configure the cargo link metadata according to the custom pkgconfig
    // above
    env_prepend_pkg_config_path(out_dir)?;
    let mut config = pkg_config::Config::new();
    config.statik(true).probe("gbm")?;
    Ok(())
}

fn minigbm() -> Result<()> {
    if use_system_minigbm() {
        pkg_config::probe_library("gbm").context("pkgconfig failed to find gbm")?;
    } else {
        // Otherwise build from source and emit cargo build metadata
        let out_dir = PathBuf::from(env::var("OUT_DIR")?).join("minigbm");
        build_and_probe_minigbm(&out_dir).context("failed building minigbm")?;
    };
    Ok(())
}

/// Builds from pinned commit as static library and probes the generated pkgconfig file to emit
/// cargo linking metadata
fn build_and_probe_virglrenderer(out_dir: &Path) -> Result<()> {
    const SOURCE_DIR: &str = "../third_party/virglrenderer";
    let install_prefix = out_dir.join("installed");

    println!("cargo:rerun-if-changed={}", SOURCE_DIR);

    if !Path::new(SOURCE_DIR).join(".git").exists() {
        bail!(
            "{} source does not exist, did you forget to \
                `git submodule update --init`?",
            SOURCE_DIR
        );
    }

    let mut platforms = vec!["egl"];
    if env::var("CARGO_FEATURE_X").is_ok() {
        platforms.push("glx");
    }

    // Ensures minigbm is available and that it's pkgconfig is locatable
    minigbm()?;

    let mut setup = Command::new("meson");
    setup
        .arg("setup")
        .current_dir(SOURCE_DIR)
        .arg("--prefix")
        .arg(install_prefix.as_os_str())
        .arg("--libdir")
        .arg("lib")
        .args(get_meson_cross_args())
        .arg(format!("-Dplatforms={}", platforms.join(",")))
        .arg("-Ddefault_library=static")
        .arg(out_dir.as_os_str());

    let setup_status = setup.status()?;
    if !setup_status.success() {
        bail!("meson setup failed with status: {}", setup_status);
    }

    let mut compile = Command::new("meson");
    compile
        .arg("compile")
        .arg("src/virglrenderer")
        .current_dir(out_dir);
    let compile_status = compile.status()?;
    if !compile_status.success() {
        bail!("meson compile failed with status: {}", compile_status);
    }

    let mut install = Command::new("meson");
    install.arg("install").current_dir(out_dir);
    let install_status = install.status()?;
    if !install_status.success() {
        bail!("meson install failed with status: {}", install_status);
    }

    let pkg_config_path = install_prefix.join("lib/pkgconfig");
    assert!(pkg_config_path.join("virglrenderer.pc").exists());

    // let pkg_config crate configure the cargo link metadata according to the generated pkgconfig
    env_prepend_pkg_config_path(pkg_config_path.as_path())?;
    let mut config = pkg_config::Config::new();
    config.statik(true).probe("virglrenderer")?;

    Ok(())
}

fn virglrenderer() -> Result<()> {
    if use_system_virglrenderer() && !use_system_minigbm() {
        bail!("Must use system minigbm if using system virglrenderer (try setting CROSVM_USE_SYSTEM_MINIGBM=1)");
    }

    // Use virglrenderer package from pkgconfig on ChromeOS builds
    if use_system_virglrenderer() {
        let lib = pkg_config::Config::new()
            .atleast_version("1.0.0")
            .probe("virglrenderer")
            .context("pkgconfig failed to find virglrenderer")?;
        if lib.defines.contains_key("VIRGL_RENDERER_UNSTABLE_APIS") {
            println!("cargo:rustc-cfg=virgl_renderer_unstable");
        }
    } else {
        // Otherwise build from source.
        let out_dir = PathBuf::from(env::var("OUT_DIR")?).join("virglrenderer");
        build_and_probe_virglrenderer(&out_dir)?;
    }
    Ok(())
}

fn gfxstream() -> Result<()> {
    if let Ok(gfxstream_path) = env::var("GFXSTREAM_PATH") {
        println!("cargo:rustc-link-lib=gfxstream_backend");
        println!("cargo:rustc-link-search={}", gfxstream_path);
        Ok(())
    } else {
        pkg_config::Config::new().probe("gfxstream_backend")?;
        pkg_config::Config::new().probe("aemu_base")?;
        pkg_config::Config::new().probe("aemu_host_common")?;
        pkg_config::Config::new().probe("aemu_logging")?;
        pkg_config::Config::new().probe("aemu_snapshot")?;

        let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();

        if target_os.contains("linux") {
            pkg_config::Config::new().probe("libdrm")?;
        }

        // Need to link against libc++ or libstdc++.  Apple is clang-only, while by default other
        // Unix platforms use libstdc++.
        if target_os.contains("macos") {
            println!("cargo:rustc-link-lib=dylib=c++");
        } else if target_os.contains("linux") || target_os.contains("nto") {
            println!("cargo:rustc-link-lib=dylib=stdc++");
        }

        Ok(())
    }
}

fn main() -> Result<()> {
    // Skip installing dependencies when generating documents.
    if env::var("CARGO_DOC").is_ok() {
        return Ok(());
    }

    if env::var("CARGO_FEATURE_MINIGBM").is_ok() {
        minigbm()?;
    }

    if env::var("CARGO_FEATURE_VIRGL_RENDERER").is_ok() {
        virglrenderer()?;
    }

    if env::var("CARGO_FEATURE_GFXSTREAM").is_ok()
        && env::var("CARGO_FEATURE_GFXSTREAM_STUB").is_err()
    {
        gfxstream()?;
    }

    Ok(())
}

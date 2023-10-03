// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::path::Path;
use std::path::PathBuf;

use anyhow::anyhow;
use anyhow::Result;
use named_lock::NamedLock;

mod sys;

static BASE_URL: &str = "https://storage.googleapis.com/chromeos-localmirror/distfiles/prebuilts/";
static DOWNLOAD_RETRIES: usize = 3;

// Returns `deps` directory for the current build.
fn get_deps_directory() -> Result<PathBuf> {
    let out_dir = env::var("OUT_DIR")
        .ok()
        .ok_or_else(|| anyhow!("OUT_DIR is not set"))?;

    let dest = PathBuf::from(&out_dir)
        .parent()
        .ok_or_else(|| anyhow!("../ not found for {:?}", out_dir))?
        .parent()
        .ok_or_else(|| anyhow!("../../ not found for {:?}", out_dir))?
        .parent()
        .ok_or_else(|| anyhow!("../../../ not found for {:?}", out_dir))?
        .join("deps");
    if dest.is_dir() {
        Ok(dest)
    } else {
        Err(anyhow!(
            "deps({:?}) directory not found OUT_DIR: {:?}",
            dest,
            out_dir
        ))
    }
}

// We download the prebuilt into deps directory and create a symlink to the downloaded prebuilt in
// deps parent directory.
// The symlink will help windows find the dll when an executable is manually run.
// For example, `file` is downloaded in
// `target/x86_64-pc-windows-gnu/release/deps/` and a `link` will be crated in
// `target/x86_64-pc-windows-gnu/release/`.
// Any executable in those two directories will be able to find the dlls they depend as in the same
// directory.
struct PrebuiltPath {
    file: PathBuf,
    link: PathBuf,
}

fn get_dest_path(filename: &str) -> Result<PrebuiltPath> {
    let deps = get_deps_directory()?;

    Ok(PrebuiltPath {
        file: deps.join(filename),
        link: deps.parent().unwrap().join(filename),
    })
}

fn get_url(library: &str, filename: &str, version: u32) -> String {
    let build_type = if env::var("DEBUG").is_ok() {
        "debug"
    } else {
        "release"
    };
    let platform = env::var("CARGO_CFG_TARGET_FAMILY").unwrap();
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let toolchain = env::var("CARGO_CFG_TARGET_ENV").unwrap();

    format!("{BASE_URL}{platform}/{arch}/{toolchain}/{library}/{build_type}/{version}/{filename}",)
}

pub fn download_file(url: &str, destination: &Path) -> Result<()> {
    let lock = NamedLock::create("crosvm_prebuilts_download")?;
    let _guard = lock.lock()?;

    // Another process may have already downloaded this since we last checked.
    if destination.exists() {
        println!("Prebuilt {destination:?} has already been downloaded by another process.");
        return Ok(());
    }

    println!("Downloading prebuilt {url} to {destination:?}");
    let mut attempts_left = DOWNLOAD_RETRIES + 1;
    loop {
        attempts_left -= 1;
        let mut cmd = sys::download_command(url, destination);
        match cmd.status() {
            Ok(exit_code) => {
                if !exit_code.success() {
                    if attempts_left == 0 {
                        return Err(anyhow!("Cannot download {}", url));
                    } else {
                        println!("Failed to download {url}. Retrying.");
                    }
                } else {
                    return Ok(());
                }
            }
            Err(error) => {
                if attempts_left == 0 {
                    return Err(anyhow!(error));
                } else {
                    println!("Failed to download {url}: {error:?}");
                }
            }
        }
    }
}

/// Downloads a prebuilt file, with name `filename` of `version` from the `library` into target's
/// `deps` directory.
pub fn download_prebuilt(library: &str, version: u32, filename: &str) -> Result<PathBuf> {
    let dest_path = get_dest_path(filename)?;
    let url = get_url(library, filename, version);

    println!("downloading prebuilt:{} to:{:?}", url, dest_path.file);
    download_file(&url, Path::new(&dest_path.file))?;
    println!(
        "creating symlink:{:?} linking to:{:?}",
        dest_path.link, dest_path.file
    );
    let _ = std::fs::remove_file(&dest_path.link);
    #[cfg(any(target_os = "android", target_os = "linux"))]
    std::os::unix::fs::symlink(&dest_path.file, &dest_path.link)?;
    #[cfg(windows)]
    let _ = std::fs::copy(&dest_path.file, &dest_path.link)?;
    Ok(dest_path.file)
}

/// Downloads a list of prebuilt file, with names in `filenames` of `version` from the `library`
/// into target's `deps` directory.
pub fn download_prebuilts(library: &str, version: u32, filenames: &[&str]) -> Result<Vec<PathBuf>> {
    let mut paths = vec![];
    for filename in filenames {
        paths.push(download_prebuilt(library, version, filename)?);
    }
    Ok(paths)
}

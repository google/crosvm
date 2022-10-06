// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::path::Path;
use std::path::PathBuf;

use anyhow::anyhow;
use anyhow::Result;

mod sys;

static BASE_URL: &str = "https://storage.googleapis.com/chromeos-localmirror/distfiles/prebuilts/";

// Returns `deps` directory for the current build.
fn get_deps_directory() -> Result<PathBuf> {
    let out_dir = env::var("OUT_DIR")
        .ok()
        .ok_or(anyhow!("OUT_DIR is not set"))?;

    let dest = PathBuf::from(&out_dir)
        .parent()
        .ok_or(anyhow!("../ not found for {:?}", out_dir))?
        .parent()
        .ok_or(anyhow!("../../ not found for {:?}", out_dir))?
        .parent()
        .ok_or(anyhow!("../../../ not found for {:?}", out_dir))?
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

fn get_dest_path(filename: &str) -> Result<PathBuf> {
    let dest = get_deps_directory()?;

    Ok(dest.join(filename))
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

fn download_file(url: &str, destination: &Path) -> Result<()> {
    let mut cmd = sys::download_command(url, destination);
    match cmd.status() {
        Ok(exit_code) => {
            if !exit_code.success() {
                Err(anyhow!("Cannot download {}", url))
            } else {
                Ok(())
            }
        }
        Err(error) => Err(anyhow!(error)),
    }
}

/// Downloads a prebuilt file, with name `filename` of `version` from the `library` into target's
/// `deps` directory.
pub fn download_prebuilt(library: &str, version: u32, filename: &str) -> Result<PathBuf> {
    let dest_path = get_dest_path(filename)?;
    let url = get_url(library, filename, version);
    println!("downloading prebuilt:{} to:{:?}", url, dest_path);

    download_file(&url, Path::new(&dest_path))?;
    Ok(dest_path)
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

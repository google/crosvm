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

#[cfg(test)]
mod tests {
    use std::env;

    use tempfile::TempDir;

    use super::download_prebuilt;
    use super::download_prebuilts;

    static LIBRARY: &str = "prebuilts_test";
    static PREBUILT_FILE1: &str = "prebuilt_test";
    static PREBUILT_FILE2: &str = "prebuilt_test2";
    static VERSION: u32 = 1;

    fn setup_env(build_type: &str) -> TempDir {
        let tempdir = tempfile::tempdir().unwrap();
        if build_type == "debug" {
            env::set_var("DEBUG", "");
        } else {
            env::remove_var("DEBUG");
        }
        env::set_var("CARGO_CFG_TARGET_FAMILY", "windows");
        env::set_var("CARGO_CFG_TARGET_ARCH", "x86_64");
        env::set_var("CARGO_CFG_TARGET_ENV", "gnu");
        let deps = tempdir.path().join("deps");
        std::fs::create_dir_all(&deps).unwrap();
        let out_dir = tempdir.path().join("build").join("crate_name").join("out");
        std::fs::create_dir_all(&out_dir).unwrap();
        env::set_var("OUT_DIR", out_dir.as_os_str().to_str().unwrap());
        tempdir
    }

    #[test]
    fn test_download_prebuilt() {
        for build_type in ["release", "debug"] {
            let _tempdir = setup_env(build_type);
            let file = download_prebuilt(LIBRARY, VERSION, PREBUILT_FILE1).unwrap();
            assert!(file.exists());
            assert_eq!(
                std::fs::read_to_string(&file).unwrap(),
                format!("hello world {}\n", build_type)
            );
        }
    }

    #[test]
    fn test_download_prebuilt_files() {
        for build_type in ["release", "debug"] {
            let _tempdir = setup_env(build_type);
            let files =
                download_prebuilts(LIBRARY, VERSION, &[PREBUILT_FILE1, PREBUILT_FILE2]).unwrap();
            for file in files {
                assert!(file.exists());
                assert_eq!(
                    std::fs::read_to_string(&file).unwrap(),
                    format!("hello world {}\n", build_type),
                    "failed for file {file:?}"
                );
            }
        }
    }
}

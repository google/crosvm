// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;

use tempfile::TempDir;

use prebuilts::download_prebuilt;
use prebuilts::download_prebuilts;

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

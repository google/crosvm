// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;

static PREBUILTS_VERSION_FILENAME: &str = "prebuilts_version";
static R8BRAIN_LIB: &str = "r8Brain.lib";
static R8BRAIN_DLL: &str = "r8Brain.dll";
static UCRTBASE_DLL: &str = "ucrtbased.dll";
static VCRUNTIME_DLL: &str = "vcruntime140d.dll";

fn main() {
    if std::env::var("CARGO_CFG_WINDOWS").is_ok() {
        let version = std::fs::read_to_string(PREBUILTS_VERSION_FILENAME)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();

        // TODO(b:253039132) build prebuilts locally on windows from build.rs.
        let files = prebuilts::download_prebuilts(
            "r8brain",
            version,
            &[R8BRAIN_DLL, R8BRAIN_LIB, UCRTBASE_DLL, VCRUNTIME_DLL],
        )
        .unwrap();
        let lib_dir = files
            .get(0)
            .unwrap()
            .parent()
            .unwrap()
            .as_os_str()
            .to_str()
            .unwrap();
        println!("cargo:rustc-link-lib=r8Brain");
        println!(r#"cargo:rustc-link-search={}"#, lib_dir);
        println!(
            r#"cargo:rustc-env=PATH={};{}"#,
            lib_dir,
            env::var("PATH").unwrap(),
        );
    }
}

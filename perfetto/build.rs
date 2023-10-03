// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::path::PathBuf;

fn main() {
    #[cfg(windows)]
    main_windows();

    #[cfg(any(target_os = "android", target_os = "linux"))]
    main_unix();

    // TODO: enable once Perfetto is in third_party/perfetto.
    /*
    let proto_files = vec![proto_path(&["config", "perfetto_config.proto"])];
    let mut out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR env does not exist."));
    out_dir.push("perfetto_protos");
    proto_build_tools::build_protos(&out_dir, proto_files.as_slice());
    */
}

#[cfg(windows)]
fn main_windows() {
    // TODO: enable once we have Perfetto libraries available on Windows,
    // download them with prebuilts::download_prebuilts.
    //
    // Ideally paths will be identical in the long term and we
    // can have a single version of this code.
    /*
    println!("cargo:rustc-link-lib=dylib=cperfetto");
    #[cfg(debug_assertions)]
    println!("cargo:rustc-link-search=..\\..\\libs\\debug");
    #[cfg(all(windows, not(debug_assertions)))]
    println!("cargo:rustc-link-search=..\\..\\libs\\release");
    */
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn main_unix() {
    // TODO: enable once we have Perfetto libraries available on unix. We may
    // want to use a prebuilt here too, in which case this would be identical
    // to the Windows version above. The paths will need to be adjusted to
    // wherever we make the Perfetto binary available.
    /*
    println!("cargo:rustc-link-lib=dylib=cperfetto");
    #[cfg(debug_assertions)]
    println!("cargo:rustc-link-search=../../libs/debug");
    #[cfg(not(debug_assertions))]
    println!("cargo:rustc-link-search=../../libs/release");
    */
}

#[allow(dead_code)]
fn proto_path(path: &[&str]) -> PathBuf {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let mut full_path = manifest_dir;
    full_path.extend(["..", "third_party", "perfetto", "protos", "perfetto"]);
    full_path.extend(path);
    full_path
}

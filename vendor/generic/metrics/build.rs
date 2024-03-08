// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    #[cfg(debug_assertions)]
    println!(
        "cargo:rustc-link-search={}\\..\\..\\..\\libs\\debug\\",
        manifest_dir
    );
    #[cfg(not(debug_assertions))]
    println!(
        "cargo:rustc-link-search={}\\..\\..\\..\\libs\\release\\",
        manifest_dir
    );

    build_protos(&PathBuf::from(manifest_dir));
}

fn build_protos(manifest_dir: &PathBuf) {
    let mut event_details_path = manifest_dir.to_owned();
    event_details_path.extend(["protos", "event_details.proto"]);

    let mut out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR env does not exist."));
    out_dir.push("metrics_protos");
    proto_build_tools::build_protos(&out_dir, &[event_details_path]);
}

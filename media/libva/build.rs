// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

fn main() {
    // Skip installing dependencies when generating documents.
    if std::env::var("CARGO_DOC").is_ok() {
        return;
    }

    // libva is unix only
    if std::env::var("CARGO_CFG_UNIX").is_err() {
        return;
    }

    match pkg_config::probe_library("libva") {
        Ok(_) => (),
        Err(e) => panic!("Libva not found: {}", e),
    };

    println!("cargo:rustc-link-lib=dylib=va");
    println!("cargo:rustc-link-lib=dylib=va-drm"); // for the vaGetDisplayDRM entrypoint
}

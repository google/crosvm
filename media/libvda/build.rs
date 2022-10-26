// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

fn main() {
    // libvda is only avalable on chromeos build.
    // To enable clippy checks with this feature enabled upstream we will just skip
    // linking the library, allowing the crate to be compiled, but not linked.
    println!("cargo:rerun-if-env-changed=CROSVM_BUILD_VARIANT");
    if std::env::var("CROSVM_BUILD_VARIANT").unwrap_or_default() == "chromeos" {
        pkg_config::probe_library("libvda").unwrap();
        println!("cargo:rustc-link-lib=dylib=vda");
    }
}

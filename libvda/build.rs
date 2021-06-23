// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

fn main() {
    match pkg_config::probe_library("libvda") {
        Ok(_) => (),
        // Ignore a pkg-config failure to allow cargo-clippy to run even when libvda.pc doesn't
        // exist.
        Err(pkg_config::Error::Failure { command, .. })
            if command == r#""pkg-config" "--libs" "--cflags" "libvda""# => {}
        Err(e) => panic!("{}", e),
    };

    println!("cargo:rustc-link-lib=dylib=vda");
}

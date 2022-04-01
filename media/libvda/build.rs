// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

fn main() {
    #[allow(clippy::single_match)]
    match pkg_config::probe_library("libvda") {
        Ok(_) => (),
        // Ignore pkg-config failures on non-chromeos platforms to allow cargo-clippy to run even
        // if libvda.pc doesn't exist.
        #[cfg(not(feature = "chromeos"))]
        Err(_) => (),
        #[cfg(feature = "chromeos")]
        Err(e) => panic!("{}", e),
    };

    println!("cargo:rustc-link-lib=dylib=vda");
}

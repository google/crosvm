// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(all(feature = "slirp", windows))]
mod win_slirp {
    use std::env;

    pub(super) fn main() {
        // This must be an absolute path or linking issues will result when a consuming crate
        // tries to link since $PWD will be different.
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

        #[cfg(debug_assertions)]
        let build_type = "debug";

        #[cfg(not(debug_assertions))]
        let build_type = "release";

        println!(
            r#"cargo:rustc-link-search={}\..\..\..\third_party\libslirp\{}"#,
            manifest_dir, build_type
        );
        println!(
            r#"cargo:rustc-env=PATH={};{}\..\..\..\third_party\libslirp\{};"#,
            env::var("PATH").unwrap(),
            manifest_dir,
            build_type,
            manifest_dir
        );
    }
}

fn main() {
    // We (the Windows crosvm maintainers) submitted upstream patches to libslirp-sys so it doesn't
    // try to link directly on Windows. This is because linking on Windows tends to be specific
    // to the build system that invokes Cargo (e.g. the crosvm jCI scripts that also produce the
    // required libslirp DLL & lib). The integration here (win_slirp::main) is specific to crosvm's
    // build process.
    #[cfg(all(feature = "slirp", windows))]
    win_slirp::main();

    // For unix, libslirp-sys's build script will make the appropriate linking calls to pkg_config.
}

// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

static PREBUILTS_VERSION_FILENAME: &str = "prebuilts_version";
static SLIRP_LIB: &str = "libslirp.lib";
static SLIRP_DLL: &str = "libslirp-0.dll";
#[cfg(unix)]
static GLIB_FILENAME: &str = "libglib-2.0.dll.a";

fn main() {
    // We (the Windows crosvm maintainers) submitted upstream patches to libslirp-sys so it doesn't
    // try to link directly on Windows. This is because linking on Windows tends to be specific
    // to the build system that invokes Cargo (e.g. the crosvm jCI scripts that also produce the
    // required libslirp DLL & lib). The integration here (win_slirp::main) is specific to crosvm's
    // build process.
    if std::env::var("CARGO_CFG_WINDOWS").is_ok() {
        let version = std::fs::read_to_string(PREBUILTS_VERSION_FILENAME)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        // TODO(b:242204245) build libslirp locally on windows from build.rs.
        prebuilts::download_prebuilts(
            "libslirp",
            version,
            &[
                SLIRP_DLL,
                SLIRP_LIB,
                #[cfg(unix)]
                // When compiling with mingw64 to run under wine64, we need glib as slirp links
                // against it.
                GLIB_FILENAME,
            ],
        )
        .unwrap();
    }

    // For unix, libslirp-sys's build script will make the appropriate linking calls to pkg_config.
}

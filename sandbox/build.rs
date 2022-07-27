// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

static PREBUILTS_VERSION_FILENAME: &str = "prebuilts_version";
static SANDBOX_LIB: &str = "libsandbox.lib";

static BINDINGS_FILE: &str = "bindings.rs";

pub fn setup_windows_prebuilts() {
    println!("cargo:rustc-link-lib=dbghelp");
    println!("cargo:rustc-link-lib=gdi32");
    println!("cargo:rustc-link-lib=oleaut32");
    println!("cargo:rustc-link-lib=setupapi");
    println!("cargo:rustc-link-lib=shell32");
    println!("cargo:rustc-link-lib=user32");
    println!("cargo:rustc-link-lib=winmm");

    if std::env::var("CARGO_CFG_DEBUG_ASSERTIONS").is_ok() {
        println!("cargo:rustc-link-lib=ucrtd");
    }

    println!("cargo:rustc-link-lib=libsandbox");

    println!("cargo:rerun-if-changed={}", BINDINGS_FILE);
}

fn main() {
    if std::env::var("CARGO_CFG_WINDOWS").is_ok() {
        let version = std::fs::read_to_string(PREBUILTS_VERSION_FILENAME)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();

        // TODO(b:253039132) build sandbox prebuilts locally on windows from build.rs.
        let files = prebuilts::download_prebuilts("sandbox", version, &[SANDBOX_LIB]).unwrap();
        println!(
            r#"cargo:rustc-link-search={};{}"#,
            std::env::var("PATH").unwrap(),
            files
                .get(0)
                .unwrap()
                .parent()
                .unwrap()
                .as_os_str()
                .to_str()
                .unwrap()
        );
        setup_windows_prebuilts();
    }
}

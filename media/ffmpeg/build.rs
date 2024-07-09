// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::PathBuf;

use pkg_config::Config;

fn main() {
    // Skip building dependencies when generating documents.
    if std::env::var("CARGO_DOC").is_ok() {
        return;
    }

    // ffmpeg is currently only supported on unix
    if std::env::var("CARGO_CFG_UNIX").is_err() {
        return;
    }

    // ffmgeg is not supported by CI on 32-bit arm
    if std::env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "arm" {
        return;
    }

    // Match all ffmpeg 6.0+ versions.
    Config::new()
        .atleast_version("60")
        .probe("libavcodec")
        .unwrap();
    Config::new()
        .atleast_version("58")
        .probe("libavutil")
        .unwrap();
    Config::new()
        .atleast_version("7")
        .probe("libswscale")
        .unwrap();

    let bindings = bindgen::Builder::default()
        .header("src/bindings.h")
        .allowlist_function("av_.*")
        .allowlist_function("avcodec_.*")
        .allowlist_function("sws_.*")
        .allowlist_function("av_image_.*")
        .allowlist_var("FF_PROFILE.*")
        .allowlist_var("AV_.*")
        .allowlist_var("AVERROR_.*")
        // Skip va_list and functions that use it to avoid ABI problems on aarch64.
        .blocklist_type(".*va_list.*")
        .blocklist_function("av_log_.*")
        .blocklist_function("av_vlog")
        .generate()
        .expect("failed to generate bindings");
    let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("writing bindings to file failed");
}

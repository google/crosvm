// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

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

    // Match all ffmpeg 5.0 versions with which our generated bindings are compatible.
    Config::new()
        .range_version("59".."60")
        .probe("libavcodec")
        .unwrap();
    Config::new()
        .range_version("57".."58")
        .probe("libavutil")
        .unwrap();
    Config::new()
        .range_version("6".."7")
        .probe("libswscale")
        .unwrap();
}

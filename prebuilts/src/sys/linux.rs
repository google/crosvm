// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::Path;
use std::process::Command;

pub(crate) fn download_command(url: &str, destination: &Path) -> Command {
    let mut cmd = Command::new("curl");
    cmd.arg("--fail")
        .arg("--location")
        .arg("--silent")
        .args(["--output", destination.to_str().unwrap()])
        .arg(url);
    cmd
}

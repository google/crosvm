// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::path::Path;
use std::process::Command;

pub(crate) fn download_command(url: &str, destination: &Path) -> Command {
    let mut cmd = Command::new("powershell");
    cmd.arg("-c").arg(format!(
        "$wc = New-Object System.Net.WebClient; $wc.DownloadFile(\"{}\", \"{}\")",
        url,
        destination.to_str().unwrap()
    ));
    cmd
}

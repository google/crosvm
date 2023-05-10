// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env::current_exe;
use std::process::Command;

/// The tests below require root privileges.
/// Re-invoke the test binary to execute the specified test with sudo. The test will fail if
/// passwordless sudo is not available.
pub fn call_test_with_sudo(name: &str) {
    check_can_sudo();

    let result = Command::new("sudo")
        .args([
            "--preserve-env",
            current_exe().unwrap().to_str().unwrap(),
            "--nocapture",
            "--ignored",
            "--exact",
            name,
        ])
        .status()
        .unwrap();

    if !result.success() {
        panic!("Test {name} failed in child process.");
    }
}

/// Checks to see if user has entered their password for sudo.
pub fn check_can_sudo() {
    // Try a passwordless sudo first to provide a proper error message.
    // Note: The combination of SUDO_ASKPASS and --askpass will fail if sudo has to ask for a
    // password. When sudo needs to ask for a password, it will call "false" and fail without
    // prompting.
    let can_sudo = Command::new("sudo")
        .args(["--askpass", "true"]) // Use an askpass program to ask for a password
        .env("SUDO_ASKPASS", "false") // Set the askpass program to false
        .output()
        .unwrap();
    if !can_sudo.status.success() {
        panic!("This test need to be run as root or with passwordless sudo.");
    }
}

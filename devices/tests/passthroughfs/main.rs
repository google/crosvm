// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Unit tests for 'devices::virtio::fs::passthrough::PassthroughFs`'s APIs.
//! These tests run only on Unix.
//!
//! Since each test needs to be run in single thread because PassthroughFs may performs process-wide
//! operations such as fchdir, we need to implement these tests as a separate test binary with a
//! custom test harness.
//! This binary is built on non-Unix platforms because Cargo.toml doesn't allow defining a
//! platform-specific test binary, but we do nothing on such environments.

#[cfg(unix)]
mod unix;

fn main() {
    // PassthroughFS is a Unix-only feature.
    #[cfg(unix)]
    unix::main();
}

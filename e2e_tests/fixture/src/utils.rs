// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides utility functions used by multiple fixture files.

use std::env;
use std::path::PathBuf;
use std::sync::mpsc::sync_channel;
use std::sync::mpsc::RecvTimeoutError;
use std::thread;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::Result;

use crate::sys::binary_name;

/// Returns the path to the crosvm binary to be tested.
///
/// The crosvm binary is expected to be alongside to the integration tests
/// binary. Alternatively in the parent directory (cargo will put the
/// test binary in target/debug/deps/ but the crosvm binary in target/debug)
pub fn find_crosvm_binary() -> PathBuf {
    let binary_name = binary_name();
    let exe_dir = env::current_exe().unwrap().parent().unwrap().to_path_buf();
    let first = exe_dir.join(binary_name);
    if first.exists() {
        return first;
    }
    let second = exe_dir.parent().unwrap().join(binary_name);
    if second.exists() {
        return second;
    }
    panic!(
        "Cannot find {} in ./ or ../ alongside test binary.",
        binary_name
    );
}

/// Run the provided closure in a separate thread and return it's result. If the closure does not
/// finish before the timeout is reached, an Error is returned instead.
///
/// WARNING: It is not possible to kill the closure if a timeout occurs. It is advised to panic
/// when an error is returned.
pub(super) fn run_with_timeout<F, U>(closure: F, timeout: Duration) -> Result<U>
where
    F: FnOnce() -> U + Send + 'static,
    U: Send + 'static,
{
    let (tx, rx) = sync_channel::<()>(1);
    let handle = thread::spawn(move || {
        let result = closure();
        // Notify main thread the closure is done. Fail silently if it's not listening anymore.
        let _ = tx.send(());
        result
    });
    match rx.recv_timeout(timeout) {
        Ok(_) => Ok(handle.join().unwrap()),
        Err(RecvTimeoutError::Timeout) => Err(anyhow!("closure timed out after {timeout:?}")),
        Err(RecvTimeoutError::Disconnected) => Err(anyhow!("closure paniced")),
    }
}

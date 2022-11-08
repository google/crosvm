// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provides utility functions used by multiple fixture files.

use std::env;
use std::path::PathBuf;

/// Returns the path to the crosvm binary to be tested.
///
/// The crosvm binary is expected to be alongside to the integration tests
/// binary. Alternatively in the parent directory (cargo will put the
/// test binary in target/debug/deps/ but the crosvm binary in target/debug)
pub fn find_crosvm_binary() -> PathBuf {
    cfg_if::cfg_if! {
        if #[cfg(features="direct")] {
            let binary_name = "crosvm-direct";
        } else {
            let binary_name = "crosvm";
        }
    }

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

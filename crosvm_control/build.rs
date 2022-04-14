// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::env;
use std::path::PathBuf;

use anyhow::{Context, Result};

fn main() -> Result<()> {
    // Skip building dependencies when generating documents.
    if std::env::var("CARGO_DOC").is_ok() {
        return Ok(());
    }

    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    let target_dir = env::var("OUT_DIR").context("failed to get OUT_DIR")?;
    let output_file = PathBuf::from(target_dir)
        .join("crosvm_control.h")
        .display()
        .to_string();

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .generate()
        .context("Unable to generate bindings")?
        .write_to_file(&output_file);

    Ok(())
}

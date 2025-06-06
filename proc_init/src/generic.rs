// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Generic implementation of product specific functions that are called on child process
//! initialization.

use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize)]
pub struct ProductAttributes {}

pub(crate) fn init_child_crash_reporting(_attrs: &ProductAttributes) {
    // Do nothing. Crash reporting is implemented by a specific product.
}

pub(crate) fn product_child_setup(_attrs: &ProductAttributes) -> anyhow::Result<()> {
    Ok(())
}

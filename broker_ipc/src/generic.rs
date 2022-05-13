// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Generic implementation of product specific functions that are called on child process
//! initialization.

use crate::{log_file_from_path, CommonChildStartupArgs};
use base::Tube;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
pub struct ProductAttributes {}

impl CommonChildStartupArgs {
    pub fn new(syslog_path: Option<PathBuf>, metrics_tube: Option<Tube>) -> anyhow::Result<Self> {
        Ok(Self {
            product_attrs: ProductAttributes {},
            metrics_tube,
            syslog_file: log_file_from_path(syslog_path)?,
        })
    }
}

pub(crate) fn init_child_crash_reporting(_attrs: &ProductAttributes) {
    // Do nothing. Crash reporting is implemented by a specific product.
}

pub(crate) fn product_child_setup(_attrs: &ProductAttributes) -> anyhow::Result<()> {
    Ok(())
}

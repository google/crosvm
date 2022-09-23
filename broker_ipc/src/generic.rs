// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Generic implementation of product specific functions that are called on child process
//! initialization.

use std::path::PathBuf;

use base::Tube;
use serde::Deserialize;
use serde::Serialize;

use crate::log_file_from_path;
use crate::CommonChildStartupArgs;

#[derive(Serialize, Deserialize)]
pub struct ProductAttributes {}

impl CommonChildStartupArgs {
    pub fn new(
        syslog_path: Option<PathBuf>,
        #[cfg(feature = "crash-report")] _crash_attrs: crash_report::CrashReportAttributes,
        metrics_tube: Option<Tube>,
    ) -> anyhow::Result<Self> {
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

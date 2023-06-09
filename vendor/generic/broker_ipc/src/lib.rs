// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Generic implementation of product specific functions that are called on child process
//! initialization.

#[cfg(feature = "crash-report")]
pub use crash_report::CrashReportAttributes;
use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize)]
pub struct ProductAttributes {}

impl ProductAttributes {
    #[allow(clippy::new_without_default)]
    pub fn new(
        #[cfg(feature = "crash-report")] _crash_attrs: CrashReportAttributes,
        #[cfg(feature = "process-invariants")] _process_invariants: EmulatorProcessInvariants,
    ) -> Self {
        Self {}
    }
}

pub fn init_child_crash_reporting(_attrs: &ProductAttributes) {
    // Do nothing. Crash reporting is implemented by a specific product.
}

pub fn product_child_setup(_attrs: &ProductAttributes) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(feature = "process-invariants")]
#[derive(Debug, Clone)]
pub struct EmulatorProcessInvariants {}

#[cfg(feature = "process-invariants")]
pub fn init_broker_process_invariants(
    _data_handle: &Option<u64>,
    _data_size: &Option<usize>,
) -> anyhow::Result<EmulatorProcessInvariants> {
    Ok(EmulatorProcessInvariants {})
}

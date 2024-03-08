// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::result::Result;
use std::time::Duration;

use crate::MetricEventType;

/// A logging struct meant for use in tracking and periodically
/// logging a single metric. The metric is aggregated over the
/// designated time period. Intended for use with high-frequency metrics.
pub struct PeriodicLogger;

impl PeriodicLogger {
    pub fn new(_event: MetricEventType, _period: Duration) -> Result<PeriodicLogger, String> {
        Ok(PeriodicLogger)
    }

    /// Indicate the event has occurred with the given
    /// value to be aggregated over the given time period.
    pub fn log(&self, _value: i64) {}
}

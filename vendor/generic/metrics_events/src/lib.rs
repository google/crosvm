// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MetricEventType {
    // No events should ever be added to this enum - all events defined in
    // upstream CrosVM should be added to the metrics_event package. Downstream
    // projects can replace the generic metrics_event package if they need
    // downstream only events.
}

pub struct RecordDetails {
    // Similar to above, this is for downstream projects.
}

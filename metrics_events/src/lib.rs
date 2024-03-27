// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod event_types;
pub mod sys;

pub use event_types::MetricEventType;
pub use metrics_events_product::MetricEventType as VendorMetricEventType;
pub use metrics_events_product::RecordDetails;

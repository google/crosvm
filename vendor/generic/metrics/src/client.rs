// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::RawDescriptor;
use base::SendTube;
use metrics_events::MetricEventType;
use metrics_events::RecordDetails;

use crate::MetricsClientDestructor;

/// This interface exists to be used and re-implemented by downstream forks. Updates shouldn't be
/// done without ensuring they won't cause breakages in dependent codebases.
pub fn initialize(_: SendTube) {}
#[cfg(test)]
pub fn force_initialize(_: SendTube) {}

pub fn push_descriptors(_: &mut Vec<RawDescriptor>) {}

pub fn get_destructor() -> MetricsClientDestructor {
    MetricsClientDestructor::new(|| {})
}
pub fn is_initialized() -> bool {
    false
}
pub fn set_auth_token(_: &str) {}
pub fn set_graphics_api(_: &str) {}
pub fn set_package_name(_: &str) {}
pub fn merge_session_invariants(_: &[u8]) {}

/// Logs a counter with the given descriptor as aux. data. A descriptor is
/// generally an enum value or error code.
pub fn log_descriptor(_event_type: MetricEventType, _descriptor: i64) {}

/// Logs a counter with no aux. data.
pub fn log_event(_event_type: MetricEventType) {}

/// Logs a real valued metric (e.g. a data transfer rate, a latency value, etc)
/// with the supplied value.
pub fn log_metric(_event_type: MetricEventType, _value: i64) {}

/// Logs a histogram metric with the supplied value. Note: step is a value to
/// be added to the distribution.
pub fn log_histogram_metric(_event_type: MetricEventType, _step: i64) {}

/// Logs a high frequency counter with the supplied aux. data and value.
pub fn log_high_frequency_descriptor_event(_: MetricEventType, _descriptor: i64, _step: i64) {}

/// Logs a counter with additional data.
pub fn log_event_with_details(_event_type: MetricEventType, _details: &RecordDetails) {}

// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use base::Tube;

use crate::protos::event_details::RecordDetails;
use crate::MetricEventType;
use crate::MetricsClientDestructor;

/// This interface exists to be used and re-implemented by downstream forks. Updates shouldn't be
/// done without ensuring they won't cause breakages in dependent codebases.
pub fn initialize(_: Tube) {}
#[cfg(test)]
pub fn force_initialize(_: Tube) {}
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
pub fn log_descriptor(_: MetricEventType, _: i64) {}
pub fn log_event(_: MetricEventType) {}
pub fn log_metric(_: MetricEventType, _: i64) {}
pub fn log_histogram_metric(_: MetricEventType, _: i64) {}
pub fn log_high_frequency_descriptor_event(_: MetricEventType, _: i64, _: i64) {}
pub fn log_event_with_details(_: MetricEventType, _: &RecordDetails) {}

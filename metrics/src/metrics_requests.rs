// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Structs used to transport log requests between client processes and the logging controller

use serde::Deserialize;
use serde::Serialize;

use crate::MetricEventType;

#[derive(Serialize, Deserialize, Debug)]
pub struct LogMetric {
    pub event_code: MetricEventType,
    pub value: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LogDescriptor {
    pub event_code: MetricEventType,
    pub descriptor: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LogHighFrequencyDescriptorMetric {
    pub event_code: MetricEventType,
    pub descriptor: i64,
    pub step: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EventWithSerializedDetails {
    pub event_code: MetricEventType,
    pub serialized_details: Box<[u8]>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum MetricsRequest {
    LogDescriptor(LogDescriptor),
    LogEvent(MetricEventType),
    LogMetric(LogMetric),
    LogHistogram(LogMetric),
    SetAuthToken(String),
    SetGraphicsApi(String),
    SetPackageName(String),
    MergeSessionInvariants(Vec<u8>),
    LogHighFrequencyDescriptorMetric(LogHighFrequencyDescriptorMetric),
    LogEventWithSerializedDetails(EventWithSerializedDetails),
}

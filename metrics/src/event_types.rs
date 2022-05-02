// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Error;
use serde::{Deserialize, Serialize};
use std::convert::From;
use std::convert::TryFrom;

// TODO(mikehoyle): Create a way to generate these directly from the
// proto for a single source-of-truth.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum MetricEventType {
    CpuUsage,
    MemoryUsage,
    Fps,
    JankyFps,
    NetworkTxRate,
    NetworkRxRate,
    Interrupts,
    FrameTime,
    EmulatorGraphicsFreeze,
    EmulatorGraphicsUnfreeze,
    EmulatorGfxstreamVkAbortReason,
    ChildProcessExit,
    ReadIo,
    WriteIo,
    AudioFormatRequestOk,
    AudioFormatModifiedOk,
    AudioFormatFailed,
    TscCoresOutOfSync,
    NetworkTxRateSummarized,
    NetworkRxRateSummarized,
    Other(i64),
}

impl From<MetricEventType> for i64 {
    fn from(event_code: MetricEventType) -> Self {
        match event_code {
            MetricEventType::CpuUsage => 10001,
            MetricEventType::MemoryUsage => 10002,
            MetricEventType::Fps => 10003,
            MetricEventType::JankyFps => 10004,
            MetricEventType::NetworkTxRate => 10005,
            MetricEventType::NetworkRxRate => 10006,
            MetricEventType::Interrupts => 10007,
            MetricEventType::FrameTime => 10008,
            MetricEventType::EmulatorGraphicsFreeze => 10009,
            MetricEventType::EmulatorGraphicsUnfreeze => 10010,
            MetricEventType::EmulatorGfxstreamVkAbortReason => 10011,
            MetricEventType::ChildProcessExit => 10012,
            MetricEventType::ReadIo => 10013,
            MetricEventType::WriteIo => 10014,
            MetricEventType::AudioFormatRequestOk => 10015,
            MetricEventType::AudioFormatModifiedOk => 10016,
            MetricEventType::AudioFormatFailed => 10017,
            MetricEventType::TscCoresOutOfSync => 10018,
            MetricEventType::NetworkTxRateSummarized => 10019,
            MetricEventType::NetworkRxRateSummarized => 10020,
            MetricEventType::Other(code) => code,
        }
    }
}

impl TryFrom<i64> for MetricEventType {
    type Error = Error;

    fn try_from(event_code: i64) -> Result<Self, Self::Error> {
        match event_code {
            10001 => Ok(MetricEventType::CpuUsage),
            10002 => Ok(MetricEventType::MemoryUsage),
            10003 => Ok(MetricEventType::Fps),
            10004 => Ok(MetricEventType::JankyFps),
            10005 => Ok(MetricEventType::NetworkTxRate),
            10006 => Ok(MetricEventType::NetworkRxRate),
            10007 => Ok(MetricEventType::Interrupts),
            10008 => Ok(MetricEventType::FrameTime),
            10009 => Ok(MetricEventType::EmulatorGraphicsFreeze),
            10010 => Ok(MetricEventType::EmulatorGraphicsUnfreeze),
            10011 => Ok(MetricEventType::EmulatorGfxstreamVkAbortReason),
            10012 => Ok(MetricEventType::ChildProcessExit),
            10013 => Ok(MetricEventType::ReadIo),
            10014 => Ok(MetricEventType::WriteIo),
            10015 => Ok(MetricEventType::AudioFormatRequestOk),
            10016 => Ok(MetricEventType::AudioFormatModifiedOk),
            10017 => Ok(MetricEventType::AudioFormatFailed),
            10018 => Ok(MetricEventType::TscCoresOutOfSync),
            10019 => Ok(MetricEventType::NetworkTxRateSummarized),
            10020 => Ok(MetricEventType::NetworkRxRateSummarized),
            _ => Ok(MetricEventType::Other(event_code)),
        }
    }
}

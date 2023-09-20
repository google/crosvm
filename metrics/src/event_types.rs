// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::convert::From;
use std::convert::TryFrom;

use anyhow::Error;
use serde::Deserialize;
use serde::Serialize;

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
    DllLoaded,
    GraphicsHangRenderThread,
    GraphicsHangSyncThread,
    AudioNoopStreamForced,
    AudioPlaybackError,
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
            MetricEventType::DllLoaded => 10021,
            MetricEventType::GraphicsHangRenderThread => 10024,
            MetricEventType::GraphicsHangSyncThread => 10026,
            MetricEventType::AudioNoopStreamForced => 10038,
            MetricEventType::AudioPlaybackError => 10039,
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
            10021 => Ok(MetricEventType::DllLoaded),
            10024 => Ok(MetricEventType::GraphicsHangRenderThread),
            10026 => Ok(MetricEventType::GraphicsHangSyncThread),
            10038 => Ok(MetricEventType::AudioNoopStreamForced),
            10039 => Ok(MetricEventType::AudioPlaybackError),
            _ => Ok(MetricEventType::Other(event_code)),
        }
    }
}

// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use metrics_events_product::MetricEventType as VendorMetricEventType;
use serde::Deserialize;
use serde::Serialize;

#[cfg(windows)]
use crate::sys::windows::WaveFormatDetails;

// TODO(mikehoyle): Create a way to generate these directly from the
// proto for a single source-of-truth.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    ChildProcessExit {
        exit_code: u32,
        #[cfg(windows)]
        process_type: win_util::ProcessType,
    },
    ReadIo,
    WriteIo,
    #[cfg(windows)]
    AudioFormatRequestOk(WaveFormatDetails),
    #[cfg(windows)]
    AudioFormatModifiedOk(WaveFormatDetails),
    #[cfg(windows)]
    AudioFormatFailed(WaveFormatDetails),
    TscCoresOutOfSync,
    NetworkTxRateSummarized,
    NetworkRxRateSummarized,
    DllLoaded(String),
    GraphicsHangRenderThread,
    GraphicsHangSyncThread,
    AudioNoopStreamForced,
    AudioPlaybackError,
    RtcWakeup,
    VirtioWakeup {
        virtio_id: u32,
    },
    VcpuShutdownError,
    Other(i64),
    Vendor(VendorMetricEventType),
}

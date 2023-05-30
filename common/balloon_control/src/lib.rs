// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use serde::Deserialize;
use serde::Serialize;

// Balloon commands that are send on the balloon command tube.
#[derive(Serialize, Deserialize, Debug)]
pub enum BalloonTubeCommand {
    // Set the size of the VM's balloon.
    Adjust {
        num_bytes: u64,
        // When this flag is set, adjust attempts can fail. After adjustment, the final
        // size of the balloon is returned via a BalloonTubeResult::Adjust message.
        //
        // The flag changes the semantics of inflating the balloon. By default, the driver
        // will indefinitely retry if it fails to allocate pages when inflating the
        // balloon.  However, when this flag is set, the balloon device responds to page
        // allocation failures in the guest by stopping inflation at the balloon's current
        // size.
        allow_failure: bool,
    },
    // Fetch balloon stats. The ID can be used to discard stale states
    // if any previous stats requests failed or timed out.
    Stats {
        id: u64,
    },
    // Fetch balloon wss. The ID can be used to discard stale states if any
    // previous wss request failed or timed out.
    WorkingSetSize {
        id: u64,
    },
    // Send balloon wss config to guest.
    WorkingSetSizeConfig {
        bins: Vec<u64>,
        refresh_threshold: u64,
        report_threshold: u64,
    },
}

// BalloonStats holds stats returned from the stats_queue.
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct BalloonStats {
    pub swap_in: Option<u64>,
    pub swap_out: Option<u64>,
    pub major_faults: Option<u64>,
    pub minor_faults: Option<u64>,
    pub free_memory: Option<u64>,
    pub total_memory: Option<u64>,
    pub available_memory: Option<u64>,
    pub disk_caches: Option<u64>,
    pub hugetlb_allocations: Option<u64>,
    pub hugetlb_failures: Option<u64>,
    pub shared_memory: Option<u64>,
    pub unevictable_memory: Option<u64>,
}

pub const VIRTIO_BALLOON_WS_MIN_NUM_BINS: usize = 2;
pub const VIRTIO_BALLOON_WS_MAX_NUM_BINS: usize = 16;
pub const VIRTIO_BALLOON_WS_MAX_NUM_INTERVALS: usize = 15;

// WSSBucket stores information about a bucket (or bin) of the working set size.
#[derive(Default, Serialize, Deserialize, Debug, Clone, Copy)]
pub struct WSSBucket {
    pub age: u64,
    pub bytes: [u64; 2],
}

// BalloonWSS holds WSS returned from the wss_queue.
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct BalloonWSS {
    /// working set size, separated per histogram bucket.
    pub wss: Vec<WSSBucket>,
}

impl BalloonWSS {
    pub fn new() -> Self {
        BalloonWSS { wss: vec![] }
    }
}

// BalloonTubeResult are results to BalloonTubeCommand defined above.
#[derive(Serialize, Deserialize, Debug)]
pub enum BalloonTubeResult {
    Stats {
        stats: BalloonStats,
        balloon_actual: u64,
        id: u64,
    },
    Adjusted {
        num_bytes: u64,
    },
    WorkingSetSize {
        wss: BalloonWSS,
        /// size of the balloon in bytes.
        balloon_actual: u64,
        id: u64,
    },
}

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
    // Fetch balloon stats.
    Stats,
    // Fetch balloon ws.
    WorkingSet,
    // Send balloon ws config to guest.
    WorkingSetConfig {
        bins: Vec<u32>,
        refresh_threshold: u32,
        report_threshold: u32,
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

// WSBucket stores information about a bucket (or bin) of the working set.
#[derive(Default, Serialize, Deserialize, Debug, Clone, Copy)]
pub struct WSBucket {
    pub age: u64,
    pub bytes: [u64; 2],
}

// BalloonWS holds WS returned from the ws_queue.
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct BalloonWS {
    /// working set, separated per histogram bucket.
    pub ws: Vec<WSBucket>,
}

impl BalloonWS {
    pub fn new() -> Self {
        BalloonWS { ws: vec![] }
    }
}

// BalloonTubeResult are results to BalloonTubeCommand defined above.
#[derive(Serialize, Deserialize, Debug)]
pub enum BalloonTubeResult {
    Stats {
        stats: BalloonStats,
        balloon_actual: u64,
    },
    Adjusted {
        num_bytes: u64,
    },
    WorkingSet {
        ws: BalloonWS,
        /// size of the balloon in bytes.
        balloon_actual: u64,
    },
}

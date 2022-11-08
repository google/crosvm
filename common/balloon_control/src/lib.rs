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
}

// Copyright 2022 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use serde::{Deserialize, Serialize};

// Balloon commands that are send on the balloon command tube.
#[derive(Serialize, Deserialize, Debug)]
pub enum BalloonTubeCommand {
    // Set the size of the VM's balloon.
    Adjust { num_bytes: u64 },
    // Fetch balloon stats. The ID can be used to discard stale states
    // if any previous stats requests failed or timed out.
    Stats { id: u64 },
}

// BalloonStats holds stats returned from the stats_queue.
#[derive(Default, Serialize, Deserialize, Debug)]
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
}

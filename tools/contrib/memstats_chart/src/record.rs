// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub struct ProcRecord {
    pub pid: u32,
    pub name: String,
    pub smaps: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Record {
    pub timestamp: u64,
    pub stats: Vec<ProcRecord>,
    pub balloon_stats: Option<BalloonStats>,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct BalloonStatsInner {
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

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
pub struct BalloonStats {
    pub stats: BalloonStatsInner,
    pub balloon_actual: u64,
}

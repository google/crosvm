// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::time::Instant;

use crate::Stat;

#[derive(Clone, Copy)]
struct StatEntry {
    count: u64,
    total: u64,
    max: u64,
}

pub struct StatUpdater {
    idx: usize,
    start: Instant,
}

pub struct GlobalStats {
    entries: [StatEntry; Stat::Count as usize],
}

pub static mut STATS: GlobalStats = GlobalStats {
    entries: [StatEntry {
        count: 0,
        total: 0,
        max: 0,
    }; Stat::Count as usize],
};

impl GlobalStats {
    // Record latency from this call until the end of block/function
    // Example:
    // pub fn foo() {
    //     let _u = STATS.record(Stat::Foo);
    //     // ... some operation ...
    // }
    // The added STATS.record will record latency of "some operation" and will
    // update max and average latencies for it under Stats::Foo. Subsequent
    // call to STATS.print() will print out max and average latencies for all
    // operations that were performed.
    pub fn record(&mut self, idx: Stat) -> StatUpdater {
        StatUpdater {
            idx: idx as usize,
            start: Instant::now(),
        }
    }

    pub fn print(&self) {
        for idx in 0..Stat::Count as usize {
            let e = &self.entries[idx as usize];
            let stat = unsafe { std::mem::transmute::<u8, Stat>(idx as u8) };
            if e.count > 0 {
                println!(
                    "Stat::{:?}: avg {}ns max {}ns",
                    stat,
                    e.total / e.count,
                    e.max
                );
            }
        }
    }

    fn update(&mut self, idx: usize, elapsed_nanos: u64) {
        let e = &mut self.entries[idx as usize];
        e.total += elapsed_nanos;
        if e.max < elapsed_nanos {
            e.max = elapsed_nanos;
        }
        e.count += 1;
    }
}

impl Drop for StatUpdater {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed();
        let elapsed_nanos = elapsed.as_secs() * 1000000000 + elapsed.subsec_nanos() as u64;
        // Unsafe due to racy access - OK for stats
        unsafe {
            STATS.update(self.idx, elapsed_nanos);
        }
    }
}

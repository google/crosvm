// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(dead_code)]

use std::cmp::Reverse;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use devices::BusStatistics;
use hypervisor::VcpuExit;
use sync::Mutex;

const ERROR_RETRY_I32: i32 = winapi::shared::winerror::ERROR_RETRY as i32;

/// Statistics about the number and duration of VM exits.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct VmExitStatistics {
    /// Whether or not statistics have been enabled to measure VM exits.
    enabled: bool,
    /// Counter of the number of VM exits per-exit-type. The index into the Vec can be determined
    /// from a &Result<VcpuExit> via the `exit_to_index` function.
    exit_counters: Vec<u64>,
    /// Sum of the duration of VM exits per-exit-type. The index into the Vec can be determined
    /// from a &Result<VcpuExit> via the `exit_to_index` function.
    exit_durations: Vec<Duration>,
}

impl VmExitStatistics {
    pub fn new() -> VmExitStatistics {
        VmExitStatistics {
            enabled: false,
            // We have a known number of exit types, and thus a known number of exit indices
            exit_counters: vec![0; MAX_EXIT_INT + 1],
            exit_durations: vec![Duration::new(0, 0); MAX_EXIT_INT + 1],
        }
    }

    /// Enable or disable statistics gathering.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the start time of the stat that is to be recorded.
    ///
    /// If the VmExitStatistics instance is not enabled this will return None.
    pub fn start_stat(&self) -> Option<Instant> {
        if !self.enabled {
            return None;
        }
        Some(Instant::now())
    }

    /// Record the end of the stat.
    ///
    /// The start value return from start_stat should be passed as `start`. If `start` is None or
    /// if the VmExitStatistics instance is not enabled this will do nothing. The counters and
    /// durations will silently overflow to prevent interference with vm operation.
    pub fn end_stat(&mut self, exit: &base::Result<VcpuExit>, start: Option<Instant>) {
        if !self.enabled || start.is_none() {
            return;
        }

        let exit_index = exit_to_index(exit);

        // We overflow because we don't want any disruptions to emulator running due to
        // statistics
        self.exit_counters[exit_index] = self.exit_counters[exit_index].overflowing_add(1).0;
        self.exit_durations[exit_index] = self.exit_durations[exit_index]
            .checked_add(start.unwrap().elapsed())
            .unwrap_or(Duration::new(0, 0)); // If we overflow, reset to 0
    }

    /// Merge several VmExitStatistics into one.
    pub fn merged(stats: &[VmExitStatistics]) -> VmExitStatistics {
        let mut merged = VmExitStatistics::new();
        for other in stats.iter() {
            for exit_index in 0..(MAX_EXIT_INT + 1) {
                // We overflow because we don't want any disruptions to emulator running due to
                // statistics
                merged.exit_counters[exit_index] = merged.exit_counters[exit_index]
                    .overflowing_add(other.exit_counters[exit_index])
                    .0;
                merged.exit_durations[exit_index] = merged.exit_durations[exit_index]
                    .checked_add(other.exit_durations[exit_index])
                    .unwrap_or(Duration::new(0, 0)); // If we overflow, reset to 0
            }
        }

        merged
    }

    /// Get a json representation of `self`. Returns an array of maps, where each map contains the
    /// count and duration of a particular vmexit.
    pub fn json(&self) -> serde_json::Value {
        let mut exits = serde_json::json!([]);
        let exits_vec = exits.as_array_mut().unwrap();
        for exit_index in 0..(MAX_EXIT_INT + 1) {
            exits_vec.push(serde_json::json!({
                "exit_type": exit_index_to_str(exit_index),
                "count": self.exit_counters[exit_index],
                "duration": {
                    "seconds": self.exit_durations[exit_index].as_secs(),
                    "subsecond_nanos": self.exit_durations[exit_index].subsec_nanos(),
                }
            }))
        }
        exits
    }
}

impl std::fmt::Display for VmExitStatistics {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Exit Type       Count           Duration")?;

        let mut exit_indices: Vec<usize> = (0..(MAX_EXIT_INT + 1)).collect();
        // Sort exit indices by exit_duration
        exit_indices.sort_by_key(|i| Reverse(self.exit_durations[*i]));

        for exit_index in exit_indices {
            writeln!(
                f,
                "{:<16}{:<16}{:<16?}",
                exit_index_to_str(exit_index),
                self.exit_counters[exit_index],
                // Alignment not implemented by Debug
                self.exit_durations[exit_index],
            )?;
        }

        Ok(())
    }
}

/// This constant should be set to the maximum integer to which the below functions will map a
/// VcpuExit.
const MAX_EXIT_INT: usize = 13;

/// Map Vm Exits to exit indexes, which are integers for storage in our counter Vecs.
fn exit_to_index(exit: &base::Result<VcpuExit>) -> usize {
    match exit {
        Ok(VcpuExit::Io { .. }) => 0,
        Ok(VcpuExit::Mmio { .. }) => 1,
        Ok(VcpuExit::IoapicEoi { .. }) => 2,
        Ok(VcpuExit::IrqWindowOpen) => 3,
        Ok(VcpuExit::Hlt) => 4,
        Ok(VcpuExit::Shutdown) => 5,
        Ok(VcpuExit::FailEntry { .. }) => 6,
        Ok(VcpuExit::SystemEventShutdown) => 7,
        Ok(VcpuExit::SystemEventReset) => 7,
        Ok(VcpuExit::SystemEventCrash) => 7,
        Ok(VcpuExit::Intr) => 8,
        Ok(VcpuExit::Cpuid { .. }) => 9,
        Err(e) if e.errno() == ERROR_RETRY_I32 => 10,
        Err(_) => 11,
        Ok(VcpuExit::Canceled) => 12,
        _ => 13,
    }
}

/// Give human readable names for each exit type that we've mapped to an exit index in
/// exit_to_index.
fn exit_index_to_str(exit: usize) -> String {
    (match exit {
        0 => "Io",
        1 => "Mmio",
        2 => "IoapicEoi",
        3 => "IrqWindowOpen",
        4 => "Hlt",
        5 => "Shutdown",
        6 => "FailEntry",
        7 => "SystemEvent",
        8 => "Intr",
        9 => "Cpuid",
        10 => "Retry",
        11 => "Error",
        12 => "Canceled",
        _ => "Unknown",
    })
    .to_string()
}

/// Collects, merges, and displays statistics between vcpu threads.
#[derive(Default, Clone, Debug)]
pub struct StatisticsCollector {
    pub pio_bus_stats: Vec<Arc<Mutex<BusStatistics>>>,
    pub mmio_bus_stats: Vec<Arc<Mutex<BusStatistics>>>,
    pub vm_exit_stats: Vec<VmExitStatistics>,
}

impl StatisticsCollector {
    pub fn new() -> StatisticsCollector {
        StatisticsCollector::default()
    }

    /// Return a merged version of the pio bus statistics, mmio bus statistics, and the vm exit
    /// statistics for all vcpus.
    fn merged(&self) -> (BusStatistics, BusStatistics, VmExitStatistics) {
        (
            BusStatistics::merged(&self.pio_bus_stats),
            BusStatistics::merged(&self.mmio_bus_stats),
            VmExitStatistics::merged(&self.vm_exit_stats),
        )
    }

    /// Get a json representation of `self`. It contains two top-level keys: "vcpus" and "merged".
    /// The "vcpus" key's value is a list of per-vcpu stats, where the "merged" stats contains the
    /// sum of all vcpu stats.
    pub fn json(&self) -> serde_json::Value {
        let mut vcpus = serde_json::json!([]);
        let vcpus_vec = vcpus.as_array_mut().unwrap();

        for i in 0..self.pio_bus_stats.len() {
            vcpus_vec.push(serde_json::json!({
                "io": self.pio_bus_stats[i].lock().json(),
                "mmio": self.mmio_bus_stats[i].lock().json(),
                "exits": self.vm_exit_stats[i].json(),
            }));
        }

        let (pio, mmio, exits) = self.merged();

        serde_json::json!({
            "merged": {
                "io": pio.json(),
                "mmio": mmio.json(),
                "exits": exits.json(),
            },
            "vcpus": vcpus
        })
    }
}

impl std::fmt::Display for StatisticsCollector {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (pio, mmio, exits) = self.merged();
        writeln!(f, "Port IO:")?;
        writeln!(f, "{}", pio)?;
        writeln!(f, "MMIO:")?;
        writeln!(f, "{}", mmio)?;
        writeln!(f, "Vm Exits:")?;
        writeln!(f, "{}", exits)
    }
}

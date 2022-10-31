// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::cmp::Reverse;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use sync::Mutex;

/// Helper enum to distinguish between read stats and write stats.
#[derive(Clone, Copy)]
pub(crate) enum BusOperation {
    Read,
    Write,
}

/// Identifying information about a device on the Bus, used for statistics.
#[derive(Clone, Default, Eq, PartialEq, Debug)]
struct DeviceStatisticsIdentifier {
    /// Name of the device
    name: String,
    /// Id of the device
    id: u32,
    /// Base address where the device was added to the bus.
    base: u64,
    /// Length of address range this device entry covers.
    len: u64,
}

impl DeviceStatisticsIdentifier {
    fn new(name: String, id: u32, base: u64, len: u64) -> DeviceStatisticsIdentifier {
        DeviceStatisticsIdentifier {
            name,
            id,
            base,
            len,
        }
    }

    /// Get a json representation of `self`.
    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "id": self.id,
            "base": self.base,
            "len": self.len})
    }
}

/// Statistics about how a device has been accessed via a Bus.
#[derive(Clone, Default, Eq, PartialEq, Debug)]
struct DeviceStatistics {
    /// Counter of the number of reads performed.
    read_counter: u64,
    /// Total duration of reads performed.
    read_duration: Duration,
    /// Counter of the number of writes performed.
    write_counter: u64,
    /// Total duration of writes performed.
    write_duration: Duration,
}

impl DeviceStatistics {
    /// Increment either a read counter or a write counter, depending on `stat`. Also add the
    /// time elapsed since `start` to read_duration or write_duration respectively.
    fn increment(&mut self, stat: BusOperation, start: Instant) {
        let (counter, duration) = match stat {
            BusOperation::Read => (&mut self.read_counter, &mut self.read_duration),
            BusOperation::Write => (&mut self.write_counter, &mut self.write_duration),
        };

        // We use saturating_add because we don't want any disruptions to emulator running due to
        // statistics
        *counter = counter.saturating_add(1);
        *duration = duration
            .checked_add(start.elapsed())
            .unwrap_or(Duration::new(0, 0)); // If we overflow, reset to 0
    }

    /// Get the accumulated count and duration of a particular Operation
    fn get(&self, stat: BusOperation) -> (u64, Duration) {
        match stat {
            BusOperation::Read => (self.read_counter, self.read_duration),
            BusOperation::Write => (self.write_counter, self.write_duration),
        }
    }

    /// Merge another DeviceStat into this one.
    fn merge(&mut self, other: &DeviceStatistics) {
        self.read_counter = self.read_counter.saturating_add(other.read_counter);
        self.read_duration = self
            .read_duration
            .checked_add(other.read_duration)
            .unwrap_or(Duration::new(0, 0)); // If we overflow, reset to 0

        self.write_counter = self.write_counter.saturating_add(other.write_counter);
        self.write_duration = self
            .write_duration
            .checked_add(other.write_duration)
            .unwrap_or(Duration::new(0, 0)); // If we overflow, reset to 0
    }

    /// Get a json representation of `self`.
    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "reads": self.read_counter,
            "read_duration": {
                "seconds": self.read_duration.as_secs(),
                "subsecond_nanos": self.read_duration.subsec_nanos(),
            },
            "writes": self.write_counter,
            "write_duration": {
                "seconds": self.write_duration.as_secs(),
                "subsecond_nanos": self.write_duration.subsec_nanos(),
            },
        })
    }
}

/// Statistics about how a bus has been accessed.
#[derive(Clone, Default, Debug)]
pub struct BusStatistics {
    /// Whether or not statistics have been enabled to measure Bus Reads/Writes.
    enabled: bool,
    /// Vec of per-device statistics, indexed by BusEntry.index.
    device_stats: Vec<DeviceStatistics>,
    /// Global information about all devices inserted into any bus.
    device_identifiers: Arc<Mutex<Vec<DeviceStatisticsIdentifier>>>,
}

impl BusStatistics {
    pub fn new() -> BusStatistics {
        BusStatistics::default()
    }

    /// Enable or disable statistics gathering.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the start time of the stat that is to be recorded.
    ///
    /// If the BusStatistics instance is not enabled this will return None.
    pub(crate) fn start_stat(&self) -> Option<Instant> {
        if !self.enabled {
            return None;
        }
        Some(Instant::now())
    }

    /// Record the end of the stat.
    ///
    /// The start value return from start_stat should be passed as `start`. If `start` is None or
    /// if the BusStatistics instance is not enabled this will do nothing. The counters and
    /// durations will silently overflow to prevent interference with vm operation.
    pub(crate) fn end_stat(
        &mut self,
        stat: BusOperation,
        start: Option<Instant>,
        device_index: usize,
    ) {
        if !self.enabled {
            return;
        }

        if let Some(start) = start {
            // Make sure the device_stats is large enough
            if self.device_stats.len() < device_index + 1 {
                self.device_stats
                    .resize(device_index + 1, DeviceStatistics::default());
            }

            self.device_stats[device_index].increment(stat, start);
        }
    }

    /// Get the next available device index.
    ///
    /// When adding a BusEntry to the bus, the Bus should call this function to get the index for
    /// the entry. This BusStatistics will then save the device `name` and `id` associated with the
    /// device index for displaying statistics later.
    pub(crate) fn next_device_index(&self, name: String, id: u32, base: u64, len: u64) -> usize {
        let mut device_identifiers = self.device_identifiers.lock();
        let idx = device_identifiers.len();
        device_identifiers.push(DeviceStatisticsIdentifier::new(name, id, base, len));
        idx
    }

    /// Merge several BusStatistics into one.
    pub fn merged(stats: &[Arc<Mutex<BusStatistics>>]) -> BusStatistics {
        if stats.len() == 0 {
            return BusStatistics::new();
        }

        let device_count = stats[0].lock().device_identifiers.lock().len();

        let mut merged = BusStatistics {
            enabled: stats[0].lock().enabled,
            device_stats: Vec::with_capacity(device_count),
            device_identifiers: stats[0].lock().device_identifiers.clone(),
        };

        for idx in 0..device_count {
            let mut device_stat = DeviceStatistics::default();
            // Merge all DeviceStatistics
            for other in stats {
                let other = other.lock();
                // Not all vcpu Buses may have stats for all devices.
                if let Some(other_stats) = other.device_stats.get(idx) {
                    device_stat.merge(other_stats);
                }
            }

            merged.device_stats.push(device_stat);
        }

        merged
    }

    /// Get a json representation of `self`. Returns an array of maps, where each map contains the
    /// read an write statistics for a particular device.
    pub fn json(&self) -> serde_json::Value {
        let mut devices = serde_json::json!([]);
        let devices_vec = devices.as_array_mut().unwrap();
        for (device_identifier, device_stat) in self
            .device_identifiers
            .lock()
            .iter()
            .zip(self.device_stats.iter())
        {
            devices_vec.push(
                serde_json::json!({"info": device_identifier.json(), "stats": device_stat.json()}),
            );
        }
        devices
    }
}

impl std::fmt::Display for BusStatistics {
    /// BusStatistics' Display is split into two tables, Reads and Writes.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (opname, op) in &[("Read", BusOperation::Read), ("Write", BusOperation::Write)] {
            writeln!(
                f,
                "Device Name                   Device Id      Address Range            {:<15}s{:<15} Duration",
                opname,
                opname
            )?;

            let mut device_indices: Vec<usize> = (0..self.device_stats.len()).collect();
            // Sort indices by op duration
            device_indices.sort_by_key(|i| Reverse(self.device_stats[*i].get(*op).1));

            for i in device_indices.iter() {
                let device_identifier = &self.device_identifiers.lock()[*i];
                let (count, duration) = self.device_stats[*i].get(*op);
                #[allow(clippy::format_in_format_args)]
                writeln!(
                    f,
                    "{:<30}0x{:<13x}{:<25}{:<15}{:<15}",
                    device_identifier.name,
                    device_identifier.id,
                    format!(
                        "0x{:x}-0x{:x}",
                        device_identifier.base,
                        device_identifier.base + device_identifier.len
                    ),
                    count,
                    // Alignment not implemented by Debug
                    format!("{:?}", duration),
                )?;
            }
            writeln!(f)?;
        }

        Ok(())
    }
}

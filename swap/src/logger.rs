// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![cfg(feature = "log_page_fault")]
#![deny(missing_docs)]

use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::Context;
use base::info;
use base::AsRawDescriptor;
use base::RawDescriptor;
use serde::Deserialize;
use serde::Serialize;
use vm_memory::GuestMemory;
use vm_memory::MemoryRegionInformation;

/// Logs page fault events into a log file in json format.
pub struct PageFaultEventLogger {
    file: File,
    base_time: Instant,
}

impl PageFaultEventLogger {
    /// Creates a log file named "page_fault.log" in the `swap_dir` and logs the initial log.
    ///
    /// initial log contains the regions information and base time.
    ///
    /// # Arguments
    ///
    /// * `swap_dir` - directory to store the log file.
    /// * `guest_memory` - [GuestMemory] containing regions info.
    pub fn create(swap_dir: &Path, guest_memory: &GuestMemory) -> anyhow::Result<Self> {
        let file_path = swap_dir.join("page_fault.log");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_path)
            .context("open pagefault event log file")?;
        let regions = regions_from_guest_memory(guest_memory);
        let base_time = Instant::now();
        serde_json::to_writer(
            &file,
            &PageFaultInitialLog {
                base_timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
                regions,
            },
        )
        .context("log initial event")?;
        let mut logger = Self { file, base_time };
        logger.line_break();
        info!("start logging page faults at {:?}", file_path);
        Ok(logger)
    }

    /// Logs a page fault event.
    ///
    /// # Arguments
    ///
    /// * `address` - the address page fault occured.
    pub fn log_page_fault(&mut self, address: usize, id_uffd: u32) {
        // it is not optimized (e.g. buffered io). but it is fine because this logger is for debug
        // purpose only.
        let _ = serde_json::to_writer(
            &self.file,
            &PageFaultEventLog {
                elapsed_nanos: self.base_time.elapsed().as_nanos(),
                address,
                id_uffd,
            },
        );
        self.line_break();
    }

    fn line_break(&mut self) {
        const LINE_BREAK: &[u8] = &[b'\n'];
        let _ = self.file.write(LINE_BREAK);
    }
}

impl AsRawDescriptor for PageFaultEventLogger {
    fn as_raw_descriptor(&self) -> RawDescriptor {
        self.file.as_raw_descriptor()
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct PageFaultInitialLog {
    base_timestamp: u128,
    regions: Vec<MemoryRegion>,
}

fn regions_from_guest_memory(guest_memory: &GuestMemory) -> Vec<MemoryRegion> {
    let mut regions = Vec::new();
    guest_memory
        .with_regions::<_, ()>(
            |MemoryRegionInformation {
                 len, base_address, ..
             }| {
                regions.push(MemoryRegion { base_address, len });
                Ok(())
            },
        )
        .unwrap(); // the call back never return error.
    regions
}

#[derive(Serialize, Deserialize, Debug)]
struct MemoryRegion {
    base_address: usize,
    len: usize,
}

#[derive(Serialize, Deserialize, Debug)]
struct PageFaultEventLog {
    elapsed_nanos: u128,
    address: usize,
    id_uffd: u32,
}

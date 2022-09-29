// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::prelude::FileExt;
use std::path::Path;
use std::sync::Mutex;

use base::error;
use base::pagesize;
use base::round_up_to_page_size;
use base::MemoryMapping;
use base::MemoryMappingBuilder;
use base::Protection;

use crate::pci::CrosvmDeviceId;
use crate::BusAccessInfo;
use crate::BusDevice;
use crate::BusDeviceSync;
use crate::BusRange;
use crate::DeviceId;
use crate::Suspendable;

pub struct DirectIo {
    dev: Mutex<File>,
    read_only: bool,
}

impl DirectIo {
    /// Create simple direct I/O access device.
    pub fn new(path: &Path, read_only: bool) -> Result<Self, io::Error> {
        let dev = OpenOptions::new().read(true).write(!read_only).open(path)?;
        Ok(DirectIo {
            dev: Mutex::new(dev),
            read_only,
        })
    }

    fn iowr(&self, port: u64, data: &[u8]) {
        if !self.read_only {
            if let Ok(ref mut dev) = self.dev.lock() {
                let _ = dev.write_all_at(data, port);
            }
        }
    }

    fn iord(&self, port: u64, data: &mut [u8]) {
        if let Ok(ref mut dev) = self.dev.lock() {
            let _ = dev.read_exact_at(data, port);
        }
    }
}

impl BusDevice for DirectIo {
    fn device_id(&self) -> DeviceId {
        CrosvmDeviceId::DirectIo.into()
    }

    fn debug_label(&self) -> String {
        "direct-io".to_string()
    }

    /// Reads at `offset` from this device
    fn read(&mut self, ai: BusAccessInfo, data: &mut [u8]) {
        self.iord(ai.address, data);
    }

    /// Writes at `offset` into this device
    fn write(&mut self, ai: BusAccessInfo, data: &[u8]) {
        self.iowr(ai.address, data);
    }
}

impl BusDeviceSync for DirectIo {
    /// Reads at `offset` from this device
    fn read(&self, ai: BusAccessInfo, data: &mut [u8]) {
        self.iord(ai.address, data);
    }

    /// Writes at `offset` into this device
    fn write(&self, ai: BusAccessInfo, data: &[u8]) {
        self.iowr(ai.address, data);
    }
}

impl Suspendable for DirectIo {}

pub struct DirectMmio {
    dev: Mutex<Vec<(BusRange, MemoryMapping)>>,
    read_only: bool,
}

impl DirectMmio {
    /// Create simple direct mmio access device.
    pub fn new(path: &Path, read_only: bool, ranges: &[BusRange]) -> Result<Self, io::Error> {
        let dev = OpenOptions::new()
            .read(true)
            .write(!read_only)
            .custom_flags(libc::O_SYNC)
            .open(path)?;
        let mut mmap_info = Vec::new();

        let protection = if read_only {
            Protection::read()
        } else {
            Protection::read_write()
        };

        for range in ranges {
            // set to the page start
            let start = range.base & (!((pagesize() - 1) as u64));
            // set to the next page of the end address
            let end = round_up_to_page_size((range.base + range.len) as usize);
            let len = end - start as usize;
            let mmap = match MemoryMappingBuilder::new(len)
                .from_file(&dev)
                .offset(start)
                .protection(protection)
                .build()
            {
                Ok(m) => m,
                Err(e) => {
                    error!(
                        "failed to create mmap for mmio: {:x} ~ {:x}, error: {}",
                        range.base,
                        range.base + range.len,
                        e
                    );
                    continue;
                }
            };

            mmap_info.push((*range, mmap));
        }

        Ok(DirectMmio {
            dev: Mutex::new(mmap_info),
            read_only,
        })
    }

    fn iowr(&self, ai: BusAccessInfo, data: &[u8]) {
        if self.read_only {
            return;
        }

        let dev = match self.dev.lock() {
            Ok(d) => d,
            Err(_) => return,
        };

        for (range, mmap) in dev.iter() {
            if !range.contains(ai.address) || !range.contains(ai.address + data.len() as u64) {
                continue;
            }

            let page_mask = (pagesize() - 1) as u64;
            let offset = (range.base & page_mask) + ai.offset;
            if let Err(e) = mmap.write_slice(data, offset as usize) {
                error!("write mmio {:x} error, {}", ai.address, e);
            }
            return;
        }
    }

    fn iord(&self, ai: BusAccessInfo, data: &mut [u8]) {
        let dev = match self.dev.lock() {
            Ok(d) => d,
            Err(_) => return,
        };

        for (range, mmap) in dev.iter() {
            if !range.contains(ai.address) || !range.contains(ai.address + data.len() as u64) {
                continue;
            }

            let page_mask = (pagesize() - 1) as u64;
            let offset = (range.base & page_mask) + ai.offset;
            if let Err(e) = mmap.read_slice(data, offset as usize) {
                error!("read mmio {:x} error {}", ai.address, e);
            }
            return;
        }
    }
}

impl BusDevice for DirectMmio {
    fn device_id(&self) -> DeviceId {
        CrosvmDeviceId::DirectMmio.into()
    }

    fn debug_label(&self) -> String {
        "direct-mmio".to_string()
    }

    /// Reads at `offset` from this device
    fn read(&mut self, ai: BusAccessInfo, data: &mut [u8]) {
        self.iord(ai, data);
    }

    /// Writes at `offset` into this device
    fn write(&mut self, ai: BusAccessInfo, data: &[u8]) {
        self.iowr(ai, data);
    }
}

impl BusDeviceSync for DirectMmio {
    /// Reads at `offset` from this device
    fn read(&self, ai: BusAccessInfo, data: &mut [u8]) {
        self.iord(ai, data);
    }

    /// Writes at `offset` into this device
    fn write(&self, ai: BusAccessInfo, data: &[u8]) {
        self.iowr(ai, data);
    }
}

impl Suspendable for DirectMmio {}

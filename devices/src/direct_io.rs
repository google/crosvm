// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::{BusAccessInfo, BusDevice, BusDeviceSync};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::prelude::FileExt;
use std::path::Path;
use std::sync::Mutex;

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

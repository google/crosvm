// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;

use anyhow::Context;
use base::warn;
use winapi::um::winbase::FILE_FLAG_NO_BUFFERING;
use winapi::um::winnt::FILE_SHARE_READ;
use winapi::um::winnt::FILE_SHARE_WRITE;

use crate::virtio::block::DiskOption;

pub fn get_seg_max(_queue_size: u16) -> u32 {
    // Allow a single segment per request, since vectored I/O is not implemented for Windows yet.
    1
}

impl DiskOption {
    /// Open the specified disk file.
    pub fn open(&self) -> anyhow::Result<Box<dyn disk::DiskFile>> {
        let mut open_option = OpenOptions::new();
        open_option
            .read(true)
            .write(!self.read_only)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);

        if self.direct {
            warn!("Opening disk file with no buffering");
            open_option.custom_flags(FILE_FLAG_NO_BUFFERING);
        }

        Ok(disk::create_disk_file(
            open_option
                .open(&self.path)
                .context("Failed to open disk file")?,
            self.sparse,
            disk::MAX_NESTING_DEPTH,
            &self.path,
        )?)
    }
}

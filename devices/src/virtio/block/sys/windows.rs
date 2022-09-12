// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;

use anyhow::Context;
use disk::AsyncDisk;
use disk::DiskFile;
use disk::SingleFileDisk;
use winapi::um::winnt::FILE_SHARE_READ;
use winapi::um::winnt::FILE_SHARE_WRITE;

use crate::virtio::block::block::DiskOption;

pub fn get_seg_max(_queue_size: u16) -> u32 {
    // Allow a single segment per request, since vectored I/O is not implemented for Windows yet.
    1
}

impl DiskOption {
    /// Open the specified disk file.
    pub fn open(&self) -> anyhow::Result<Box<dyn DiskFile>> {
        let io_concurrency = self.io_concurrency.get();

        // We can only take the write lock if a single handle is used (otherwise we can't open
        // multiple handles).
        let share_flags = if io_concurrency == 1 {
            FILE_SHARE_READ
        } else {
            FILE_SHARE_READ | FILE_SHARE_WRITE
        };

        let mut files = Vec::new();
        for _ in 0..io_concurrency {
            files.push(
                OpenOptions::new()
                    .read(true)
                    .write(!self.read_only)
                    .share_mode(share_flags)
                    .open(&self.path)
                    .context("Failed to open disk file")?,
            );
        }

        Ok(Box::new(SingleFileDisk::new_from_files(files)?).into_inner())
    }
}

// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;

use anyhow::Context;
use base::warn;
use cros_async::sys::windows::ExecutorKindSys;
use cros_async::Executor;
use cros_async::ExecutorKind;
use winapi::um::winbase::FILE_FLAG_NO_BUFFERING;
use winapi::um::winbase::FILE_FLAG_OVERLAPPED;
use winapi::um::winnt::FILE_SHARE_READ;
use winapi::um::winnt::FILE_SHARE_WRITE;

use crate::virtio::block::DiskOption;
use crate::virtio::BlockAsync;

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

        let mut flags = 0;
        if self.direct {
            warn!("Opening disk file with no buffering");
            flags |= FILE_FLAG_NO_BUFFERING;
        }

        let is_overlapped = matches!(
            self.async_executor.unwrap_or_default(),
            ExecutorKind::SysVariants(ExecutorKindSys::Overlapped { .. })
        );
        if is_overlapped {
            warn!("Opening disk file for overlapped IO");
            flags |= FILE_FLAG_OVERLAPPED;
        }

        if flags != 0 {
            open_option.custom_flags(flags);
        }

        let file = open_option
            .open(&self.path)
            .context("Failed to open disk file")?;
        let image_type = disk::detect_image_type(&file, is_overlapped)?;
        Ok(disk::create_disk_file_of_type(
            file,
            self.sparse,
            disk::MAX_NESTING_DEPTH,
            &self.path,
            image_type,
        )?)
    }
}

impl BlockAsync {
    pub fn create_executor(&self) -> Executor {
        let mut kind = self.executor_kind;
        if let ExecutorKind::SysVariants(ExecutorKindSys::Overlapped { concurrency }) = &mut kind {
            if concurrency.is_none() {
                *concurrency = Some(self.io_concurrency);
            }
        }
        Executor::with_executor_kind(kind).expect("Failed to create an executor")
    }
}
